"""
Reinforcement Learning Fine-tuning for Real-World Performance
Uses REINFORCE algorithm to optimize for security-critical metrics
"""

import sys
from pathlib import Path
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.distributions import Categorical
import numpy as np
from tqdm import tqdm
import matplotlib.pyplot as plt

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.data_loader import VDISCDataset, create_dataloaders
from src.models.vulnerability_detector import create_model


class RLVulnerabilityTrainer:
    """
    Reinforcement Learning trainer for vulnerability detection
    
    Approach:
    - Treat vulnerability detection as a decision-making problem
    - Agent learns to make binary decisions (safe/vulnerable)
    - Reward based on security impact: high penalty for missed vulnerabilities
    - Uses REINFORCE (policy gradient) for optimization
    """
    
    def __init__(self, model, train_loader, val_loader, device='cpu'):
        self.model = model.to(device)
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.device = device
        
        # RL-specific optimizer (lower LR for fine-tuning)
        self.optimizer = torch.optim.Adam(model.parameters(), lr=0.00005)
        
        # Metrics tracking
        self.rewards_history = []
        self.f1_history = []
        
    def compute_reward(self, predictions, labels):
        """
        Compute reward with security-focused weighting
        
        Reward structure:
        - True Positive (detect real vuln): +10 (critical!)
        - True Negative (correctly mark safe): +1
        - False Negative (miss vuln): -20 (DANGEROUS!)
        - False Positive (false alarm): -2
        """
        rewards = torch.zeros_like(predictions, dtype=torch.float32)
        
        pred_classes = (predictions > 0.5).long()
        
        # True Positive: Correctly detected vulnerability
        tp_mask = (pred_classes == 1) & (labels == 1)
        rewards[tp_mask] = 10.0
        
        # True Negative: Correctly marked safe
        tn_mask = (pred_classes == 0) & (labels == 0)
        rewards[tn_mask] = 1.0
        
        # False Negative: MISSED vulnerability (CRITICAL ERROR)
        fn_mask = (pred_classes == 0) & (labels == 1)
        rewards[fn_mask] = -20.0
        
        # False Positive: False alarm (annoying but not dangerous)
        fp_mask = (pred_classes == 1) & (labels == 0)
        rewards[fp_mask] = -2.0
        
        return rewards
    
    def train_epoch(self):
        """Single RL training epoch using REINFORCE"""
        self.model.train()
        epoch_rewards = []
        
        pbar = tqdm(self.train_loader, desc='RL Training')
        
        for batch_idx, batch in enumerate(pbar):
            code_features = batch['code_features'].to(self.device)
            ast_features = batch['ast_features'].to(self.device)
            cfg_features = batch['cfg_features'].to(self.device)
            pdg_features = batch['pdg_features'].to(self.device)
            labels = batch['label'].to(self.device)
            
            # Forward pass
            logits = self.model(code_features, ast_features, cfg_features, pdg_features)
            probs = F.softmax(logits, dim=1)
            
            # Sample actions from policy
            dist = Categorical(probs)
            actions = dist.sample()
            log_probs = dist.log_prob(actions)
            
            # Get vulnerability probabilities for reward calculation
            vuln_probs = probs[:, 1]
            
            # Compute rewards
            rewards = self.compute_reward(vuln_probs, labels)
            
            # Policy gradient loss (REINFORCE)
            loss = -(log_probs * rewards).mean()
            
            # Add entropy bonus to encourage exploration
            entropy = dist.entropy().mean()
            loss = loss - 0.01 * entropy
            
            # Backward pass
            self.optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()
            
            # Track metrics
            epoch_rewards.append(rewards.mean().item())
            
            pbar.set_postfix({
                'avg_reward': np.mean(epoch_rewards[-100:]),
                'loss': loss.item()
            })
        
        return np.mean(epoch_rewards)
    
    def validate(self):
        """Validate model with standard metrics"""
        self.model.eval()
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in tqdm(self.val_loader, desc='Validation'):
                code_features = batch['code_features'].to(self.device)
                ast_features = batch['ast_features'].to(self.device)
                cfg_features = batch['cfg_features'].to(self.device)
                pdg_features = batch['pdg_features'].to(self.device)
                labels = batch['label'].to(self.device)
                
                logits = self.model(code_features, ast_features, cfg_features, pdg_features)
                probs = F.softmax(logits, dim=1)
                preds = probs[:, 1]
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
        
        # Compute metrics
        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)
        pred_classes = (all_preds > 0.5).astype(int)
        
        tp = ((pred_classes == 1) & (all_labels == 1)).sum()
        tn = ((pred_classes == 0) & (all_labels == 0)).sum()
        fp = ((pred_classes == 1) & (all_labels == 0)).sum()
        fn = ((pred_classes == 0) & (all_labels == 1)).sum()
        
        accuracy = (tp + tn) / len(all_labels)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
    
    def train(self, num_epochs=10):
        """Full RL training loop"""
        print("="*80)
        print("🤖 Reinforcement Learning Fine-Tuning")
        print("="*80)
        
        best_f1 = 0
        
        for epoch in range(num_epochs):
            print(f"\n📍 RL Epoch {epoch + 1}/{num_epochs}")
            
            # RL training
            avg_reward = self.train_epoch()
            self.rewards_history.append(avg_reward)
            
            # Validation
            metrics = self.validate()
            self.f1_history.append(metrics['f1'])
            
            print(f"\n  Average Reward: {avg_reward:.4f}")
            print(f"  Validation F1:  {metrics['f1']:.4f}")
            print(f"  Recall:         {metrics['recall']:.4f}")
            print(f"  Precision:      {metrics['precision']:.4f}")
            
            # Save best model
            if metrics['f1'] > best_f1:
                best_f1 = metrics['f1']
                torch.save({
                    'model_state_dict': self.model.state_dict(),
                    'best_f1': best_f1,
                    'epoch': epoch,
                    'type': 'RL-finetuned'
                }, 'data/models/best_model_rl.pth')
                print(f"  ✅ New best F1! Saved model.")
        
        # Plot training curves
        self.plot_training_curves()
        
        print("\n" + "="*80)
        print("✅ RL Fine-tuning Complete!")
        print("="*80)
        print(f"  Best F1: {best_f1:.4f}")
        print(f"  Model: data/models/best_model_rl.pth")
    
    def plot_training_curves(self):
        """Plot RL training curves"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        
        # Rewards
        ax1.plot(self.rewards_history, 'b-', linewidth=2)
        ax1.set_xlabel('Epoch', fontsize=12)
        ax1.set_ylabel('Average Reward', fontsize=12)
        ax1.set_title('RL Training Rewards', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3)
        
        # F1 Score
        ax2.plot(self.f1_history, 'g-', linewidth=2)
        ax2.set_xlabel('Epoch', fontsize=12)
        ax2.set_ylabel('F1 Score', fontsize=12)
        ax2.set_title('Validation F1 Score', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('results/rl_training_curves.png', dpi=300, bbox_inches='tight')
        print("\n  📊 Saved: results/rl_training_curves.png")


def main():
    print("="*80)
    print("🚀 ZeroDayGuard - RL Fine-Tuning")
    print("="*80)
    
    # Load pre-trained model
    model_path = Path('data/models/best_model.pth')
    
    if not model_path.exists():
        print("\n❌ No pre-trained model found!")
        print("   Run python train_production.py first")
        return
    
    print("\n📂 Loading pre-trained model...")
    
    # Create model
    model = create_model(
        model_type='improved',
        code_feature_dim=24,
        graph_feature_dim=8,
        hidden_dim=512,
        num_classes=2,
        dropout=0.5
    )
    
    # Load weights
    checkpoint = torch.load(model_path, map_location='cpu')
    model.load_state_dict(checkpoint['model_state_dict'])
    print("✅ Model loaded")
    
    # Load datasets (use subset for RL fine-tuning)
    print("\n📦 Loading datasets for RL...")
    train_dataset = VDISCDataset(
        hdf5_path='data/raw/vdisc/VDISC_train.hdf5',
        max_samples=50000  # RL on 50K samples
    )
    val_dataset = VDISCDataset(
        hdf5_path='data/raw/vdisc/VDISC_validate.hdf5',
        max_samples=5000
    )
    
    train_loader, val_loader, _ = create_dataloaders(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        batch_size=64,
        num_workers=0
    )
    
    print(f"  Train: {len(train_dataset):,}")
    print(f"  Val:   {len(val_dataset):,}")
    
    # RL Trainer
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"\n💻 Device: {device.upper()}")
    
    rl_trainer = RLVulnerabilityTrainer(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        device=device
    )
    
    # Train with RL
    rl_trainer.train(num_epochs=10)
    
    print("\n🎯 RL fine-tuning optimizes for:")
    print("  • Minimizing missed vulnerabilities (high recall)")
    print("  • Reducing false alarms")
    print("  • Real-world security impact")


if __name__ == '__main__':
    main()
