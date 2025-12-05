"""
Model Evaluation Script
Evaluate trained model on test set and generate comprehensive report
"""

import sys
from pathlib import Path
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.data_loader import VDISCDataset, collate_fn
from src.models.vulnerability_detector import create_model


class ModelEvaluator:
    """Comprehensive model evaluation"""
    
    def __init__(self, model_path: str = 'data/models/best_model.pth'):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Load checkpoint
        print(f"Loading model from {model_path}...")
        self.checkpoint = torch.load(model_path, map_location=self.device)
        
        # Create model
        self.model = create_model(
            model_type='simple',
            code_feature_dim=24,
            graph_feature_dim=8,
            hidden_dim=128,
            dropout=0.3
        )
        
        self.model.load_state_dict(self.checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()
        
        print(f"✅ Model loaded!")
        print(f"   Best F1: {self.checkpoint.get('best_val_f1', 'N/A')}")
    
    def evaluate_test_set(self, test_path: str, max_samples: int = None):
        """Evaluate on test set"""
        print(f"\n📊 Evaluating on test set...")
        
        # Load test data
        test_dataset = VDISCDataset(test_path, max_samples=max_samples)
        test_loader = DataLoader(
            test_dataset,
            batch_size=32,
            shuffle=False,
            num_workers=0,
            collate_fn=collate_fn
        )
        
        all_preds = []
        all_labels = []
        all_probs = []
        
        print(f"Processing {len(test_dataset)} test samples...")
        
        with torch.no_grad():
            for batch_features, labels in tqdm(test_loader, desc='Testing'):
                # Move to device
                code_features = batch_features['code_features'].to(self.device)
                ast_features = batch_features['ast_features'].to(self.device)
                cfg_features = batch_features['cfg_features'].to(self.device)
                pdg_features = batch_features['pdg_features'].to(self.device)
                labels = labels.to(self.device)
                
                # Forward pass
                logits = self.model(code_features, ast_features, cfg_features, pdg_features)
                probs = torch.softmax(logits, dim=1)
                preds = torch.argmax(logits, dim=1)
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())  # Probability of vulnerable class
        
        return np.array(all_preds), np.array(all_labels), np.array(all_probs)
    
    def generate_report(self, preds, labels, probs):
        """Generate comprehensive evaluation report"""
        print("\n" + "="*70)
        print("📊 EVALUATION REPORT")
        print("="*70)
        
        # Basic metrics
        accuracy = accuracy_score(labels, preds)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, preds, average='binary', zero_division=0
        )
        
        print(f"\n🎯 Overall Metrics:")
        print(f"   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"   Precision: {precision:.4f} ({precision*100:.2f}%)")
        print(f"   Recall:    {recall:.4f} ({recall*100:.2f}%)")
        print(f"   F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
        
        # AUC-ROC
        try:
            auc = roc_auc_score(labels, probs)
            print(f"   AUC-ROC:   {auc:.4f}")
        except:
            print(f"   AUC-ROC:   N/A")
        
        # Confusion matrix
        cm = confusion_matrix(labels, preds)
        tn, fp, fn, tp = cm.ravel()
        
        print(f"\n📈 Confusion Matrix:")
        print(f"   True Negatives:  {tn:,} (correctly identified safe code)")
        print(f"   False Positives: {fp:,} (safe code flagged as vulnerable)")
        print(f"   False Negatives: {fn:,} (missed vulnerabilities) ⚠️")
        print(f"   True Positives:  {tp:,} (correctly detected vulnerabilities)")
        
        # Per-class metrics
        print(f"\n📊 Per-Class Performance:")
        print(f"   Safe Code:")
        print(f"      Precision: {tn/(tn+fn) if (tn+fn) > 0 else 0:.4f}")
        print(f"      Recall:    {tn/(tn+fp) if (tn+fp) > 0 else 0:.4f}")
        print(f"   Vulnerable Code:")
        print(f"      Precision: {tp/(tp+fp) if (tp+fp) > 0 else 0:.4f} (when flagged, how often correct)")
        print(f"      Recall:    {tp/(tp+fn) if (tp+fn) > 0 else 0:.4f} (% of vulnerabilities caught)")
        
        # Risk assessment
        print(f"\n⚠️  Risk Assessment:")
        if fn > 0:
            miss_rate = fn / (tp + fn) if (tp + fn) > 0 else 0
            print(f"   Missed {fn:,} vulnerabilities ({miss_rate*100:.1f}% miss rate)")
        if fp > 0:
            false_alarm = fp / (tn + fp) if (tn + fp) > 0 else 0
            print(f"   {fp:,} false alarms ({false_alarm*100:.1f}% false positive rate)")
        
        print("="*70)
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'confusion_matrix': cm,
            'auc': auc if 'auc' in locals() else None
        }
    
    def plot_confusion_matrix(self, cm, save_path='results/test_confusion_matrix.png'):
        """Plot confusion matrix"""
        plt.figure(figsize=(10, 8))
        
        # Normalize to show percentages
        cm_percent = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis] * 100
        
        # Create annotations showing both count and percentage
        annot = np.array([[f'{cm[i,j]:,}\n({cm_percent[i,j]:.1f}%)' 
                          for j in range(cm.shape[1])] 
                         for i in range(cm.shape[0])])
        
        sns.heatmap(cm, annot=annot, fmt='', cmap='Blues', 
                   xticklabels=['Safe', 'Vulnerable'],
                   yticklabels=['Safe', 'Vulnerable'],
                   cbar_kws={'label': 'Count'})
        
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.title('Confusion Matrix - Test Set Evaluation', fontsize=14, fontweight='bold')
        
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"\n📊 Confusion matrix saved to {save_path}")
        plt.close()
    
    def plot_roc_curve(self, labels, probs, save_path='results/test_roc_curve.png'):
        """Plot ROC curve"""
        fpr, tpr, thresholds = roc_curve(labels, probs)
        auc = roc_auc_score(labels, probs)
        
        plt.figure(figsize=(10, 8))
        plt.plot(fpr, tpr, linewidth=2, label=f'ROC Curve (AUC = {auc:.4f})')
        plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')
        
        plt.xlabel('False Positive Rate', fontsize=12)
        plt.ylabel('True Positive Rate (Recall)', fontsize=12)
        plt.title('ROC Curve - Vulnerability Detection', fontsize=14, fontweight='bold')
        plt.legend(fontsize=11)
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"📊 ROC curve saved to {save_path}")
        plt.close()
    
    def plot_prediction_distribution(self, labels, probs, save_path='results/test_prediction_dist.png'):
        """Plot prediction probability distribution"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))
        
        # Safe samples
        safe_probs = probs[labels == 0]
        ax1.hist(safe_probs, bins=50, alpha=0.7, color='green', edgecolor='black')
        ax1.axvline(0.5, color='red', linestyle='--', linewidth=2, label='Threshold')
        ax1.set_xlabel('Vulnerability Probability', fontsize=11)
        ax1.set_ylabel('Count', fontsize=11)
        ax1.set_title('Safe Code - Prediction Distribution', fontsize=12, fontweight='bold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Vulnerable samples
        vuln_probs = probs[labels == 1]
        ax2.hist(vuln_probs, bins=50, alpha=0.7, color='red', edgecolor='black')
        ax2.axvline(0.5, color='red', linestyle='--', linewidth=2, label='Threshold')
        ax2.set_xlabel('Vulnerability Probability', fontsize=11)
        ax2.set_ylabel('Count', fontsize=11)
        ax2.set_title('Vulnerable Code - Prediction Distribution', fontsize=12, fontweight='bold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"📊 Prediction distribution saved to {save_path}")
        plt.close()


def main():
    """Run full evaluation"""
    print("="*70)
    print("ZeroDayGuard - Model Evaluation")
    print("="*70)
    
    # Initialize evaluator
    evaluator = ModelEvaluator('data/models/best_model.pth')
    
    # Evaluate on test set (use 5000 samples for quick test, None for full)
    preds, labels, probs = evaluator.evaluate_test_set(
        'data/raw/vdisc/VDISC_test.hdf5',
        max_samples=5000  # Change to None for full test set
    )
    
    # Generate report
    metrics = evaluator.generate_report(preds, labels, probs)
    
    # Create visualizations
    evaluator.plot_confusion_matrix(metrics['confusion_matrix'])
    evaluator.plot_roc_curve(labels, probs)
    evaluator.plot_prediction_distribution(labels, probs)
    
    print("\n✅ Evaluation complete!")
    print(f"\n📁 Generated files:")
    print(f"   - results/test_confusion_matrix.png")
    print(f"   - results/test_roc_curve.png")
    print(f"   - results/test_prediction_dist.png")


if __name__ == '__main__':
    main()
