"""
Quick Demo Script to Test the Pipeline
Tests preprocessing on a small sample
"""

import sys
from pathlib import Path
import torch

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.data_loader import VDISCDataset, create_dataloaders
from src.models.vulnerability_detector import create_model


def main():
    print("="*60)
    print("ZeroDayGuard - Quick Demo")
    print("="*60)
    
    # Test with small sample
    print("\n📦 Loading small dataset sample...")
    train_dataset = VDISCDataset(
        hdf5_path='data/raw/vdisc/VDISC_train.hdf5',
        max_samples=100  # Only 100 samples for quick test
    )
    
    print(f"✅ Loaded {len(train_dataset)} samples")
    
    # Create data loader
    print("\n🔄 Creating data loader...")
    train_loader, _, _ = create_dataloaders(
        train_dataset=train_dataset,
        batch_size=16,
        num_workers=0
    )
    
    # Get one batch
    print("\n📊 Testing data loading...")
    batch_features, labels = next(iter(train_loader))
    
    print(f"Batch size: {labels.shape[0]}")
    print(f"Code features shape: {batch_features['code_features'].shape}")
    print(f"AST features shape: {batch_features['ast_features'].shape}")
    print(f"CFG features shape: {batch_features['cfg_features'].shape}")
    print(f"PDG features shape: {batch_features['pdg_features'].shape}")
    print(f"Labels shape: {labels.shape}")
    print(f"Labels: {labels.tolist()}")
    
    # Create model
    print("\n🧠 Creating model...")
    model = create_model(
        model_type='simple',
        code_feature_dim=24,  # Updated: 5 basic + 18 keywords + 1 dangerous count
        graph_feature_dim=8,
        hidden_dim=128,
        dropout=0.3
    )
    
    # Test forward pass
    print("\n⚡ Testing forward pass...")
    model.eval()
    with torch.no_grad():
        logits = model(
            batch_features['code_features'],
            batch_features['ast_features'],
            batch_features['cfg_features'],
            batch_features['pdg_features']
        )
    
    print(f"Output logits shape: {logits.shape}")
    print(f"Predictions: {torch.argmax(logits, dim=1).tolist()}")
    
    # Calculate accuracy on random predictions (should be ~50%)
    predictions = torch.argmax(logits, dim=1)
    correct = (predictions == labels).sum().item()
    accuracy = correct / len(labels)
    
    print(f"\n📈 Random model accuracy: {accuracy:.2%}")
    print(f"   (Should be around 50% for untrained model)")
    
    print("\n" + "="*60)
    print("✅ All components working correctly!")
    print("="*60)
    print("\nNext steps:")
    print("1. Run 'python train.py' to start training")
    print("2. Monitor training curves and metrics")
    print("3. Evaluate on test set after training")


if __name__ == '__main__':
    main()
