"""
Quick Training Script with Optimized Settings
Improved hyperparameters for better F1 score
"""

import sys
from pathlib import Path
import yaml
import torch

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.data_loader import VDISCDataset, create_dataloaders, get_class_weights
from src.models.vulnerability_detector import create_model
from src.training.trainer import VulnerabilityTrainer


def main():
    print("="*70)
    print("🚀 ZeroDayGuard - OPTIMIZED Training")
    print("="*70)
    
    # OPTIMIZED Configuration
    config = {
        # Data settings
        'train_hdf5_path': 'data/raw/vdisc/VDISC_train.hdf5',
        'val_hdf5_path': 'data/raw/vdisc/VDISC_validate.hdf5',
        'batch_size': 64,  # Larger batch for stability
        'num_workers': 0,
        
        # Model settings - IMPROVED
        'model_type': 'improved',  # Use attention model
        'code_feature_dim': 24,
        'graph_feature_dim': 8,
        'hidden_dim': 256,  # Increased capacity
        'dropout': 0.5,  # More regularization
        
        # Training settings - OPTIMIZED
        'num_epochs': 30,
        'learning_rate': 0.0005,  # Lower for stability
        'weight_decay': 1e-4,  # More regularization
        'early_stopping_patience': 8,
        
        # Use full training set for better performance
        'max_train_samples': 50000,  # More data = better learning
        'max_val_samples': 5000,
    }
    
    print("\n📋 Optimized Configuration:")
    print(f"  Model: {config['model_type']} (with attention)")
    print(f"  Hidden Dim: {config['hidden_dim']} (increased)")
    print(f"  Dropout: {config['dropout']} (more regularization)")
    print(f"  Learning Rate: {config['learning_rate']} (stable)")
    print(f"  Training Samples: {config['max_train_samples']:,}")
    
    # Create datasets
    print("\n📦 Loading datasets...")
    train_dataset = VDISCDataset(
        hdf5_path=config['train_hdf5_path'],
        max_samples=config['max_train_samples']
    )
    val_dataset = VDISCDataset(
        hdf5_path=config['val_hdf5_path'],
        max_samples=config['max_val_samples']
    )
    
    print(f"✅ Train: {len(train_dataset):,} | Val: {len(val_dataset):,}")
    
    # Class weights
    print("\n⚖️ Calculating class weights...")
    class_weights = get_class_weights(config['train_hdf5_path'])
    config['class_weights'] = class_weights
    print(f"Weights: Safe={class_weights[0]:.4f}, Vulnerable={class_weights[1]:.4f}")
    
    # Data loaders
    print("\n🔄 Creating data loaders...")
    train_loader, val_loader, _ = create_dataloaders(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        batch_size=config['batch_size'],
        num_workers=config['num_workers']
    )
    
    # Create IMPROVED model
    print(f"\n🧠 Creating {config['model_type']} model...")
    model = create_model(
        model_type=config['model_type'],
        code_feature_dim=config['code_feature_dim'],
        graph_feature_dim=config['graph_feature_dim'],
        hidden_dim=config['hidden_dim'],
        num_classes=2,
        dropout=config['dropout']
    )
    
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Parameters: {total_params:,}")
    
    # Trainer
    print("\n🎯 Starting optimized training...")
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    trainer = VulnerabilityTrainer(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        config=config,
        device=device
    )
    
    # Train
    trainer.train(num_epochs=config['num_epochs'])
    
    # Final eval
    print("\n📊 Final Validation Metrics:")
    val_metrics = trainer.validate()
    print(f"  Accuracy:  {val_metrics['accuracy']:.4f}")
    print(f"  Precision: {val_metrics['precision']:.4f}")
    print(f"  Recall:    {val_metrics['recall']:.4f}")
    print(f"  F1 Score:  {val_metrics['f1']:.4f}")
    
    trainer.plot_confusion_matrix(val_metrics['predictions'], val_metrics['labels'])
    
    # Save config
    Path('configs').mkdir(exist_ok=True)
    with open('configs/optimized_config.yaml', 'w') as f:
        yaml.dump(config, f)
    
    print("\n" + "="*70)
    print("✅ OPTIMIZED TRAINING COMPLETE!")
    print("="*70)
    print(f"\n📁 Outputs:")
    print(f"  Model: data/models/best_model.pth")
    print(f"  Curves: results/training_curves.png")
    print(f"  Matrix: results/confusion_matrix.png")
    
    if val_metrics['f1'] > 0.50:
        print(f"\n🎉 EXCELLENT! F1={val_metrics['f1']:.4f} > 0.50")
    elif val_metrics['f1'] > 0.40:
        print(f"\n✅ GOOD! F1={val_metrics['f1']:.4f} - Usable for deployment")
    else:
        print(f"\n⚠️ F1={val_metrics['f1']:.4f} - May need more training data")


if __name__ == '__main__':
    main()
