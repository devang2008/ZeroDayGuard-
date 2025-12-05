"""
Main Training Script for ZeroDayGuard
Run this script to train the vulnerability detection model
"""

import sys
from pathlib import Path
import yaml
import torch

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.data_loader import VDISCDataset, create_dataloaders, get_class_weights
from src.models.vulnerability_detector import create_model
from src.training.trainer import VulnerabilityTrainer


def main():
    """Main training function"""
    
    print("="*60)
    print("ZeroDayGuard - Vulnerability Detection Training")
    print("="*60)
    
    # Configuration
    config = {
        # Data settings
        'train_hdf5_path': 'data/raw/vdisc/VDISC_train.hdf5',
        'val_hdf5_path': 'data/raw/vdisc/VDISC_validate.hdf5',
        'batch_size': 32,
        'num_workers': 0,  # Set to 0 for Windows
        
        # Model settings
        'model_type': 'simple',  # or 'improved'
        'code_feature_dim': 24,  # 5 basic + 18 keywords + 1 dangerous count
        'graph_feature_dim': 8,
        'hidden_dim': 128,
        'dropout': 0.3,
        
        # Training settings
        'num_epochs': 50,
        'learning_rate': 0.001,
        'weight_decay': 1e-5,
        'early_stopping_patience': 10,
        
        # For quick testing - limit samples
        'max_train_samples': 10000,  # Quick test with 10K samples
        'max_val_samples': 2000,     # Quick test with 2K validation samples
    }
    
    print("\n📋 Configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
    
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
    
    print(f"✅ Train samples: {len(train_dataset):,}")
    print(f"✅ Val samples: {len(val_dataset):,}")
    
    # Calculate class weights
    print("\n⚖️ Calculating class weights...")
    class_weights = get_class_weights(config['train_hdf5_path'])
    config['class_weights'] = class_weights
    print(f"Class weights: {class_weights}")
    
    # Create data loaders
    print("\n🔄 Creating data loaders...")
    train_loader, val_loader, _ = create_dataloaders(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        test_dataset=None,
        batch_size=config['batch_size'],
        num_workers=config['num_workers']
    )
    
    # Create model
    print(f"\n🧠 Creating {config['model_type']} model...")
    model = create_model(
        model_type=config['model_type'],
        code_feature_dim=config['code_feature_dim'],
        graph_feature_dim=config['graph_feature_dim'],
        hidden_dim=config['hidden_dim'],
        num_classes=2,
        dropout=config['dropout']
    )
    
    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total parameters: {total_params:,}")
    print(f"Trainable parameters: {trainable_params:,}")
    
    # Create trainer
    print("\n🎯 Initializing trainer...")
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
    
    # Evaluate final model
    print("\n📊 Final Evaluation...")
    val_metrics = trainer.validate()
    
    print(f"\nFinal Validation Metrics:")
    print(f"  Accuracy:  {val_metrics['accuracy']:.4f}")
    print(f"  Precision: {val_metrics['precision']:.4f}")
    print(f"  Recall:    {val_metrics['recall']:.4f}")
    print(f"  F1 Score:  {val_metrics['f1']:.4f}")
    
    # Plot confusion matrix
    trainer.plot_confusion_matrix(val_metrics['predictions'], val_metrics['labels'])
    
    # Save final config
    print("\n💾 Saving configuration...")
    Path('configs').mkdir(exist_ok=True)
    with open('configs/training_config.yaml', 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print("\n" + "="*60)
    print("✅ Training completed successfully!")
    print("="*60)
    print(f"\n📁 Outputs:")
    print(f"  Model: data/models/best_model.pth")
    print(f"  Training curves: results/training_curves.png")
    print(f"  Confusion matrix: results/confusion_matrix.png")
    print(f"  Config: configs/training_config.yaml")


if __name__ == '__main__':
    main()
