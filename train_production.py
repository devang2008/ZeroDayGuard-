"""
Production Training with Full Dataset + RL Fine-tuning
Option C: Best Results for Real-World Deployment
"""

import sys
from pathlib import Path
import yaml
import torch
import torch.nn as nn
from datetime import datetime

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.data_loader import VDISCDataset, create_dataloaders, get_class_weights
from src.models.production_model import create_production_model
from src.training.trainer import VulnerabilityTrainer


def main():
    print("="*80)
    print("🚀 ZeroDayGuard - PRODUCTION TRAINING (Full Dataset)")
    print("="*80)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # PRODUCTION Configuration - Full Dataset
    config = {
        # Data settings - FULL DATASET
        'train_hdf5_path': 'data/raw/vdisc/VDISC_train.hdf5',
        'val_hdf5_path': 'data/raw/vdisc/VDISC_validate.hdf5',
        'batch_size': 128,  # Large batch for GPU efficiency
        'num_workers': 0,
        
        # Model settings - IMPROVED ARCHITECTURE
        'model_type': 'improved',  # Attention-based model
        'code_feature_dim': 24,
        'graph_feature_dim': 8,
        'hidden_dim': 512,  # Large capacity for complex patterns
        'dropout': 0.5,
        
        # Training settings - PRODUCTION
        'num_epochs': 100,  # More epochs for convergence
        'learning_rate': 0.0003,  # Stable learning
        'weight_decay': 1e-4,
        'early_stopping_patience': 15,  # Patient for full dataset
        
        # FULL DATASET - Use all available data
        'max_train_samples': None,  # Use ALL 1,019,471 samples
        'max_val_samples': None,    # Use ALL 127,476 samples
        
        # Advanced settings
        'gradient_clip': 1.0,
        'save_interval': 5,  # Save every 5 epochs
    }
    
    print("\n📋 Production Configuration:")
    print(f"  🎯 Model: {config['model_type']} with Attention")
    print(f"  🧠 Hidden Dim: {config['hidden_dim']}")
    print(f"  📊 Batch Size: {config['batch_size']}")
    print(f"  📚 Training: FULL DATASET (~1M samples)")
    print(f"  ⏱️  Estimated Time: 12-15 hours")
    
    # Create datasets
    print("\n📦 Loading FULL datasets...")
    print("  ⏳ This may take a few minutes...")
    
    train_dataset = VDISCDataset(
        hdf5_path=config['train_hdf5_path'],
        max_samples=config['max_train_samples']
    )
    val_dataset = VDISCDataset(
        hdf5_path=config['val_hdf5_path'],
        max_samples=config['max_val_samples']
    )
    
    print(f"\n✅ Loaded:")
    print(f"  📈 Train: {len(train_dataset):,} samples")
    print(f"  📊 Val:   {len(val_dataset):,} samples")
    print(f"  💾 Total: {len(train_dataset) + len(val_dataset):,} samples")
    
    # Class weights for imbalance
    print("\n⚖️  Calculating class weights...")
    class_weights = get_class_weights(config['train_hdf5_path'])
    config['class_weights'] = class_weights
    print(f"  Safe: {class_weights[0]:.4f}")
    print(f"  Vulnerable: {class_weights[1]:.4f}")
    print(f"  Ratio: 1:{class_weights[1]/class_weights[0]:.1f}")
    
    # Data loaders
    print("\n🔄 Creating data loaders...")
    train_loader, val_loader, _ = create_dataloaders(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        batch_size=config['batch_size'],
        num_workers=config['num_workers']
    )
    
    print(f"  Batches per epoch: {len(train_loader):,}")
    print(f"  Validation batches: {len(val_loader):,}")
    
    # Create PRODUCTION model with attention
    print(f"\n🧠 Creating PRODUCTION model...")
    model = create_production_model(
        model_type='production',
        code_feature_dim=config['code_feature_dim'],
        graph_feature_dim=config['graph_feature_dim'],
        hidden_dim=config['hidden_dim'],
        num_classes=2,
        dropout=config['dropout']
    )
    
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    
    print(f"  Total Parameters: {total_params:,}")
    print(f"  Trainable: {trainable_params:,}")
    print(f"  Model Size: {total_params * 4 / 1024 / 1024:.2f} MB")
    
    # Device selection
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"\n💻 Device: {device.upper()}")
    
    if device == 'cuda':
        print(f"  GPU: {torch.cuda.get_device_name(0)}")
        print(f"  Memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
    else:
        print("  ⚠️  CPU training - Will take 12-15 hours")
    
    # Trainer
    print("\n" + "="*80)
    print("🎯 STARTING PRODUCTION TRAINING")
    print("="*80)
    print("\n💡 Tips:")
    print("  • This will run for 12-15 hours")
    print("  • Best model saved automatically at each improvement")
    print("  • Early stopping will prevent overfitting")
    print("  • Progress saved every 5 epochs")
    print("\n🔴 DO NOT close this window!\n")
    
    trainer = VulnerabilityTrainer(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        config=config,
        device=device
    )
    
    # Start training
    try:
        trainer.train(num_epochs=config['num_epochs'])
        
        # Final evaluation
        print("\n" + "="*80)
        print("📊 FINAL VALIDATION METRICS")
        print("="*80)
        
        val_metrics = trainer.validate()
        print(f"\n  Accuracy:  {val_metrics['accuracy']:.4f}")
        print(f"  Precision: {val_metrics['precision']:.4f}")
        print(f"  Recall:    {val_metrics['recall']:.4f}")
        print(f"  F1 Score:  {val_metrics['f1']:.4f}")
        
        trainer.plot_confusion_matrix(val_metrics['predictions'], val_metrics['labels'])
        
        # Save config
        Path('configs').mkdir(exist_ok=True)
        with open('configs/production_config.yaml', 'w') as f:
            yaml.dump(config, f)
        
        print("\n" + "="*80)
        print("✅ PRODUCTION TRAINING COMPLETE!")
        print("="*80)
        print(f"\nCompleted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n📁 Outputs:")
        print(f"  🎯 Model: data/models/best_model.pth")
        print(f"  📈 Curves: results/training_curves.png")
        print(f"  📊 Matrix: results/confusion_matrix.png")
        print(f"  ⚙️  Config: configs/production_config.yaml")
        
        if val_metrics['f1'] >= 0.60:
            print(f"\n🎉 EXCELLENT! F1={val_metrics['f1']:.4f} - Production Ready!")
        elif val_metrics['f1'] >= 0.50:
            print(f"\n✅ GOOD! F1={val_metrics['f1']:.4f} - Ready for deployment")
        else:
            print(f"\n⚠️  F1={val_metrics['f1']:.4f} - May need RL fine-tuning")
        
        print("\n🔄 Next: Run python train_rl.py for RL fine-tuning")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Training interrupted by user")
        print("💾 Model checkpoint saved at last validation")
        
    except Exception as e:
        print(f"\n\n❌ Error during training: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
