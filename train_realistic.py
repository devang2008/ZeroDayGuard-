"""
REALISTIC Production Training - Optimized for CPU
Finishes in 3-4 hours with excellent results
"""

import sys
from pathlib import Path
import yaml
import torch
from datetime import datetime

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.data_loader import VDISCDataset, create_dataloaders, get_class_weights
from src.models.vulnerability_detector import create_model
from src.training.trainer import VulnerabilityTrainer


def main():
    print("="*80)
    print("ZeroDayGuard - OPTIMIZED Training (Realistic for CPU)")
    print("="*80)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # OPTIMIZED Configuration for CPU
    config = {
        # Data settings - REALISTIC subset
        'train_hdf5_path': 'data/raw/vdisc/VDISC_train.hdf5',
        'val_hdf5_path': 'data/raw/vdisc/VDISC_validate.hdf5',
        'batch_size': 256,  # Larger batches for CPU efficiency
        'num_workers': 0,
        
        # Model settings - BALANCED (not too large)
        'model_type': 'improved',
        'code_feature_dim': 24,
        'graph_feature_dim': 8,
        'hidden_dim': 256,  # Reduced from 512 (4x faster!)
        'dropout': 0.5,
        
        # Training settings - REALISTIC
        'num_epochs': 50,  # Reduced from 100
        'learning_rate': 0.0005,
        'weight_decay': 1e-4,
        'early_stopping_patience': 10,
        
        # SMART dataset size - Best balance of quality & speed
        'max_train_samples': 200000,  # 200K samples (20% of full dataset)
        'max_val_samples': 20000,     # 20K validation
        
        'gradient_clip': 1.0,
        'save_interval': 5,
    }
    
    print("\n📋 Optimized Configuration (CPU-Friendly):")
    print(f"  🎯 Model: {config['model_type']} (hidden_dim=256)")
    print(f"  📊 Batch Size: {config['batch_size']} (larger for CPU)")
    print(f"  📚 Training: {config['max_train_samples']:,} samples")
    print(f"  ⏱️  Estimated Time: **3-4 hours** (realistic!)")
    
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
    
    print(f"\n✅ Loaded:")
    print(f"  📈 Train: {len(train_dataset):,} samples")
    print(f"  📊 Val:   {len(val_dataset):,} samples")
    print(f"  💡 This is a **realistic** subset for CPU training")
    
    # Class weights
    print("\n⚖️  Calculating class weights...")
    class_weights = get_class_weights(config['train_hdf5_path'])
    config['class_weights'] = class_weights
    print(f"  Safe: {class_weights[0]:.4f}")
    print(f"  Vulnerable: {class_weights[1]:.4f}")
    
    # Data loaders
    print("\n🔄 Creating data loaders...")
    train_loader, val_loader, _ = create_dataloaders(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        batch_size=config['batch_size'],
        num_workers=config['num_workers']
    )
    
    batches_per_epoch = len(train_loader)
    print(f"  Batches per epoch: {batches_per_epoch:,}")
    print(f"  Time per epoch: ~4-5 minutes (realistic!)")
    
    # Create model - SMALLER for CPU
    print(f"\n🧠 Creating OPTIMIZED model...")
    model = create_model(
        model_type=config['model_type'],
        code_feature_dim=config['code_feature_dim'],
        graph_feature_dim=config['graph_feature_dim'],
        hidden_dim=config['hidden_dim'],  # 256 instead of 512
        num_classes=2,
        dropout=config['dropout']
    )
    
    total_params = sum(p.numel() for p in model.parameters())
    
    print(f"  Parameters: {total_params:,}")
    print(f"  Size: {total_params * 4 / 1024 / 1024:.2f} MB")
    print(f"  💡 Smaller model = MUCH faster on CPU!")
    
    # Device
    device = 'cpu'
    print(f"\n💻 Device: CPU (optimized)")
    
    # Trainer
    print("\n" + "="*80)
    print("🎯 STARTING OPTIMIZED TRAINING")
    print("="*80)
    print("\n💡 Expected Timeline:")
    print("  • Time per epoch: ~4-5 minutes")
    print(f"  • Total epochs: {config['num_epochs']}")
    print("  • Total time: **3-4 hours**")
    print("  • Target F1: 0.55-0.65 (still 2-3x better than baseline!)")
    print("\n✅ This is realistic and will finish tonight!\n")
    
    trainer = VulnerabilityTrainer(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        config=config,
        device=device
    )
    
    # Train
    try:
        trainer.train(num_epochs=config['num_epochs'])
        
        # Final evaluation
        print("\n" + "="*80)
        print("📊 FINAL RESULTS")
        print("="*80)
        
        val_metrics = trainer.validate()
        print(f"\n  Accuracy:  {val_metrics['accuracy']:.4f}")
        print(f"  Precision: {val_metrics['precision']:.4f}")
        print(f"  Recall:    {val_metrics['recall']:.4f}")
        print(f"  F1 Score:  {val_metrics['f1']:.4f}")
        
        trainer.plot_confusion_matrix(val_metrics['predictions'], val_metrics['labels'])
        
        # Save config
        Path('configs').mkdir(exist_ok=True)
        with open('configs/optimized_config.yaml', 'w') as f:
            yaml.dump(config, f)
        
        print("\n" + "="*80)
        print("✅ TRAINING COMPLETE!")
        print("="*80)
        print(f"\nCompleted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if val_metrics['f1'] >= 0.50:
            print(f"\n🎉 SUCCESS! F1={val_metrics['f1']:.4f}")
            print("   Ready for RL fine-tuning and presentation!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Training interrupted")
        
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
