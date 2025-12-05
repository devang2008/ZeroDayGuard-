"""
Monitor training progress in real-time
"""

import time
from pathlib import Path
import torch
from datetime import datetime, timedelta


def monitor_training():
    """Monitor training progress"""
    
    print("="*70)
    print("📊 ZeroDayGuard - Training Monitor")
    print("="*70)
    
    model_path = Path('data/models/best_model.pth')
    results_path = Path('results/training_curves.png')
    
    start_time = datetime.now()
    last_modified = None
    
    print(f"\n⏰ Started monitoring: {start_time.strftime('%H:%M:%S')}")
    print(f"📁 Watching: {model_path}")
    print(f"\n💡 This script checks for training updates every 5 minutes")
    print("Press Ctrl+C to stop monitoring\n")
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            current_time = datetime.now()
            elapsed = current_time - start_time
            
            print(f"\n[Check #{iteration}] {current_time.strftime('%H:%M:%S')} (Elapsed: {elapsed})")
            
            # Check if model exists
            if model_path.exists():
                # Get modification time
                mod_time = datetime.fromtimestamp(model_path.stat().st_mtime)
                
                if last_modified is None or mod_time > last_modified:
                    # Model updated!
                    print(f"  ✅ Model updated: {mod_time.strftime('%H:%M:%S')}")
                    
                    # Load and show metrics
                    try:
                        checkpoint = torch.load(model_path, map_location='cpu')
                        
                        if 'best_val_f1' in checkpoint:
                            f1 = checkpoint['best_val_f1']
                            epoch = checkpoint.get('epoch', 'unknown')
                            print(f"  📈 Best F1: {f1:.4f} (Epoch {epoch})")
                            
                            # Progress estimate
                            if f1 > 0.60:
                                print(f"  🎉 EXCELLENT! Target achieved!")
                            elif f1 > 0.50:
                                print(f"  ✅ GOOD! Getting close to target")
                            elif f1 > 0.40:
                                print(f"  📊 Making progress...")
                            else:
                                print(f"  ⏳ Early stages, keep training...")
                        
                        if 'history' in checkpoint:
                            history = checkpoint['history']
                            epochs_done = len(history.get('train_loss', []))
                            print(f"  📊 Epochs completed: {epochs_done}")
                    
                    except Exception as e:
                        print(f"  ⚠️  Could not read checkpoint: {e}")
                    
                    last_modified = mod_time
                else:
                    print(f"  ⏳ Training in progress (no updates since last check)")
                    print(f"     Last update: {mod_time.strftime('%H:%M:%S')}")
            else:
                print(f"  ⏳ Model not created yet (still loading data or early epochs)")
            
            # Check results
            if results_path.exists():
                print(f"  📊 Training curves generated")
            
            # Estimate completion
            if elapsed.total_seconds() > 0:
                estimated_total = timedelta(hours=14)  # Average estimate
                remaining = estimated_total - elapsed
                
                if remaining.total_seconds() > 0:
                    print(f"  ⏱️  Estimated remaining: ~{remaining.total_seconds() / 3600:.1f} hours")
                else:
                    print(f"  🎯 Should be completing soon!")
            
            # Wait 5 minutes
            print(f"\n  💤 Next check in 5 minutes...")
            time.sleep(300)  # 5 minutes
            
    except KeyboardInterrupt:
        print("\n\n✋ Monitoring stopped by user")
        print(f"Total monitoring time: {datetime.now() - start_time}")


if __name__ == '__main__':
    monitor_training()
