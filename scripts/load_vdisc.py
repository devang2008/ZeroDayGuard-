"""
VDISC Dataset Loader and Inspector
Loads and analyzes the Draper VDISC vulnerability dataset
"""

import h5py
import numpy as np
import os
from pathlib import Path

def inspect_hdf5_file(filepath):
    """Inspect the structure of an HDF5 file"""
    print(f"\n{'='*60}")
    print(f"📂 Inspecting: {os.path.basename(filepath)}")
    print(f"{'='*60}")
    
    try:
        with h5py.File(filepath, 'r') as f:
            print(f"\n📊 File Structure:")
            print(f"Keys/Datasets: {list(f.keys())}")
            
            # Inspect each dataset
            for key in f.keys():
                dataset = f[key]
                print(f"\n🔹 Dataset: '{key}'")
                print(f"   Shape: {dataset.shape}")
                print(f"   Dtype: {dataset.dtype}")
                print(f"   Size: {dataset.size:,} elements")
                
                # Show sample data (first few elements)
                if len(dataset.shape) == 1 and dataset.size <= 10:
                    print(f"   Data: {dataset[:]}")
                elif len(dataset.shape) == 1:
                    print(f"   Sample (first 5): {dataset[:5]}")
                else:
                    print(f"   Sample shape: {dataset[0].shape if len(dataset) > 0 else 'Empty'}")
            
            # Get attributes if any
            print(f"\n📝 File Attributes:")
            for attr_name, attr_value in f.attrs.items():
                print(f"   {attr_name}: {attr_value}")
        
        return True
    except Exception as e:
        print(f"❌ Error loading file: {e}")
        return False

def analyze_dataset_statistics(filepath, dataset_name):
    """Analyze statistics of the dataset"""
    print(f"\n{'='*60}")
    print(f"📈 Statistics for {dataset_name}")
    print(f"{'='*60}")
    
    try:
        with h5py.File(filepath, 'r') as f:
            # Look for common key names
            possible_label_keys = ['labels', 'label', 'target', 'targets', 'y', 'vulnerable']
            possible_data_keys = ['data', 'features', 'X', 'functions', 'code']
            
            # Find labels
            label_key = None
            for key in possible_label_keys:
                if key in f.keys():
                    label_key = key
                    break
            
            if label_key:
                labels = f[label_key][:]
                print(f"\n🎯 Label Distribution ('{label_key}'):")
                unique, counts = np.unique(labels, return_counts=True)
                total = len(labels)
                
                for val, count in zip(unique, counts):
                    percentage = (count / total) * 100
                    label_name = "Vulnerable" if val == 1 else "Safe" if val == 0 else f"Class {val}"
                    print(f"   {label_name} ({val}): {count:,} ({percentage:.2f}%)")
                
                print(f"\n   Total Samples: {total:,}")
                
                # Calculate balance ratio
                if len(unique) == 2:
                    ratio = min(counts) / max(counts)
                    print(f"   Balance Ratio: {ratio:.4f} (1.0 = perfectly balanced)")
            else:
                print(f"\n⚠️ Could not find label data. Available keys: {list(f.keys())}")
            
            # Print all keys for reference
            print(f"\n📋 All Available Keys:")
            for key in f.keys():
                print(f"   - {key}: shape {f[key].shape}")
                
    except Exception as e:
        print(f"❌ Error analyzing dataset: {e}")

def load_readme():
    """Load and display README content"""
    readme_path = "data/raw/vdisc/README"
    
    print(f"\n{'='*60}")
    print(f"📖 README Content")
    print(f"{'='*60}\n")
    
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(content)
    except FileNotFoundError:
        print("⚠️ README file not found")
    except Exception as e:
        print(f"⚠️ Error reading README: {e}")

def main():
    """Main function to inspect all VDISC files"""
    
    print("\n" + "="*60)
    print("🛡️  VDISC Dataset Inspector")
    print("="*60)
    
    # Define file paths
    base_path = Path("data/raw/vdisc")
    files = {
        'train': base_path / "VDISC_train.hdf5",
        'validate': base_path / "VDISC_validate.hdf5",
        'test': base_path / "VDISC_test.hdf5"
    }
    
    # Check if files exist
    print("\n🔍 Checking downloaded files...")
    all_exist = True
    for name, filepath in files.items():
        if filepath.exists():
            size_mb = filepath.stat().st_size / (1024 * 1024)
            print(f"   ✅ {filepath.name} ({size_mb:.1f} MB)")
        else:
            print(f"   ❌ {filepath.name} - NOT FOUND")
            all_exist = False
    
    if not all_exist:
        print("\n⚠️ Some files are missing. Please download all files.")
        return
    
    print("\n✅ All files found!")
    
    # Load README first
    load_readme()
    
    # Inspect each file
    for name, filepath in files.items():
        inspect_hdf5_file(str(filepath))
        analyze_dataset_statistics(str(filepath), name.capitalize())
    
    # Summary
    print(f"\n{'='*60}")
    print(f"✅ Dataset Inspection Complete!")
    print(f"{'='*60}")
    print(f"\nNext Steps:")
    print(f"1. Review the dataset structure above")
    print(f"2. Check label distribution (vulnerable vs safe)")
    print(f"3. Understand the data format")
    print(f"4. Start preprocessing for graph generation")
    print(f"\nUse this data to:")
    print(f"  - Train your GNN model")
    print(f"  - Validate hyperparameters")
    print(f"  - Test final performance")

if __name__ == "__main__":
    main()
