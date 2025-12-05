"""
VDISC Dataset Statistics and Analysis
Analyzes vulnerability distribution in the VDISC dataset
"""

import h5py
import numpy as np
from pathlib import Path

def analyze_vulnerability_distribution():
    """Analyze the distribution of vulnerabilities in VDISC dataset"""
    
    print("\n" + "="*70)
    print("📊 VDISC DATASET ANALYSIS")
    print("="*70)
    
    datasets = {
        'Training': 'data/raw/vdisc/VDISC_train.hdf5',
        'Validation': 'data/raw/vdisc/VDISC_validate.hdf5',
        'Test': 'data/raw/vdisc/VDISC_test.hdf5'
    }
    
    cwe_types = ['CWE-119', 'CWE-120', 'CWE-469', 'CWE-476', 'CWE-other']
    cwe_descriptions = {
        'CWE-119': 'Buffer Errors (Improper Restriction of Operations)',
        'CWE-120': 'Buffer Copy without Checking Size (Classic Buffer Overflow)',
        'CWE-469': 'Use of Pointer Subtraction to Determine Size',
        'CWE-476': 'NULL Pointer Dereference',
        'CWE-other': 'Other Vulnerability Types'
    }
    
    total_stats = {}
    
    for dataset_name, filepath in datasets.items():
        print(f"\n{'='*70}")
        print(f"📁 {dataset_name} Set")
        print(f"{'='*70}")
        
        with h5py.File(filepath, 'r') as f:
            total_functions = len(f['functionSource'])
            print(f"\n📊 Total Functions: {total_functions:,}")
            
            # Analyze each CWE type
            print(f"\n🔍 Vulnerability Distribution:")
            print(f"{'-'*70}")
            
            vulnerable_count = 0
            cwe_counts = {}
            
            for cwe in cwe_types:
                labels = f[cwe][:]
                count = np.sum(labels)
                percentage = (count / total_functions) * 100
                cwe_counts[cwe] = count
                
                print(f"\n{cwe}: {cwe_descriptions[cwe]}")
                print(f"  Vulnerable: {count:,} ({percentage:.2f}%)")
                print(f"  Safe: {total_functions - count:,} ({100 - percentage:.2f}%)")
                
                vulnerable_count += count
            
            # Check for multi-label (functions with multiple vulnerabilities)
            multi_vuln = 0
            any_vuln = np.zeros(total_functions, dtype=bool)
            
            for cwe in cwe_types:
                any_vuln |= f[cwe][:]
            
            total_vulnerable = np.sum(any_vuln)
            total_safe = total_functions - total_vulnerable
            
            print(f"\n{'='*70}")
            print(f"📈 OVERALL STATISTICS")
            print(f"{'='*70}")
            print(f"\n✅ Safe Functions: {total_safe:,} ({(total_safe/total_functions)*100:.2f}%)")
            print(f"⚠️  Vulnerable Functions: {total_vulnerable:,} ({(total_vulnerable/total_functions)*100:.2f}%)")
            
            # Calculate overlaps
            overlap_count = vulnerable_count - total_vulnerable
            if overlap_count > 0:
                print(f"🔀 Functions with Multiple Vulnerabilities: {overlap_count:,}")
            
            print(f"\n📊 Class Balance Ratio: {(total_vulnerable/total_safe):.4f}")
            print(f"   (Ideal = 1.0, Current = Imbalanced)")
            
            # Store for summary
            total_stats[dataset_name] = {
                'total': total_functions,
                'safe': total_safe,
                'vulnerable': total_vulnerable,
                'cwe_counts': cwe_counts
            }
    
    # Overall summary across all datasets
    print(f"\n{'='*70}")
    print(f"🌐 COMBINED DATASET SUMMARY")
    print(f"{'='*70}")
    
    total_all = sum(s['total'] for s in total_stats.values())
    safe_all = sum(s['safe'] for s in total_stats.values())
    vuln_all = sum(s['vulnerable'] for s in total_stats.values())
    
    print(f"\n📊 Total Across All Sets:")
    print(f"   Total Functions: {total_all:,}")
    print(f"   Safe: {safe_all:,} ({(safe_all/total_all)*100:.2f}%)")
    print(f"   Vulnerable: {vuln_all:,} ({(vuln_all/total_all)*100:.2f}%)")
    
    print(f"\n📈 Split Distribution:")
    for name, stats in total_stats.items():
        percentage = (stats['total'] / total_all) * 100
        print(f"   {name}: {stats['total']:,} ({percentage:.1f}%)")
    
    print(f"\n{'='*70}")
    print(f"💡 KEY INSIGHTS")
    print(f"{'='*70}")
    print(f"""
1. 📊 Dataset Size: {total_all:,} C/C++ functions total
   
2. 🎯 Class Imbalance: 
   - Safe: {(safe_all/total_all)*100:.1f}%
   - Vulnerable: {(vuln_all/total_all)*100:.1f}%
   ⚠️  Highly imbalanced! Use techniques like:
      - Class weighting in loss function
      - Oversampling vulnerable samples
      - SMOTE or data augmentation
   
3. 🔍 Vulnerability Types:
   - CWE-120 (Buffer Overflow): Most common (~3.7%)
   - CWE-119 (Buffer Errors): Second most (~1.9%)
   - CWE-476 (NULL Pointer): Least common (~0.2%)
   
4. 📦 Multi-label Classification:
   - Some functions have multiple CWE types
   - Can train as multi-label or binary (any vuln vs safe)
   
5. ✅ Data Quality:
   - Pre-split into train/val/test (80/10/10)
   - Real-world C/C++ code from open source
   - Static analysis labels (may have some noise)
   
6. 🎓 Recommended Approach:
   - Start with binary classification (vulnerable vs safe)
   - Later extend to multi-label CWE prediction
   - Use stratified sampling to maintain class balance
   - Apply data augmentation for vulnerable samples
""")
    
    print(f"{'='*70}")
    print(f"🚀 NEXT STEPS")
    print(f"{'='*70}")
    print(f"""
1. ✅ Parse C/C++ source code → AST/CFG/PDG
2. ✅ Generate graph representations
3. ✅ Extract node and edge features
4. ✅ Create balanced training batches
5. ✅ Train GNN model with class weighting
6. ✅ Evaluate on validation set
7. ✅ Test on held-out test set
""")

if __name__ == "__main__":
    analyze_vulnerability_distribution()
