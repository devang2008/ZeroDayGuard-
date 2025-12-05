"""
Data Loader for VDISC Dataset
Loads and preprocesses the VDISC vulnerability dataset
"""

import h5py
import numpy as np
from typing import Tuple, List, Dict
from pathlib import Path
import torch
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm

from .code_parser import CodeParser
from .graph_generator import SimpleGraphGenerator


class VDISCDataset(Dataset):
    """
    PyTorch Dataset for VDISC vulnerability data
    """
    
    def __init__(self, 
                 hdf5_path: str,
                 max_samples: int = None,
                 binary_classification: bool = True,
                 use_cache: bool = True):
        """
        Initialize VDISC dataset
        
        Args:
            hdf5_path: Path to HDF5 file
            max_samples: Maximum number of samples to load (None = all)
            binary_classification: If True, any vulnerability = 1, else multi-label
            use_cache: Cache processed features
        """
        self.hdf5_path = hdf5_path
        self.max_samples = max_samples
        self.binary_classification = binary_classification
        self.use_cache = use_cache
        
        self.parser = CodeParser()
        self.graph_gen = SimpleGraphGenerator()
        
        # Load data
        self._load_data()
    
    def _load_data(self):
        """Load data from HDF5 file"""
        print(f"Loading data from {self.hdf5_path}...")
        
        with h5py.File(self.hdf5_path, 'r') as f:
            # Load source code
            self.source_codes = f['functionSource'][:]
            
            # Decode bytes to strings
            self.source_codes = [code.decode('utf-8') if isinstance(code, bytes) 
                                else code for code in self.source_codes]
            
            # Load labels
            cwe_types = ['CWE-119', 'CWE-120', 'CWE-469', 'CWE-476', 'CWE-other']
            
            if self.binary_classification:
                # Any vulnerability = 1, safe = 0
                labels = np.zeros(len(self.source_codes), dtype=np.int64)
                for cwe in cwe_types:
                    labels |= f[cwe][:].astype(np.int64)
                self.labels = labels
            else:
                # Multi-label classification
                self.labels = np.column_stack([f[cwe][:] for cwe in cwe_types])
        
        # Limit samples if specified
        if self.max_samples:
            self.source_codes = self.source_codes[:self.max_samples]
            self.labels = self.labels[:self.max_samples]
        
        print(f"Loaded {len(self.source_codes)} samples")
        
        # Calculate class distribution
        if self.binary_classification:
            vulnerable = np.sum(self.labels)
            safe = len(self.labels) - vulnerable
            print(f"  Safe: {safe} ({safe/len(self.labels)*100:.1f}%)")
            print(f"  Vulnerable: {vulnerable} ({vulnerable/len(self.labels)*100:.1f}%)")
    
    def __len__(self) -> int:
        return len(self.source_codes)
    
    def __getitem__(self, idx: int) -> Tuple[Dict, int]:
        """
        Get a single sample
        
        Returns:
            Tuple of (features_dict, label)
        """
        source_code = self.source_codes[idx]
        label = self.labels[idx]
        
        # Parse code and extract features
        parsed = self.parser.parse(source_code)
        code_features = self.parser.extract_features(parsed)
        
        # Generate graphs
        graphs = self.graph_gen.generate_all_graphs(source_code)
        
        # Extract graph features
        ast_features = self.graph_gen.get_graph_features(graphs['ast'])
        cfg_features = self.graph_gen.get_graph_features(graphs['cfg'])
        pdg_features = self.graph_gen.get_graph_features(graphs['pdg'])
        
        # Combine all features
        features = {
            'code_features': torch.FloatTensor(code_features),
            'ast_features': torch.FloatTensor(ast_features),
            'cfg_features': torch.FloatTensor(cfg_features),
            'pdg_features': torch.FloatTensor(pdg_features),
            'ast_graph': graphs['ast'],
            'cfg_graph': graphs['cfg'],
            'pdg_graph': graphs['pdg'],
            'source_code': source_code
        }
        
        return features, label


def create_dataloaders(
    train_dataset: 'VDISCDataset' = None,
    val_dataset: 'VDISCDataset' = None,
    test_dataset: 'VDISCDataset' = None,
    train_path: str = None,
    val_path: str = None,
    test_path: str = None,
    batch_size: int = 32,
    max_samples_train: int = None,
    max_samples_val: int = None,
    max_samples_test: int = None,
    num_workers: int = 0
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """
    Create DataLoaders for train, validation, and test sets
    
    Args:
        train_dataset: Pre-created training dataset (optional)
        val_dataset: Pre-created validation dataset (optional)
        test_dataset: Pre-created test dataset (optional)
        train_path: Path to training HDF5 file (used if dataset not provided)
        val_path: Path to validation HDF5 file (used if dataset not provided)
        test_path: Path to test HDF5 file (used if dataset not provided)
        batch_size: Batch size for training
        max_samples_*: Maximum samples to load from each set
        num_workers: Number of worker processes for data loading
        
    Returns:
        Tuple of (train_loader, val_loader, test_loader)
    """
    # Create datasets if not provided
    if train_dataset is None and train_path is not None:
        train_dataset = VDISCDataset(train_path, max_samples=max_samples_train)
    if val_dataset is None and val_path is not None:
        val_dataset = VDISCDataset(val_path, max_samples=max_samples_val)
    if test_dataset is None and test_path is not None:
        test_dataset = VDISCDataset(test_path, max_samples=max_samples_test)
    
    # Create dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
        collate_fn=collate_fn
    ) if train_dataset is not None else None
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        collate_fn=collate_fn
    ) if val_dataset is not None else None
    
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        collate_fn=collate_fn
    ) if test_dataset is not None else None
    
    return train_loader, val_loader, test_loader


def collate_fn(batch):
    """
    Custom collate function for batching
    
    Args:
        batch: List of (features, label) tuples
        
    Returns:
        Batched features and labels
    """
    features_list, labels_list = zip(*batch)
    
    # Stack features
    code_features = torch.stack([f['code_features'] for f in features_list])
    ast_features = torch.stack([f['ast_features'] for f in features_list])
    cfg_features = torch.stack([f['cfg_features'] for f in features_list])
    pdg_features = torch.stack([f['pdg_features'] for f in features_list])
    
    # Keep graphs as list (can't stack graphs directly)
    ast_graphs = [f['ast_graph'] for f in features_list]
    cfg_graphs = [f['cfg_graph'] for f in features_list]
    pdg_graphs = [f['pdg_graph'] for f in features_list]
    
    # Stack labels
    labels = torch.LongTensor(labels_list)
    
    batched_features = {
        'code_features': code_features,
        'ast_features': ast_features,
        'cfg_features': cfg_features,
        'pdg_features': pdg_features,
        'ast_graphs': ast_graphs,
        'cfg_graphs': cfg_graphs,
        'pdg_graphs': pdg_graphs
    }
    
    return batched_features, labels


def get_class_weights(train_path: str) -> torch.Tensor:
    """
    Calculate class weights for imbalanced dataset
    
    Args:
        train_path: Path to training HDF5 file
        
    Returns:
        Tensor of class weights
    """
    with h5py.File(train_path, 'r') as f:
        cwe_types = ['CWE-119', 'CWE-120', 'CWE-469', 'CWE-476', 'CWE-other']
        labels = np.zeros(len(f['functionSource']), dtype=np.int64)
        for cwe in cwe_types:
            labels |= f[cwe][:].astype(np.int64)
    
    # Calculate class counts
    unique, counts = np.unique(labels, return_counts=True)
    
    # Calculate weights (inverse frequency)
    total = len(labels)
    weights = total / (len(unique) * counts)
    
    print(f"\nClass Distribution:")
    for u, c, w in zip(unique, counts, weights):
        print(f"  Class {u}: {c} samples ({c/total*100:.1f}%), weight: {w:.4f}")
    
    return torch.FloatTensor(weights)
