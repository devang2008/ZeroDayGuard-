"""
Project Structure Setup Script
Creates necessary directories for ZeroDayGuard project
"""

import os
from pathlib import Path

def create_directory_structure():
    """Create the complete project directory structure"""
    
    print("🏗️  Setting up ZeroDayGuard project structure...\n")
    
    # Define directory structure
    directories = [
        # Source code directories
        "src",
        "src/preprocessing",
        "src/features",
        "src/models",
        "src/training",
        "src/recommendation",
        "src/utils",
        "src/inference",
        
        # Data directories
        "data",
        "data/raw",
        "data/raw/vdisc",
        "data/processed",
        "data/processed/graphs",
        "data/processed/features",
        "data/models",
        "data/checkpoints",
        
        # Test directories
        "tests",
        "tests/unit",
        "tests/integration",
        
        # Configuration
        "configs",
        
        # Scripts
        "scripts",
        
        # Documentation
        "docs",
        "docs/images",
        
        # Frontend (optional)
        "frontend",
        "frontend/src",
        "frontend/public",
        
        # Logs
        "logs",
        
        # Results
        "results",
        "results/experiments",
        "results/reports",
    ]
    
    # Create directories
    created_count = 0
    existing_count = 0
    
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created: {directory}")
            created_count += 1
        else:
            print(f"   ⏭️  Exists: {directory}")
            existing_count += 1
    
    print(f"\n📊 Summary:")
    print(f"   Created: {created_count} directories")
    print(f"   Existed: {existing_count} directories")
    
    # Create __init__.py files for Python packages
    print(f"\n📝 Creating __init__.py files...")
    
    python_packages = [
        "src",
        "src/preprocessing",
        "src/features",
        "src/models",
        "src/training",
        "src/recommendation",
        "src/utils",
        "src/inference",
        "tests",
        "tests/unit",
        "tests/integration",
    ]
    
    for package in python_packages:
        init_file = Path(package) / "__init__.py"
        if not init_file.exists():
            init_file.touch()
            print(f"   ✅ Created: {init_file}")
    
    # Create .gitkeep files for empty directories
    print(f"\n📌 Creating .gitkeep files for version control...")
    
    gitkeep_dirs = [
        "data/raw/vdisc",
        "data/processed/graphs",
        "data/processed/features",
        "data/models",
        "data/checkpoints",
        "logs",
        "results/experiments",
        "results/reports",
    ]
    
    for directory in gitkeep_dirs:
        gitkeep_file = Path(directory) / ".gitkeep"
        if not gitkeep_file.exists():
            gitkeep_file.touch()
            print(f"   ✅ Created: {gitkeep_file}")
    
    # Create a sample config file
    print(f"\n⚙️  Creating sample configuration file...")
    
    config_content = """# ZeroDayGuard Configuration File

# Model Configuration
model:
  name: "MultiGraphGNN"
  num_node_features: 64
  hidden_channels: 128
  num_layers: 3
  num_classes: 2
  dropout: 0.3
  
# Training Configuration
training:
  learning_rate: 0.001
  batch_size: 32
  num_epochs: 100
  early_stopping_patience: 10
  validation_split: 0.15
  test_split: 0.15
  
# Data Configuration
data:
  dataset_name: "VDISC"
  raw_data_path: "data/raw/vdisc"
  processed_data_path: "data/processed"
  cache_graphs: true
  
# GNN Configuration
gnn:
  type: "GCN"  # Options: GCN, GAT, GraphSAGE
  aggregation: "mean"  # Options: mean, max, sum
  
# Anomaly Detection (Zero-Day)
anomaly_detection:
  enabled: true
  autoencoder_dim: 64
  contamination: 0.1
  
# API Configuration
api:
  host: "0.0.0.0"
  port: 5000
  debug: false
  cors_enabled: true
  
# Logging
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  log_file: "logs/zerodayguard.log"
  
# Experiment Tracking
experiment:
  use_wandb: false
  project_name: "zerodayguard"
  entity: "your-username"
"""
    
    config_file = Path("configs/config.yaml")
    if not config_file.exists():
        with open(config_file, 'w') as f:
            f.write(config_content)
        print(f"   ✅ Created: {config_file}")
    
    print(f"\n✅ Project structure setup complete!")
    print(f"\n📁 Your project structure:")
    print(f"""
    project/
    ├── src/              (source code)
    ├── data/             (datasets)
    ├── tests/            (unit & integration tests)
    ├── configs/          (configuration files)
    ├── scripts/          (utility scripts)
    ├── docs/             (documentation)
    ├── logs/             (log files)
    └── results/          (experiment results)
    """)

if __name__ == "__main__":
    create_directory_structure()
