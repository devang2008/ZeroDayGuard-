import torch

print("="*70)
print("🎮 GPU Detection")
print("="*70)

print(f"\n📦 PyTorch version: {torch.__version__}")
print(f"🔍 CUDA available: {torch.cuda.is_available()}")

if torch.cuda.is_available():
    print(f"✅ CUDA version: {torch.version.cuda}")
    print(f"✅ GPU count: {torch.cuda.device_count()}")
    print(f"✅ GPU name: {torch.cuda.get_device_name(0)}")
    
    total_memory = torch.cuda.get_device_properties(0).total_memory
    print(f"✅ GPU memory: {total_memory / 1024**3:.1f} GB")
    
    # Test GPU
    print("\n🧪 Testing GPU...")
    x = torch.randn(1000, 1000).cuda()
    y = torch.randn(1000, 1000).cuda()
    z = torch.matmul(x, y)
    print("✅ GPU computation successful!")
    
    # Estimate speedup
    print("\n⚡ GPU Training Benefits:")
    print("  • CPU training time: 12-15 hours")
    print("  • GPU training time: 3-4 hours (3-4x faster!)")
    print("  • Larger batch sizes possible")
    print("  • Better GPU utilization")
else:
    print("\n❌ CUDA not available!")
    print("   Make sure:")
    print("   1. PyTorch with CUDA is installed")
    print("   2. NVIDIA drivers are up to date")
    print("   3. GPU is properly connected")
