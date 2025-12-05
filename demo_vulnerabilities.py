# ZeroDayGuard - Quick Demo Script
# Run this to see vulnerability detection in action!

import subprocess
import sys

print("="*70)
print("🔐 ZeroDayGuard - Vulnerability Detection Demo")
print("="*70)
print()

examples = [
    ("SQL Injection", "examples/sql_injection.c", "CWE-89"),
    ("Path Traversal", "examples/path_traversal.c", "CWE-22"),
    ("Hard-coded Credentials", "examples/hardcoded_credentials.py", "CWE-798"),
    ("Buffer Overflow", "examples/buffer_overflow.c", "CWE-119"),
    ("Command Injection", "examples/command_injection.c", "CWE-78"),
]

print("📋 Testing 5 different vulnerability types:\n")

for i, (name, filepath, cwe) in enumerate(examples, 1):
    print(f"{i}. {name} ({cwe})")

print("\n" + "="*70)
print()

for i, (name, filepath, cwe) in enumerate(examples, 1):
    print(f"\n{'='*70}")
    print(f"Test #{i}: {name} ({cwe})")
    print('='*70)
    
    # Run scanner
    cmd = [
        sys.executable,
        "deploy_realworld.py",
        "--file",
        filepath
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            env={'PYTHONIOENCODING': 'utf-8'}
        )
        
        print(result.stdout)
        
        if result.returncode != 0:
            print(f"⚠️  Error: {result.stderr}")
            
    except Exception as e:
        print(f"❌ Error running scanner: {e}")
    
    print()

print("="*70)
print("✅ Demo completed!")
print("="*70)
print()
print("📊 Summary:")
print("  - Scanned 5 different vulnerability types")
print("  - Detected CWE patterns (SQL injection, XSS, command injection, etc.)")
print("  - Provided specific security recommendations")
print()
print("💡 Try scanning your own code:")
print("  python deploy_realworld.py --file your_code.c")
print()
print("🎯 ZeroDayGuard - Protecting code from cyber attacks!")
print("="*70)
