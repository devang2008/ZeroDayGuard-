"""
Real-World Vulnerability Prediction Script
Use trained model to scan actual C/C++ code for vulnerabilities
"""

import sys
from pathlib import Path
import torch
import numpy as np
from typing import Dict, List, Tuple

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.code_parser import CodeParser
from src.preprocessing.graph_generator import SimpleGraphGenerator
from src.models.vulnerability_detector import create_model


class VulnerabilityScanner:
    """
    Production-ready vulnerability scanner
    Scan real C/C++ code and get vulnerability predictions
    """
    
    def __init__(self, model_path: str = 'data/models/best_model.pth'):
        """Initialize scanner with trained model"""
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Load model
        print(f"Loading model from {model_path}...")
        checkpoint = torch.load(model_path, map_location=self.device)
        
        # Create model with same architecture
        self.model = create_model(
            model_type='simple',
            code_feature_dim=24,
            graph_feature_dim=8,
            hidden_dim=128,
            dropout=0.3
        )
        
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()
        
        # Initialize feature extractors
        self.parser = CodeParser()
        self.graph_gen = SimpleGraphGenerator()
        
        print(f"✅ Model loaded successfully!")
        print(f"   Best F1 Score: {checkpoint.get('best_val_f1', 'N/A'):.4f}")
        print(f"   Device: {self.device}")
    
    def scan_code(self, source_code: str) -> Dict:
        """
        Scan a single code snippet for vulnerabilities
        
        Args:
            source_code: C/C++ source code string
            
        Returns:
            Dictionary with prediction results
        """
        # Extract features
        parsed = self.parser.parse(source_code)
        code_features = self.parser.extract_features(parsed)
        
        # Generate graphs
        graphs = self.graph_gen.generate_all_graphs(source_code)
        ast_features = self.graph_gen.get_graph_features(graphs['ast'])
        cfg_features = self.graph_gen.get_graph_features(graphs['cfg'])
        pdg_features = self.graph_gen.get_graph_features(graphs['pdg'])
        
        # Convert to tensors
        code_features = torch.FloatTensor(code_features).unsqueeze(0).to(self.device)
        ast_features = torch.FloatTensor(ast_features).unsqueeze(0).to(self.device)
        cfg_features = torch.FloatTensor(cfg_features).unsqueeze(0).to(self.device)
        pdg_features = torch.FloatTensor(pdg_features).unsqueeze(0).to(self.device)
        
        # Predict
        with torch.no_grad():
            logits = self.model(code_features, ast_features, cfg_features, pdg_features)
            probabilities = torch.softmax(logits, dim=1)
            prediction = torch.argmax(logits, dim=1).item()
        
        # Get confidence scores
        safe_prob = probabilities[0][0].item()
        vuln_prob = probabilities[0][1].item()
        
        return {
            'vulnerable': bool(prediction),
            'confidence': vuln_prob if prediction else safe_prob,
            'safe_probability': safe_prob,
            'vulnerable_probability': vuln_prob,
            'risk_level': self._get_risk_level(vuln_prob),
            'code_metrics': {
                'lines_of_code': parsed['lines'].__len__(),
                'functions': len(parsed['functions']),
                'dangerous_calls': sum(parsed['keywords'].get(func, 0) 
                                      for func in ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf'])
            }
        }
    
    def _get_risk_level(self, vuln_prob: float) -> str:
        """Convert probability to risk level"""
        if vuln_prob < 0.3:
            return "LOW"
        elif vuln_prob < 0.6:
            return "MEDIUM"
        elif vuln_prob < 0.8:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a C/C++ source file"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        result = self.scan_code(source_code)
        result['file'] = file_path
        return result
    
    def scan_directory(self, directory: str, extensions: List[str] = ['.c', '.cpp', '.h']) -> List[Dict]:
        """Scan all C/C++ files in a directory"""
        results = []
        dir_path = Path(directory)
        
        for ext in extensions:
            for file_path in dir_path.rglob(f'*{ext}'):
                try:
                    result = self.scan_file(str(file_path))
                    results.append(result)
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")
        
        return results
    
    def print_report(self, result: Dict):
        """Print formatted vulnerability report"""
        print("\n" + "="*60)
        if 'file' in result:
            print(f"📄 File: {result['file']}")
        
        if result['vulnerable']:
            print(f"⚠️  VULNERABILITY DETECTED!")
            print(f"   Risk Level: {result['risk_level']}")
            print(f"   Confidence: {result['vulnerable_probability']:.1%}")
        else:
            print(f"✅ CODE APPEARS SAFE")
            print(f"   Confidence: {result['safe_probability']:.1%}")
        
        print(f"\n📊 Code Metrics:")
        print(f"   Lines of Code: {result['code_metrics']['lines_of_code']}")
        print(f"   Functions: {result['code_metrics']['functions']}")
        print(f"   Dangerous Function Calls: {result['code_metrics']['dangerous_calls']}")
        
        print(f"\n🎯 Probabilities:")
        print(f"   Safe: {result['safe_probability']:.1%}")
        print(f"   Vulnerable: {result['vulnerable_probability']:.1%}")
        print("="*60)


def main():
    """Demo: Scan example code for SECURITY VULNERABILITIES (exploits, not just bugs)"""
    
    print("="*70)
    print("🔐 ZeroDayGuard - Cybersecurity Vulnerability Scanner")
    print("Detects Exploitable Weaknesses: Buffer Overflows, Injection Attacks, RCE")
    print("="*70)
    
    # Initialize scanner
    scanner = VulnerabilityScanner('data/models/best_model.pth')
    
    # Example 1: Vulnerable code (buffer overflow)
    vulnerable_code = """
    #include <stdio.h>
    #include <string.h>
    
    void copy_user_input(char *user_data) {
        char buffer[100];
        strcpy(buffer, user_data);  // UNSAFE! No bounds checking
        printf("Data: %s\\n", buffer);
    }
    
    int main() {
        char input[500];
        gets(input);  // UNSAFE! No bounds checking
        copy_user_input(input);
        return 0;
    }
    """
    
    print("\n\n🔍 SCANNING EXAMPLE 1: Vulnerable Code")
    print("-" * 60)
    print(vulnerable_code)
    result1 = scanner.scan_code(vulnerable_code)
    scanner.print_report(result1)
    
    # Example 2: Safe code (proper bounds checking)
    safe_code = """
    #include <stdio.h>
    #include <string.h>
    
    #define BUFFER_SIZE 100
    
    int safe_copy(const char *src, char *dest, size_t dest_size) {
        if (strlen(src) >= dest_size) {
            return -1;  // Error: source too large
        }
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\\0';
        return 0;
    }
    
    int main() {
        char buffer[BUFFER_SIZE];
        char input[BUFFER_SIZE];
        
        if (fgets(input, sizeof(input), stdin) != NULL) {
            if (safe_copy(input, buffer, sizeof(buffer)) == 0) {
                printf("Data: %s\\n", buffer);
            }
        }
        return 0;
    }
    """
    
    print("\n\n🔍 SCANNING EXAMPLE 2: Safe Code")
    print("-" * 60)
    print(safe_code)
    result2 = scanner.scan_code(safe_code)
    scanner.print_report(result2)
    
    # Example 3: Memory leak vulnerability
    memory_leak_code = """
    #include <stdlib.h>
    
    void process_data(int size) {
        char *data = (char*)malloc(size);
        // Missing free(data)!
        
        if (size > 1000) {
            return;  // Early return without freeing
        }
        
        // Do processing...
    }
    
    int main() {
        for (int i = 0; i < 1000; i++) {
            process_data(100);  // Memory leak!
        }
        return 0;
    }
    """
    
    print("\n\n🔍 SCANNING EXAMPLE 3: Memory Leak")
    print("-" * 60)
    print(memory_leak_code)
    result3 = scanner.scan_code(memory_leak_code)
    scanner.print_report(result3)
    
    # Summary
    print("\n\n" + "="*60)
    print("📊 SCAN SUMMARY")
    print("="*60)
    print(f"Total Scans: 3")
    print(f"Vulnerabilities Found: {sum([result1['vulnerable'], result2['vulnerable'], result3['vulnerable']])}")
    print(f"Safe Code: {sum([not result1['vulnerable'], not result2['vulnerable'], not result3['vulnerable']])}")
    print("="*60)
    
    print("\n💡 USAGE EXAMPLES:")
    print("   1. Scan single file:")
    print("      scanner.scan_file('mycode.c')")
    print("\n   2. Scan directory:")
    print("      scanner.scan_directory('src/', ['.c', '.cpp'])")
    print("\n   3. Scan code string:")
    print("      scanner.scan_code(code_string)")


if __name__ == '__main__':
    main()
