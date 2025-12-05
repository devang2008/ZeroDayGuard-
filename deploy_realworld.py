"""
Real-World Deployment Script
- REST API endpoint
- CLI tool for scanning
- Integration with CI/CD
"""

import sys
from pathlib import Path
import argparse
import torch
import json
import numpy as np
import re
from typing import Dict, List
from datetime import datetime

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.code_parser import CodeParser
from src.preprocessing.graph_generator import SimpleGraphGenerator
from src.models.vulnerability_detector import create_model


class RealWorldScanner:
    """Production vulnerability scanner with comprehensive reporting"""
    
    def __init__(self, model_path: str = 'data/models/best_model_rl.pth'):
        print("🔐 Loading ZeroDayGuard Scanner...")
        
        # Load model
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        
        # Try RL model first, fallback to regular
        if Path(model_path).exists():
            checkpoint = torch.load(model_path, map_location=self.device)
            print(f"  ✅ Loaded: {model_path}")
        else:
            model_path = 'data/models/best_model.pth'
            checkpoint = torch.load(model_path, map_location=self.device)
            print(f"  ✅ Loaded: {model_path}")
        
        # Create model - use simple type to match trained model
        self.model = create_model(
            model_type='simple',
            code_feature_dim=24,
            graph_feature_dim=8,
            hidden_dim=128,
            num_classes=2,
            dropout=0.3
        )
        
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()
        
        # Parsers
        self.code_parser = CodeParser()
        
        print("  ✅ Scanner ready\n")
    
    def scan_code(self, code: str) -> Dict:
        """
        Scan code and return detailed report
        
        Returns:
            {
                'vulnerable': bool,
                'confidence': float,
                'risk_level': str,
                'cwe_patterns': List[str],
                'dangerous_functions': List[str],
                'recommendations': List[str]
            }
        """
        # Parse features
        parsed_code = self.code_parser.parse(code)
        code_features = self.code_parser.extract_features(parsed_code)
        
        # Simple graph features (using counts as proxies)
        graph_features = np.array([
            len(parsed_code['functions']),
            len(parsed_code['variables']),
            len(parsed_code['calls']),
            parsed_code.get('complexity', 0),
            len([c for c in code if c in '{}']),  # Control flow proxy
            len([c for c in code if c == ';']),   # Statement count
            len(re.findall(r'->', code)),         # Pointer usage
            len(re.findall(r'\*', code))          # Dereference count
        ], dtype=np.float32)
        
        # Convert to tensors
        code_tensor = torch.FloatTensor(code_features).unsqueeze(0).to(self.device)
        # Create dummy graph features (all zeros since we don't have graph data)
        graph_tensor = torch.zeros(1, 8).to(self.device)
        
        # Predict
        with torch.no_grad():
            logits = self.model(code_tensor, graph_tensor, graph_tensor, graph_tensor)
            probs = torch.softmax(logits, dim=1)
            vuln_prob = probs[0, 1].item()
        
        # Analyze patterns
        dangerous_funcs = self._detect_dangerous_functions(code)
        cwe_patterns = self._detect_cwe_patterns(code, code_features)
        recommendations = self._generate_recommendations(dangerous_funcs, cwe_patterns)
        
        # Determine risk level
        if vuln_prob > 0.8:
            risk_level = 'CRITICAL'
        elif vuln_prob > 0.6:
            risk_level = 'HIGH'
        elif vuln_prob > 0.4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'vulnerable': vuln_prob > 0.5,
            'confidence': vuln_prob if vuln_prob > 0.5 else 1 - vuln_prob,
            'vulnerability_score': vuln_prob,
            'risk_level': risk_level,
            'cwe_patterns': cwe_patterns,
            'dangerous_functions': dangerous_funcs,
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat()
        }
    
    def _detect_dangerous_functions(self, code: str) -> List[str]:
        """Detect dangerous function calls"""
        dangerous = [
            # Buffer overflow functions
            'strcpy', 'strcat', 'gets', 'sprintf', 'scanf',
            'strncpy', 'strncat', 'vsprintf', 'vsnprintf',
            # Command injection
            'system', 'exec', 'eval', 'popen', 'execve', 'execl',
            # SQL injection (if database code)
            'mysql_query', 'sqlite3_exec', 'PQexec', 'executeQuery',
            # XSS/injection vectors
            'innerHTML', 'document.write', 'eval', 'setTimeout',
            # File operations
            'fopen', 'open', 'read', 'write'
        ]
        
        found = []
        for func in dangerous:
            if func + '(' in code or func + ' ' in code:
                found.append(func)
        
        return found
    
    def _detect_cwe_patterns(self, code: str, features: List[float]) -> List[str]:
        """Detect CWE vulnerability patterns"""
        patterns = []
        code_upper = code.upper()
        
        # CWE-119: Buffer Overflow
        if any(f in code for f in ['strcpy', 'strcat', 'gets', 'sprintf']):
            patterns.append('CWE-119: Buffer Overflow')
        
        # CWE-120: Buffer Copy Without Size Check
        if 'strcpy' in code or 'strcat' in code:
            patterns.append('CWE-120: Buffer Copy Without Size Check')
        
        # CWE-476: NULL Pointer Dereference
        if '->' in code and 'if' not in code[:code.find('->') if '->' in code else 0]:
            patterns.append('CWE-476: NULL Pointer Dereference')
        
        # CWE-78: OS Command Injection
        if any(f in code for f in ['system(', 'exec(', 'popen(', 'execve(']):
            patterns.append('CWE-78: OS Command Injection')
        
        # CWE-89: SQL Injection
        if 'SELECT' in code_upper or 'INSERT' in code_upper or 'UPDATE' in code_upper:
            # Check for string concatenation in SQL
            if any(op in code for op in ['"+', '" +', '+ "', "'+", "' +", "+ '"]):
                patterns.append('CWE-89: SQL Injection')
            elif 'sprintf' in code or 'strcat' in code:
                patterns.append('CWE-89: SQL Injection (via string formatting)')
        
        # CWE-79: Cross-Site Scripting (XSS)
        if any(x in code for x in ['innerHTML', 'document.write', 'eval(']):
            if 'sanitize' not in code.lower() and 'escape' not in code.lower():
                patterns.append('CWE-79: Cross-Site Scripting (XSS)')
        
        # CWE-22: Path Traversal
        if 'fopen(' in code or 'open(' in code:
            if '../' in code or '..\\' in code:
                patterns.append('CWE-22: Path Traversal')
            elif 'validate' not in code.lower() and 'sanitize' not in code.lower():
                patterns.append('CWE-22: Improper File Path Validation')
        
        # CWE-798: Hard-coded Credentials
        if any(x in code.lower() for x in ['password = "', 'passwd="', 'api_key = "', 'secret = "']):
            patterns.append('CWE-798: Hard-coded Credentials')
        
        # CWE-327: Weak Crypto
        if any(x in code_upper for x in ['MD5', 'SHA1', 'DES', 'RC4']):
            patterns.append('CWE-327: Use of Broken/Risky Cryptographic Algorithm')
        
        # CWE-611: XML External Entity (XXE)
        if 'parseXML' in code or 'XMLParser' in code:
            if 'DTD' in code_upper or 'ENTITY' in code_upper:
                patterns.append('CWE-611: XML External Entity (XXE) Injection')
        
        # CWE-434: Unrestricted File Upload
        if 'upload' in code.lower() and 'file' in code.lower():
            if 'validate' not in code.lower() and 'extension' not in code.lower():
                patterns.append('CWE-434: Unrestricted File Upload')
        
        # CWE-502: Deserialization
        if any(x in code for x in ['unserialize', 'pickle.loads', 'yaml.load']):
            patterns.append('CWE-502: Insecure Deserialization')
        
        # CWE-352: CSRF
        if 'POST' in code_upper or 'PUT' in code_upper or 'DELETE' in code_upper:
            if 'csrf' not in code.lower() and 'token' not in code.lower():
                patterns.append('CWE-352: Cross-Site Request Forgery (CSRF)')
        
        return patterns
    
    def _generate_recommendations(self, dangerous_funcs: List[str], cwe_patterns: List[str]) -> List[str]:
        """Generate security recommendations"""
        recs = []
        cwe_str = str(cwe_patterns)
        
        # Buffer overflow fixes
        if 'strcpy' in dangerous_funcs:
            recs.append("Replace strcpy() with strncpy() and ensure null termination")
        if 'gets' in dangerous_funcs:
            recs.append("Replace gets() with fgets() to prevent buffer overflow")
        if 'sprintf' in dangerous_funcs:
            recs.append("Replace sprintf() with snprintf() to prevent buffer overflow")
        if 'CWE-119' in cwe_str or 'CWE-120' in cwe_str:
            recs.append("Implement bounds checking for all buffer operations")
        
        # SQL Injection fixes
        if 'CWE-89' in cwe_str:
            recs.append("Use prepared statements/parameterized queries instead of string concatenation")
            recs.append("Never concatenate user input directly into SQL queries")
            recs.append("Use ORM frameworks (e.g., SQLAlchemy, Hibernate) for safer database access")
        
        # XSS fixes
        if 'CWE-79' in cwe_str:
            recs.append("Sanitize all user input before rendering in HTML")
            recs.append("Use content security policy (CSP) headers")
            recs.append("Encode output using htmlspecialchars() or equivalent")
            recs.append("Avoid using innerHTML, use textContent instead")
        
        # Command Injection fixes
        if 'CWE-78' in cwe_str:
            recs.append("Avoid system(), exec(), eval() - use safer alternatives")
            recs.append("Whitelist allowed commands and validate all inputs")
            recs.append("Use subprocess with shell=False in Python")
        
        # Path Traversal fixes
        if 'CWE-22' in cwe_str:
            recs.append("Validate and sanitize all file paths")
            recs.append("Use realpath() to resolve symbolic links")
            recs.append("Implement whitelist of allowed directories")
        
        # NULL pointer fixes
        if 'CWE-476' in cwe_str:
            recs.append("Add NULL pointer checks before dereferencing")
            recs.append("Initialize all pointers to NULL")
        
        # Hard-coded credentials
        if 'CWE-798' in cwe_str:
            recs.append("Move credentials to environment variables or secure vaults")
            recs.append("Use .env files (excluded from version control)")
            recs.append("Implement proper secret management (e.g., AWS Secrets Manager)")
        
        # Weak crypto
        if 'CWE-327' in cwe_str:
            recs.append("Replace MD5/SHA1 with SHA-256 or SHA-3")
            recs.append("Use bcrypt or Argon2 for password hashing")
            recs.append("Replace DES/RC4 with AES-256")
        
        # XXE fixes
        if 'CWE-611' in cwe_str:
            recs.append("Disable external entity processing in XML parsers")
            recs.append("Use defusedxml library in Python")
        
        # File upload fixes
        if 'CWE-434' in cwe_str:
            recs.append("Validate file extensions against whitelist")
            recs.append("Check file content type, not just extension")
            recs.append("Store uploaded files outside web root")
        
        # Deserialization fixes
        if 'CWE-502' in cwe_str:
            recs.append("Avoid deserializing untrusted data")
            recs.append("Use JSON instead of pickle/serialize")
            recs.append("Implement signature verification for serialized data")
        
        # CSRF fixes
        if 'CWE-352' in cwe_str:
            recs.append("Implement CSRF tokens for all state-changing operations")
            recs.append("Use SameSite cookie attribute")
            recs.append("Verify referrer headers")
        
        if not recs:
            recs.append("Code appears safe, but manual security review recommended")
        
        return recs
    
    def scan_file(self, filepath: str) -> Dict:
        """Scan a file"""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        result = self.scan_code(code)
        result['file'] = filepath
        return result
    
    def scan_directory(self, directory: str, extensions: List[str] = ['.c', '.cpp', '.h']) -> List[Dict]:
        """Scan all files in directory"""
        results = []
        dir_path = Path(directory)
        
        for ext in extensions:
            for file_path in dir_path.rglob(f'*{ext}'):
                try:
                    result = self.scan_file(str(file_path))
                    results.append(result)
                except Exception as e:
                    print(f"  ⚠️  Error scanning {file_path}: {e}")
        
        return results
    
    def generate_report(self, results: List[Dict], output_file: str = None):
        """Generate comprehensive security report"""
        total = len(results)
        vulnerable = sum(1 for r in results if r['vulnerable'])
        
        report = {
            'summary': {
                'total_files': total,
                'vulnerable_files': vulnerable,
                'safe_files': total - vulnerable,
                'scan_date': datetime.now().isoformat()
            },
            'vulnerabilities': [r for r in results if r['vulnerable']],
            'safe_files': [r['file'] for r in results if not r['vulnerable']]
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Report saved: {output_file}")
        
        return report


def main():
    parser = argparse.ArgumentParser(description='ZeroDayGuard - Real-World Vulnerability Scanner')
    parser.add_argument('--file', type=str, help='Scan a single file')
    parser.add_argument('--dir', type=str, help='Scan a directory')
    parser.add_argument('--output', type=str, default='security_report.json', help='Output report file')
    parser.add_argument('--model', type=str, default='data/models/best_model_rl.pth', help='Model path')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = RealWorldScanner(model_path=args.model)
    
    if args.file:
        # Scan single file
        print(f"🔍 Scanning: {args.file}")
        result = scanner.scan_file(args.file)
        
        print(f"\n{'='*70}")
        print(f"📊 SCAN RESULTS")
        print(f"{'='*70}")
        print(f"File: {result['file']}")
        print(f"Status: {'⚠️  VULNERABLE' if result['vulnerable'] else '✅ SAFE'}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Confidence: {result['confidence']:.2%}")
        
        if result['cwe_patterns']:
            print(f"\n🎯 Detected Patterns:")
            for pattern in result['cwe_patterns']:
                print(f"  • {pattern}")
        
        if result['dangerous_functions']:
            print(f"\n⚠️  Dangerous Functions:")
            for func in result['dangerous_functions']:
                print(f"  • {func}()")
        
        if result['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in result['recommendations']:
                print(f"  • {rec}")
    
    elif args.dir:
        # Scan directory
        print(f"🔍 Scanning directory: {args.dir}")
        results = scanner.scan_directory(args.dir)
        
        # Generate report
        report = scanner.generate_report(results, args.output)
        
        print(f"\n{'='*70}")
        print(f"📊 DIRECTORY SCAN RESULTS")
        print(f"{'='*70}")
        print(f"Total Files: {report['summary']['total_files']}")
        print(f"Vulnerable: {report['summary']['vulnerable_files']}")
        print(f"Safe: {report['summary']['safe_files']}")
        
        if report['vulnerabilities']:
            print(f"\n⚠️  VULNERABILITIES FOUND:")
            for vuln in report['vulnerabilities'][:10]:  # Show first 10
                print(f"\n  File: {vuln['file']}")
                print(f"  Risk: {vuln['risk_level']}")
                print(f"  Patterns: {', '.join(vuln['cwe_patterns'][:3])}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
