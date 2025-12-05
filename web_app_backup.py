"""
ZeroDayGuard Web Application
Beautiful UI for vulnerability scanning
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import sys
from pathlib import Path
import torch
import numpy as np
import re
import os
import zipfile
import tempfile
import json
from typing import Dict, List
from datetime import datetime
from werkzeug.utils import secure_filename

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.preprocessing.code_parser import CodeParser
from src.models.vulnerability_detector import create_model

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

ALLOWED_EXTENSIONS = {
    'c', 'cpp', 'h', 'hpp', 'cc', 'cxx',  # C/C++
    'py', 'pyw',  # Python
    'js', 'jsx', 'ts', 'tsx',  # JavaScript/TypeScript
    'java',  # Java
    'php', 'php3', 'php4', 'php5',  # PHP
    'go',  # Go
    'rs',  # Rust
    'cs',  # C#
    'rb',  # Ruby
    'pl',  # Perl
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class VulnerabilityScanner:
    def __init__(self, model_path: str = 'data/models/best_model.pth'):
        """Initialize the scanner"""
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Load checkpoint
        checkpoint = torch.load(model_path, map_location=self.device)
        
        # Create model
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
        
        # Parser
        self.code_parser = CodeParser()
    
    def scan_code(self, code: str, language: str = 'c') -> Dict:
        """Scan code and return detailed report"""
        try:
            # Parse features
            parsed_code = self.code_parser.parse(code)
            code_features = self.code_parser.extract_features(parsed_code)
            
            # Convert to tensors
            code_tensor = torch.FloatTensor(code_features).unsqueeze(0).to(self.device)
            graph_tensor = torch.zeros(1, 8).to(self.device)
            
            # Predict
            with torch.no_grad():
                logits = self.model(code_tensor, graph_tensor, graph_tensor, graph_tensor)
                probs = torch.softmax(logits, dim=1)
                vuln_prob = probs[0][1].item()
        except Exception as e:
            print(f"Error in model prediction: {e}")
            # Fallback to pattern-based detection only
            vuln_prob = 0.5
        
        # Detect patterns
        dangerous_funcs = self._detect_dangerous_functions(code)
        cwe_patterns = self._detect_cwe_patterns(code, code_features)
        
        # Risk assessment
        is_vulnerable = vuln_prob > 0.3
        if vuln_prob > 0.7 and len(cwe_patterns) > 2:
            risk_level = 'CRITICAL'
        elif vuln_prob > 0.5 or len(cwe_patterns) > 1:
            risk_level = 'HIGH'
        elif vuln_prob > 0.3 or len(cwe_patterns) > 0:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Recommendations
        recommendations = self._generate_recommendations(dangerous_funcs, cwe_patterns)
        
        return {
            'vulnerable': is_vulnerable,
            'confidence': round(vuln_prob * 100, 2),
            'risk_level': risk_level,
            'cwe_patterns': cwe_patterns,
            'dangerous_functions': dangerous_funcs,
            'recommendations': recommendations,
            'code_metrics': {
                'lines_of_code': int(len(parsed_code['lines'])),
                'functions': int(len(parsed_code['functions'])),
                'variables': int(len(parsed_code['variables'])),
                'complexity': float(code_features[20]) if len(code_features) > 20 else 0.0
            }
        }
    
    def _detect_dangerous_functions(self, code: str) -> List[Dict]:
        """Detect dangerous function calls with line numbers"""
        dangerous = [
            'strcpy', 'strcat', 'gets', 'sprintf', 'scanf',
            'system', 'exec', 'eval', 'popen', 'execve',
            'mysql_query', 'sqlite3_exec', 'PQexec',
            'innerHTML', 'document.write',
            'fopen', 'open'
        ]
        
        found = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for func in dangerous:
                if func + '(' in line or func + ' ' in line:
                    found.append({
                        'function': func,
                        'line': line_num,
                        'code': line.strip()
                    })
        
        return found
    
    def _detect_cwe_patterns(self, code: str, features: List[float]) -> List[str]:
        """Detect CWE vulnerability patterns"""
        patterns = []
        code_upper = code.upper()
        
        # CWE-119: Buffer Overflow
        if any(f in code for f in ['strcpy', 'strcat', 'gets', 'sprintf']):
            patterns.append('CWE-119: Buffer Overflow')
        
        # CWE-89: SQL Injection
        if 'SELECT' in code_upper or 'INSERT' in code_upper or 'UPDATE' in code_upper:
            if any(op in code for op in ['"+', '" +', '+ "', "'+", "' +", "+ '"]):
                patterns.append('CWE-89: SQL Injection')
        
        # CWE-79: XSS
        if any(x in code for x in ['innerHTML', 'document.write', 'eval(']):
            if 'sanitize' not in code.lower() and 'escape' not in code.lower():
                patterns.append('CWE-79: Cross-Site Scripting (XSS)')
        
        # CWE-78: Command Injection
        if any(f in code for f in ['system(', 'exec(', 'popen(', 'execve(']):
            patterns.append('CWE-78: OS Command Injection')
        
        # CWE-22: Path Traversal
        if 'fopen(' in code or 'open(' in code:
            if '../' in code or '..\\' in code:
                patterns.append('CWE-22: Path Traversal')
        
        # CWE-798: Hard-coded Credentials
        if any(x in code.lower() for x in ['password = "', 'passwd="', 'api_key = "', 'secret = "']):
            patterns.append('CWE-798: Hard-coded Credentials')
        
        # CWE-327: Weak Crypto
        if any(x in code_upper for x in ['MD5', 'SHA1', 'DES', 'RC4']):
            patterns.append('CWE-327: Weak Cryptographic Algorithm')
        
        # CWE-476: NULL Pointer
        if '->' in code and 'if' not in code[:code.find('->') if '->' in code else 0]:
            patterns.append('CWE-476: NULL Pointer Dereference')
        
        return patterns
    
    def _generate_recommendations(self, dangerous_funcs: List[Dict], cwe_patterns: List[Dict]) -> List[str]:
        """Generate security recommendations"""
        recs = []
        func_names = [f['function'] for f in dangerous_funcs]
        cwe_names = [p['cwe'] for p in cwe_patterns]
        cwe_str = str(cwe_names)
        
        if 'strcpy' in func_names:
            recs.append("Replace strcpy() with strncpy() and ensure null termination")
        if 'gets' in func_names:
            recs.append("Replace gets() with fgets() to prevent buffer overflow")
        if 'CWE-89' in cwe_str:
            recs.append("Use prepared statements/parameterized queries instead of string concatenation")
        if 'CWE-79' in cwe_str:
            recs.append("Sanitize all user input and use textContent instead of innerHTML")
        if 'CWE-78' in cwe_str:
            recs.append("Avoid system(), exec(), eval() - use safer alternatives with input validation")
        if 'CWE-22' in cwe_str:
            recs.append("Validate and sanitize all file paths, use realpath() to resolve symbolic links")
        if 'CWE-798' in cwe_str:
            recs.append("Move credentials to environment variables or secure vaults")
        if 'CWE-327' in cwe_str:
            recs.append("Replace weak algorithms: Use SHA-256/SHA-3, bcrypt/Argon2, AES-256")
        if 'CWE-476' in cwe_str:
            recs.append("Add NULL pointer checks before dereferencing")
        
        if not recs:
            recs.append("Code appears safe, but manual security review recommended")
        
        return recs

# Initialize scanner
scanner = VulnerabilityScanner()

@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    """Scan code endpoint"""
    try:
        data = request.get_json()
        code = data.get('code', '')
        language = data.get('language', 'c')
        
        if not code:
            return jsonify({'error': 'No code provided'}), 400
        
        print(f"\n=== Scanning code ({len(code)} chars, language: {language}) ===")
        
        # Scan code
        result = scanner.scan_code(code, language)
        result['timestamp'] = datetime.now().isoformat()
        
        print(f"Result: {result['vulnerable']}, Confidence: {result['confidence']}%")
        
        return jsonify(result)
    
    except Exception as e:
        print(f"ERROR in /api/scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/api/scan-project', methods=['POST'])
def scan_project():
    """Scan entire project folder"""
    try:
        if 'project' not in request.files:
            return jsonify({'error': 'No project file uploaded'}), 400
        
        file = request.files['project']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.zip'):
            return jsonify({'error': 'Please upload a ZIP file'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        print(f"\n=== Scanning project: {filename} ===")
        
        # Extract and scan
        extract_dir = os.path.join(app.config['UPLOAD_FOLDER'], f'extracted_{os.getpid()}')
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Scan all files
            results = scan_directory(extract_dir)
            
            # Generate report
            report = generate_project_report(results, filename)
            
            return jsonify(report)
        
        finally:
            # Cleanup
            try:
                os.remove(filepath)
                import shutil
                shutil.rmtree(extract_dir, ignore_errors=True)
            except:
                pass
    
    except Exception as e:
        print(f"ERROR in /api/scan-project: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Project scan failed: {str(e)}'}), 500

def scan_directory(directory):
    """Recursively scan all files in directory"""
    results = {
        'total_files': 0,
        'scanned_files': 0,
        'vulnerable_files': 0,
        'safe_files': 0,
        'files': [],
        'vulnerabilities_by_cwe': {},
        'critical_files': [],
        'high_risk_files': [],
        'medium_risk_files': []
    }
    
    for root, dirs, files in os.walk(directory):
        # Skip common ignore directories
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', 'env', '.venv'}]
        
        for file in files:
            if not allowed_file(file):
                continue
            
            results['total_files'] += 1
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, directory)
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                # Scan the file
                scan_result = scanner.scan_code(code)
                
                file_result = {
                    'path': relative_path,
                    'name': file,
                    'vulnerable': scan_result['vulnerable'],
                    'confidence': scan_result['confidence'],
                    'risk_level': scan_result['risk_level'],
                    'cwe_patterns': scan_result['cwe_patterns'],
                    'dangerous_functions': scan_result['dangerous_functions'],
                    'lines_of_code': scan_result['code_metrics']['lines_of_code']
                }
                
                results['files'].append(file_result)
                results['scanned_files'] += 1
                
                if scan_result['vulnerable']:
                    results['vulnerable_files'] += 1
                    
                    # Categorize by risk
                    if scan_result['risk_level'] == 'CRITICAL':
                        results['critical_files'].append(file_result)
                    elif scan_result['risk_level'] == 'HIGH':
                        results['high_risk_files'].append(file_result)
                    elif scan_result['risk_level'] == 'MEDIUM':
                        results['medium_risk_files'].append(file_result)
                    
                    # Count CWE patterns
                    for cwe in scan_result['cwe_patterns']:
                        if cwe not in results['vulnerabilities_by_cwe']:
                            results['vulnerabilities_by_cwe'][cwe] = []
                        results['vulnerabilities_by_cwe'][cwe].append(relative_path)
                else:
                    results['safe_files'] += 1
                
                print(f"  Scanned: {relative_path} - {scan_result['risk_level']}")
            
            except Exception as e:
                print(f"  Error scanning {relative_path}: {e}")
                continue
    
    return results

def generate_project_report(results, project_name):
    """Generate comprehensive project report"""
    total = results['scanned_files']
    vuln = results['vulnerable_files']
    safe = results['safe_files']
    
    # Calculate security score (0-100)
    if total > 0:
        security_score = int((safe / total) * 100)
    else:
        security_score = 0
    
    # Determine overall risk
    critical_count = len(results['critical_files'])
    high_count = len(results['high_risk_files'])
    
    if critical_count > 0:
        overall_risk = 'CRITICAL'
    elif high_count > 3:
        overall_risk = 'HIGH'
    elif vuln > total * 0.3:
        overall_risk = 'MEDIUM'
    else:
        overall_risk = 'LOW'
    
    # Top vulnerabilities
    top_cwes = sorted(
        results['vulnerabilities_by_cwe'].items(),
        key=lambda x: len(x[1]),
        reverse=True
    )[:5]
    
    report = {
        'project_name': project_name,
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_files': results['total_files'],
            'scanned_files': results['scanned_files'],
            'vulnerable_files': vuln,
            'safe_files': safe,
            'security_score': security_score,
            'overall_risk': overall_risk
        },
        'risk_breakdown': {
            'critical': critical_count,
            'high': high_count,
            'medium': len(results['medium_risk_files']),
            'low': safe
        },
        'top_vulnerabilities': [
            {
                'cwe': cwe,
                'count': len(files),
                'affected_files': files[:3]  # Top 3 files
            }
            for cwe, files in top_cwes
        ],
        'critical_files': results['critical_files'][:10],
        'high_risk_files': results['high_risk_files'][:10],
        'all_files': results['files']
    }
    
    return report

@app.route('/api/examples')
def get_examples():
    """Get example vulnerable code"""
    examples = {
        'sql_injection': {
            'name': 'SQL Injection',
            'cwe': 'CWE-89',
            'code': '''// Vulnerable to SQL Injection
void login_user(char* username, char* password) {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE username='%s' AND password='%s'", 
            username, password);
    // Attacker input: admin' OR '1'='1
    mysql_query(conn, query);
}'''
        },
        'buffer_overflow': {
            'name': 'Buffer Overflow',
            'cwe': 'CWE-119',
            'code': '''// Vulnerable to Buffer Overflow
void copy_data(char* user_input) {
    char buffer[100];
    strcpy(buffer, user_input);  // No bounds checking!
    printf("Data: %s\\n", buffer);
}'''
        },
        'command_injection': {
            'name': 'Command Injection',
            'cwe': 'CWE-78',
            'code': '''// Vulnerable to Command Injection
void ping_host(char* ip_address) {
    char command[200];
    sprintf(command, "ping %s", ip_address);
    system(command);  // Dangerous!
    // Attacker: "8.8.8.8; rm -rf /"
}'''
        },
        'xss': {
            'name': 'Cross-Site Scripting',
            'cwe': 'CWE-79',
            'code': '''// Vulnerable to XSS
function displayComment(comment) {
    document.getElementById('output').innerHTML = comment;
    // Attacker: "<script>alert('XSS')</script>"
}'''
        }
    }
    
    return jsonify(examples)

if __name__ == '__main__':
    print("🔐 Starting ZeroDayGuard Web Server...")
    print("📍 Open: http://localhost:5000")
    print("✅ Scanner loaded and ready!")
    app.run(debug=True, host='0.0.0.0', port=5000)
