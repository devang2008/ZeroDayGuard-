"""
ZeroDayGuard Web Application - Enhanced with Auto-Fix Feature
Beautiful UI for vulnerability scanning with exact line numbers and automated fixes
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
import io
from typing import Dict, List, Tuple
from datetime import datetime
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import google.generativeai as genai

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load secure configuration
load_dotenv()

from src.preprocessing.code_parser import CodeParser
from src.models.vulnerability_detector import create_model

# Configure AI backend
api_key = os.getenv('API_KEY')
if api_key:
    genai.configure(api_key=api_key)

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
    
    def scan_code(self, code: str, language: str = 'c', filename: str = 'code') -> Dict:
        """Scan code and return detailed report with line numbers"""
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
        
        # Detect patterns WITH LOCATIONS
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
        
        # Calculate security confidence score (inverse of vulnerability)
        # Fewer vulnerabilities = Higher confidence score
        # This makes the score increase when you fix vulnerabilities
        security_confidence = round((1 - vuln_prob) * 100, 2)
        
        return {
            'vulnerable': is_vulnerable,
            'confidence': security_confidence,
            'risk_level': risk_level,
            'cwe_patterns': cwe_patterns,  # Now includes line numbers and code
            'dangerous_functions': dangerous_funcs,  # Now includes line numbers and code
            'recommendations': recommendations,
            'code_metrics': {
                'lines_of_code': int(len(parsed_code['lines'])),
                'functions': int(len(parsed_code['functions'])),
                'variables': int(len(parsed_code['variables'])),
                'complexity': float(code_features[20]) if len(code_features) > 20 else 0.0
            },
            'filename': filename
        }
    
    def _detect_dangerous_functions(self, code: str) -> List[Dict]:
        """Detect dangerous function calls WITH LINE NUMBERS AND CODE"""
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
                if func + '(' in line or (func + ' ' in line and '(' in line):
                    found.append({
                        'function': func,
                        'line': line_num,
                        'code': line.strip(),
                        'severity': 'HIGH' if func in ['strcpy', 'gets', 'system', 'exec', 'eval'] else 'MEDIUM'
                    })
        
        return found
    
    def _detect_cwe_patterns(self, code: str, features: List[float]) -> List[Dict]:
        """Detect CWE vulnerability patterns WITH EXACT LOCATIONS"""
        patterns = []
        lines = code.split('\n')
        
        # CWE-119: Buffer Overflow
        for line_num, line in enumerate(lines, 1):
            if any(f in line for f in ['strcpy', 'strcat', 'gets', 'sprintf']):
                patterns.append({
                    'cwe': 'CWE-119: Buffer Overflow',
                    'line': line_num,
                    'code': line.strip(),
                    'severity': 'CRITICAL',
                    'description': 'Unsafe function can cause buffer overflow'
                })
        
        # CWE-89: SQL Injection
        for line_num, line in enumerate(lines, 1):
            line_upper = line.upper()
            if 'SELECT' in line_upper or 'INSERT' in line_upper or 'UPDATE' in line_upper or 'DELETE' in line_upper:
                if any(op in line for op in ['"+ ', '" +', '+ "', "'+ ", "' +", "+ '", '"+', "'+", 'query = ']):
                    patterns.append({
                        'cwe': 'CWE-89: SQL Injection',
                        'line': line_num,
                        'code': line.strip(),
                        'severity': 'CRITICAL',
                        'description': 'SQL query built with string concatenation'
                    })
        
        # CWE-79: XSS
        for line_num, line in enumerate(lines, 1):
            if any(x in line for x in ['innerHTML', 'document.write', 'eval(']):
                if 'sanitize' not in line.lower() and 'escape' not in line.lower():
                    patterns.append({
                        'cwe': 'CWE-79: Cross-Site Scripting (XSS)',
                        'line': line_num,
                        'code': line.strip(),
                        'severity': 'HIGH',
                        'description': 'Unsanitized user input used in DOM manipulation'
                    })
        
        # CWE-78: Command Injection
        for line_num, line in enumerate(lines, 1):
            if any(f in line for f in ['system(', 'exec(', 'popen(', 'execve(', 'shell_exec(', 'passthru(']):
                patterns.append({
                    'cwe': 'CWE-78: OS Command Injection',
                    'line': line_num,
                    'code': line.strip(),
                    'severity': 'CRITICAL',
                    'description': 'Direct execution of system commands'
                })
        
        # CWE-22: Path Traversal
        for line_num, line in enumerate(lines, 1):
            if ('fopen(' in line or 'open(' in line or 'file_get_contents(' in line):
                if '../' in line or '..\\'in line:
                    patterns.append({
                        'cwe': 'CWE-22: Path Traversal',
                        'line': line_num,
                        'code': line.strip(),
                        'severity': 'HIGH',
                        'description': 'File path allows directory traversal'
                    })
        
        # CWE-798: Hard-coded Credentials
        for line_num, line in enumerate(lines, 1):
            if any(x in line.lower() for x in ['password = "', 'password="', 'passwd="', 'api_key = "', 'secret = "', 'apikey=']):
                # Check if it's actually a hardcoded value (not empty or placeholder)
                if '""' not in line and '"your_' not in line.lower() and '"xxx' not in line.lower():
                    patterns.append({
                        'cwe': 'CWE-798: Hard-coded Credentials',
                        'line': line_num,
                        'code': line.strip(),
                        'severity': 'HIGH',
                        'description': 'Credentials hardcoded in source code'
                    })
        
        # CWE-327: Weak Crypto
        for line_num, line in enumerate(lines, 1):
            if any(x in line.upper() for x in ['MD5(', 'MD5.', 'SHA1(', 'SHA1.', 'DES(', 'DES.', 'RC4']):
                patterns.append({
                    'cwe': 'CWE-327: Weak Cryptographic Algorithm',
                    'line': line_num,
                    'code': line.strip(),
                    'severity': 'MEDIUM',
                    'description': 'Using deprecated or weak cryptographic algorithm'
                })
        
        # CWE-352: CSRF (No token in form)
        for line_num, line in enumerate(lines, 1):
            if '<form' in line.lower() and 'method' in line.lower():
                if 'csrf' not in lines[min(line_num, len(lines)-1)].lower():
                    patterns.append({
                        'cwe': 'CWE-352: Cross-Site Request Forgery (CSRF)',
                        'line': line_num,
                        'code': line.strip(),
                        'severity': 'MEDIUM',
                        'description': 'Form without CSRF protection'
                    })
        
        # CWE-502: Insecure Deserialization
        for line_num, line in enumerate(lines, 1):
            if any(x in line for x in ['pickle.loads', 'yaml.load(', 'unserialize(']):
                patterns.append({
                    'cwe': 'CWE-502: Insecure Deserialization',
                    'line': line_num,
                    'code': line.strip(),
                    'severity': 'HIGH',
                    'description': 'Deserializing untrusted data'
                })
        
        # CWE-639: Insecure Direct Object Reference (IDOR)
        for line_num, line in enumerate(lines, 1):
            if any(x in line for x in ['request.args', 'request.GET', 'request.POST', '$_GET', '$_POST']):
                if any(y in line for y in ['user_id', 'file_id', 'order_id', 'account_id']):
                    patterns.append({
                        'cwe': 'CWE-639: Insecure Direct Object Reference (IDOR)',
                        'line': line_num,
                        'code': line.strip(),
                        'severity': 'HIGH',
                        'description': 'Direct object reference from user input without authorization check'
                    })
        
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
        if 'CWE-352' in cwe_str:
            recs.append("Implement CSRF tokens for all state-changing operations")
        if 'CWE-502' in cwe_str:
            recs.append("Avoid deserializing untrusted data or use safe serialization formats like JSON")
        if 'CWE-639' in cwe_str:
            recs.append("Implement proper authorization checks before accessing objects")
        
        if not recs:
            recs.append("Code appears safe, but manual security review recommended")
        
        return recs

class VulnerabilityFixer:
    """Advanced vulnerability auto-fix engine"""
    
    def __init__(self):
        self.api_key = os.getenv('API_KEY')
        self.model = None
        
        print("\n" + "="*50)
        print("[FIXER INIT] Initializing VulnerabilityFixer...")
        print(f"[FIXER INIT] API Key present: {bool(self.api_key)}")
        
        if self.api_key:
            try:
                print(f"[FIXER INIT] Configuring Gemini model...")
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-2.5-flash')
                print(f"[FIXER INIT] ✅ Gemini model initialized successfully!")
            except Exception as e:
                print(f"[FIXER INIT] ❌ Failed to initialize Gemini: {type(e).__name__}: {str(e)}")
                self.model = None
        else:
            print(f"[FIXER INIT] ⚠️ No API key found in .env file")
        
        self.fix_patterns = self._initialize_fix_patterns()
        print(f"[FIXER INIT] Loaded {len(self.fix_patterns)} pattern-based fixes")
        print("="*50 + "\n")
    
    def _initialize_fix_patterns(self) -> Dict:
        """Initialize vulnerability fix patterns"""
        return {
            'CWE-89': {
                'name': 'SQL Injection',
                'patterns': [
                    {
                        'find': r'(sprintf|snprintf)\s*\(\s*(\w+)\s*,\s*"SELECT\s+\*\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*\'%s\'',
                        'language': 'c',
                        'fix_template': 'Use prepared statements instead:\n// Prepared statement (secure)\nsqlite3_stmt *stmt;\nsqlite3_prepare_v2(db, "SELECT * FROM {table} WHERE {column}=?", -1, &stmt, NULL);\nsqlite3_bind_text(stmt, 1, {value}, -1, SQLITE_TRANSIENT);'
                    },
                    {
                        'find': r'query\s*=\s*f?"SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*[\'"]?\{',
                        'language': 'python',
                        'fix_template': 'Use parameterized query:\ncursor.execute("SELECT * FROM {table} WHERE {column}=?", ({value},))'
                    }
                ]
            },
            'CWE-119': {
                'name': 'Buffer Overflow',
                'patterns': [
                    {
                        'find': r'strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',
                        'replacement': r'strncpy(\1, \2, sizeof(\1) - 1);\n\1[sizeof(\1) - 1] = \'\\0\';  // Ensure null termination',
                        'language': 'c'
                    },
                    {
                        'find': r'strcat\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',
                        'replacement': r'strncat(\1, \2, sizeof(\1) - strlen(\1) - 1);',
                        'language': 'c'
                    },
                    {
                        'find': r'gets\s*\(\s*(\w+)\s*\)',
                        'replacement': r'fgets(\1, sizeof(\1), stdin);',
                        'language': 'c'
                    },
                    {
                        'find': r'sprintf\s*\(\s*(\w+)\s*,',
                        'replacement': r'snprintf(\1, sizeof(\1),',
                        'language': 'c'
                    }
                ]
            },
            'CWE-78': {
                'name': 'Command Injection',
                'patterns': [
                    {
                        'find': r'system\s*\(\s*["\']?(.+?)["\']?\s*\)',
                        'language': 'c',
                        'fix_template': 'Use execv with array args:\nchar *args[] = {{"{cmd}", NULL}};\nexecv("/bin/{cmd}", args);'
                    },
                    {
                        'find': r'subprocess\.run\s*\(\s*f?"(.+?)"\s*,\s*shell\s*=\s*True',
                        'replacement': r'subprocess.run(["\1"], shell=False)  # Use array, disable shell',
                        'language': 'python'
                    }
                ]
            },
            'CWE-79': {
                'name': 'Cross-Site Scripting',
                'patterns': [
                    {
                        'find': r'\.innerHTML\s*=\s*(\w+)',
                        'replacement': r'.textContent = \1  // Use textContent (safe)',
                        'language': 'javascript'
                    },
                    {
                        'find': r'document\.write\s*\(\s*(\w+)\s*\)',
                        'replacement': r'document.getElementById("output").textContent = \1  // Safe DOM manipulation',
                        'language': 'javascript'
                    }
                ]
            },
            'CWE-327': {
                'name': 'Weak Cryptography',
                'patterns': [
                    {
                        'find': r'hashlib\.md5\s*\(\s*(.+?)\s*\)',
                        'replacement': r'hashlib.sha256(\1)  # Use SHA-256 instead of MD5',
                        'language': 'python'
                    },
                    {
                        'find': r'hashlib\.sha1\s*\(\s*(.+?)\s*\)',
                        'replacement': r'hashlib.sha256(\1)  # Use SHA-256 instead of SHA-1',
                        'language': 'python'
                    }
                ]
            },
            'CWE-798': {
                'name': 'Hard-coded Credentials',
                'patterns': [
                    {
                        'find': r'(password|passwd|api_key|secret)\s*=\s*["\'](.+?)["\']',
                        'replacement': r'\1 = os.getenv("\1".upper())  # Load from environment',
                        'language': 'python'
                    },
                    {
                        'find': r'app\.secret_key\s*=\s*["\'](.+?)["\']',
                        'replacement': r'app.secret_key = os.getenv("SECRET_KEY")  # Load from environment',
                        'language': 'python'
                    }
                ]
            },
            'CWE-502': {
                'name': 'Insecure Deserialization',
                'patterns': [
                    {
                        'find': r'pickle\.loads?\s*\(\s*(.+?)\s*\)',
                        'replacement': r'json.loads(\1)  # Use JSON instead of pickle for untrusted data',
                        'language': 'python'
                    },
                    {
                        'find': r'yaml\.load\s*\(\s*(.+?)\s*\)',
                        'replacement': r'yaml.safe_load(\1)  # Use safe_load to prevent code execution',
                        'language': 'python'
                    }
                ]
            },
            'CWE-22': {
                'name': 'Path Traversal',
                'patterns': [
                    {
                        'find': r'open\s*\(\s*(.+?)\s*,',
                        'language': 'python',
                        'fix_template': '# Validate and sanitize file paths\nimport os\nfilepath = os.path.abspath(os.path.join(SAFE_DIR, os.path.basename({path})))\nif not filepath.startswith(SAFE_DIR):\n    raise ValueError("Invalid path")\nopen(filepath,'
                    }
                ]
            }
        }
    
    def generate_fix(self, vulnerability: Dict, full_code: str, language: str = 'c') -> Dict:
        """Generate intelligent fix for vulnerability"""
        cwe = vulnerability.get('cwe', '')
        original_line = vulnerability.get('code', '')
        line_number = vulnerability.get('line', 0)
        severity = vulnerability.get('severity', 'MEDIUM')
        description = vulnerability.get('description', '')
        
        print(f"\n[FIX REQUEST] {cwe} at line {line_number}")
        print(f"[FIX REQUEST] Code: {original_line[:60]}...")
        
        # Extract context (5 lines before and after)
        lines = full_code.split('\n')
        start_idx = max(0, line_number - 6)
        end_idx = min(len(lines), line_number + 5)
        context = '\n'.join(lines[start_idx:end_idx])
        
        # Try AI-powered fix first
        print(f"[FIX REQUEST] Trying AI-powered fix...")
        ai_fix = self._generate_ai_fix(cwe, original_line, context, language, severity, description)
        if ai_fix:
            print(f"[FIX REQUEST] ✅ AI fix successful!")
            return ai_fix
        
        print(f"[FIX REQUEST] AI fix not available, trying pattern-based fix...")
        # Fallback to pattern-based fix
        cwe_id = cwe.split(':')[0] if ':' in cwe else cwe
        if cwe_id not in self.fix_patterns:
            print(f"[FIX REQUEST] ❌ No pattern available for {cwe_id}")
            manual_guide = self._get_manual_remediation_guide(cwe, language)
            # Generate AI explanation for the threat
            explanation = self._generate_threat_explanation(cwe, original_line, language, severity)
            return {
                'can_fix': False,
                'reason': manual_guide,
                'manual_fix': description or 'Manual review required',
                'explanation': explanation
            }
        
        print(f"[FIX REQUEST] Found pattern for {cwe_id}")
        pattern_info = self.fix_patterns[cwe_id]
        
        # Try to find matching pattern
        for pattern in pattern_info['patterns']:
            if 'language' in pattern and pattern['language'] != language:
                continue
            
            if 'find' in pattern:
                match = re.search(pattern['find'], original_line, re.IGNORECASE)
                if match:
                    if 'replacement' in pattern:
                        fixed_line = re.sub(pattern['find'], pattern['replacement'], original_line, flags=re.IGNORECASE)
                        return {
                            'can_fix': True,
                            'original': original_line.strip(),
                            'fixed': fixed_line.strip(),
                            'line': vulnerability.get('line'),
                            'explanation': f'Replaced vulnerable code with secure alternative'
                        }
                    elif 'fix_template' in pattern:
                        return {
                            'can_fix': True,
                            'original': original_line.strip(),
                            'fixed': pattern['fix_template'],
                            'line': vulnerability.get('line'),
                            'explanation': f'Generated secure code template'
                        }
        
        # Pattern didn't match - provide manual remediation guide with AI explanation
        explanation = self._generate_threat_explanation(cwe, original_line, language, severity)
        return {
            'can_fix': False,
            'reason': self._get_manual_remediation_guide(cwe, language),
            'manual_fix': f'Please manually review and fix: {original_line}',
            'explanation': explanation
        }
    
    def _get_manual_remediation_guide(self, cwe: str, language: str) -> str:
        """Generate detailed manual remediation instructions for a CWE."""
        guides = {
            'CWE-89': {
                'title': 'SQL Injection Prevention',
                'steps': [
                    '1. Use parameterized queries (prepared statements)',
                    '2. Never concatenate user input into SQL queries',
                    '3. Use an ORM framework with built-in protections',
                    '4. Validate and sanitize all user inputs',
                    '5. Apply least privilege to database accounts'
                ],
                'example': {
                    'python': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                    'javascript': 'db.query("SELECT * FROM users WHERE id = $1", [userId])',
                    'java': 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");'
                }
            },
            'CWE-79': {
                'title': 'Cross-Site Scripting (XSS) Prevention',
                'steps': [
                    '1. Escape all user data before rendering in HTML',
                    '2. Use textContent instead of innerHTML for text',
                    '3. Implement Content Security Policy (CSP) headers',
                    '4. Validate inputs on both client and server side',
                    '5. Use framework sanitization methods'
                ],
                'example': {
                    'python': 'from html import escape; safe = escape(user_input)',
                    'javascript': 'element.textContent = userInput; // or DOMPurify.sanitize()',
                    'java': 'String safe = StringEscapeUtils.escapeHtml4(userInput);'
                }
            },
            'CWE-78': {
                'title': 'Command Injection Prevention',
                'steps': [
                    '1. Avoid executing system commands when possible',
                    '2. Use safe APIs instead of shell commands',
                    '3. Validate and whitelist all inputs',
                    '4. Never use shell=True in subprocess calls',
                    '5. Escape arguments properly'
                ],
                'example': {
                    'python': 'subprocess.run(["ls", "-l", directory], shell=False)',
                    'javascript': 'execFile("ls", ["-l", directory])',
                    'java': 'new ProcessBuilder("ls", "-l", directory).start();'
                }
            },
            'CWE-22': {
                'title': 'Path Traversal Prevention',
                'steps': [
                    '1. Validate file paths against a whitelist',
                    '2. Use path normalization functions',
                    '3. Reject paths containing "../" or "..\\\\"',
                    '4. Use absolute paths and verify they stay in allowed directory',
                    '5. Store files with indirect references (IDs)'
                ],
                'example': {
                    'python': 'safe_path = os.path.abspath(os.path.join(base_dir, filename)); if safe_path.startswith(base_dir): open(safe_path)',
                    'javascript': 'const safePath = path.resolve(baseDir, filename); if (safePath.startsWith(baseDir)) fs.readFile(safePath)',
                    'java': 'Path safePath = Paths.get(baseDir, filename).normalize();'
                }
            },
            'CWE-327': {
                'title': 'Weak Cryptography Remediation',
                'steps': [
                    '1. Replace MD5/SHA1 with SHA-256 or higher',
                    '2. Use bcrypt, scrypt, or Argon2 for passwords',
                    '3. Replace DES with AES-256',
                    '4. Use authenticated encryption (AES-GCM)',
                    '5. Keep cryptographic libraries updated'
                ],
                'example': {
                    'python': 'import hashlib; hash = hashlib.sha256(data.encode()).hexdigest()',
                    'javascript': 'const hash = crypto.createHash("sha256").update(data).digest("hex");',
                    'java': 'MessageDigest.getInstance("SHA-256").digest(data.getBytes());'
                }
            },
            'CWE-798': {
                'title': 'Hard-coded Credentials Remediation',
                'steps': [
                    '1. Move credentials to environment variables',
                    '2. Use secure key management (AWS KMS, Azure Key Vault)',
                    '3. Store configs outside version control',
                    '4. Implement secrets rotation',
                    '5. Never commit credentials to repositories'
                ],
                'example': {
                    'python': 'password = os.getenv("DB_PASSWORD")',
                    'javascript': 'const password = process.env.DB_PASSWORD;',
                    'java': 'String password = System.getenv("DB_PASSWORD");'
                }
            },
            'CWE-502': {
                'title': 'Insecure Deserialization Prevention',
                'steps': [
                    '1. Use JSON instead of pickle/serialize',
                    '2. Validate object types before deserialization',
                    '3. Use allowlists for acceptable classes',
                    '4. Sign serialized data to detect tampering',
                    '5. Never deserialize untrusted data'
                ],
                'example': {
                    'python': 'data = json.loads(input_string)  # instead of pickle.loads()',
                    'javascript': 'const data = JSON.parse(inputString);',
                    'java': 'ObjectMapper mapper = new ObjectMapper(); obj = mapper.readValue(json, MyClass.class);'
                }
            },
            'CWE-119': {
                'title': 'Buffer Overflow Prevention',
                'steps': [
                    '1. Use safe string functions (strncpy, snprintf)',
                    '2. Always specify buffer size limits',
                    '3. Validate input lengths before copying',
                    '4. Use memory-safe languages when possible',
                    '5. Enable compiler protections (stack canaries)'
                ],
                'example': {
                    'c': 'strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = 0;',
                    'cpp': 'std::string safe_str = input.substr(0, MAX_LENGTH);'
                }
            }
        }
        
        # Get the guide for this CWE
        cwe_id = cwe.split(':')[0] if ':' in cwe else cwe
        guide = guides.get(cwe_id)
        
        if not guide:
            return 'Manual review required. Consult OWASP guidelines for this vulnerability type.'
        
        # Build the remediation guide with pipe-separated format for parsing in frontend
        steps_text = '\\n'.join(guide['steps'])
        example = guide['example'].get(language, guide['example'].get('python', ''))
        
        return f"{guide['title']}|{steps_text}|{example}"
    
    def _generate_threat_explanation(self, cwe: str, code: str, language: str, severity: str) -> str:
        """Use Gemini AI to generate detailed, specific threat explanation."""
        if not self.model:
            # Fallback explanation if AI is not available
            return f"This {cwe} vulnerability in your {language} code could allow attackers to compromise your application's security."
        
        try:
            prompt = f"""You are a cybersecurity expert. Explain this specific vulnerability in simple, clear terms.

**Vulnerability Type:** {cwe}
**Severity:** {severity}
**Programming Language:** {language}
**Vulnerable Code:**
```{language}
{code}
```

**Task:**
Write a brief (2-3 sentences) explanation that covers:
1. What this specific vulnerability is and how it occurs in THIS CODE
2. What real attack could exploit THIS CODE
3. What damage or data breach could result

Be specific to the code shown, not generic. Use simple language."""
            
            response = self.model.generate_content(prompt)
            explanation = response.text.strip()
            print(f"[AI EXPLAIN] Generated explanation for {cwe}")
            return explanation
        except Exception as e:
            print(f"[AI EXPLAIN] ❌ Error: {str(e)[:100]}")
            # Fallback to generic explanation
            return f"This {cwe} vulnerability allows attackers to manipulate your {language} application. It should be fixed immediately to prevent security breaches."
    
    def _generate_ai_fix(self, cwe: str, vulnerable_code: str, context: str, language: str, severity: str, description: str) -> Dict:
        """Generate intelligent fix using advanced backend"""
        if not self.model:
            print(f"[AI FIX] Model not initialized. API key present: {bool(self.api_key)}")
            return None
        
        try:
            print(f"[AI FIX] Generating fix for {cwe} in {language}...")
            prompt = f"""You are an expert security engineer. Fix this security vulnerability.

**Vulnerability Details:**
- Type: {cwe}
- Severity: {severity}
- Description: {description}
- Language: {language}

**Vulnerable Code:**
```{language}
{vulnerable_code}
```

**Code Context:**
```{language}
{context}
```

**Task:**
Provide ONLY the fixed code line(s) that replace the vulnerable code. Your response must:
1. Be syntactically correct {language} code
2. Fix the security issue completely
3. Maintain the same functionality
4. Follow secure coding best practices
5. Be concise - only the fixed line(s), no explanations

**Return format:**
Just the fixed code, nothing else."""

            response = self.model.generate_content(prompt)
            fixed_code = response.text.strip()
            
            print(f"[AI FIX] Raw response length: {len(fixed_code)}")
            
            # Clean up code formatting
            fixed_code = fixed_code.replace('```' + language, '').replace('```', '').strip()
            
            # Validate it's not empty
            if not fixed_code or len(fixed_code) < 5:
                print(f"[AI FIX] Generated code too short: '{fixed_code}'")
                return None
            
            print(f"[AI FIX] ✅ Successfully generated fix: {fixed_code[:50]}...")
            return {
                'can_fix': True,
                'original': vulnerable_code.strip(),
                'fixed': fixed_code,
                'explanation': 'Secure code generated using AI',
                'confidence': 'high'
            }
        except Exception as e:
            print(f"[AI FIX] ❌ Error: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def fix_file(self, file_content: str, vulnerabilities: List[Dict], language: str = 'c') -> Tuple[str, List[Dict]]:
        """Fix all vulnerabilities in a file"""
        lines = file_content.split('\n')
        fixes_applied = []
        
        # Sort vulnerabilities by line number (descending) to avoid line number shifts
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.get('line', 0), reverse=True)
        
        for vuln in sorted_vulns:
            fix_result = self.generate_fix(vuln, file_content, language)
            
            if fix_result.get('can_fix'):
                line_num = vuln.get('line', 0)
                if 0 < line_num <= len(lines):
                    # Replace the vulnerable line
                    old_line = lines[line_num - 1]
                    lines[line_num - 1] = fix_result['fixed']
                    
                    fixes_applied.append({
                        'line': line_num,
                        'cwe': vuln.get('cwe'),
                        'original': old_line.strip(),
                        'fixed': fix_result['fixed'],
                        'success': True
                    })
            else:
                fixes_applied.append({
                    'line': vuln.get('line'),
                    'cwe': vuln.get('cwe'),
                    'success': False,
                    'reason': fix_result.get('reason', 'Cannot auto-fix')
                })
        
        fixed_content = '\n'.join(lines)
        return fixed_content, fixes_applied

# Initialize scanner and fixer
scanner = VulnerabilityScanner()
fixer = VulnerabilityFixer()

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
        
        # Scan code with detailed locations
        result = scanner.scan_code(code, language, 'user_code')
        result['timestamp'] = datetime.now().isoformat()
        
        print(f"Result: {result['vulnerable']}, Confidence: {result['confidence']}%")
        print(f"Found {len(result['cwe_patterns'])} CWE patterns")
        print(f"Found {len(result['dangerous_functions'])} dangerous functions")
        
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
        'medium_risk_files': [],
        'all_vulnerabilities': []  # Detailed list of ALL vulnerabilities with locations
    }
    
    for root, dirs, files in os.walk(directory):
        # Skip common ignore directories
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', 'env', '.venv', 'dist', 'build'}]
        
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
                scan_result = scanner.scan_code(code, filename=relative_path)
                
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
                    
                    # Add detailed vulnerabilities with file locations
                    for cwe in scan_result['cwe_patterns']:
                        vuln_detail = {
                            'file': relative_path,
                            'line': cwe['line'],
                            'cwe': cwe['cwe'],
                            'code': cwe['code'],
                            'severity': cwe['severity'],
                            'description': cwe.get('description', '')
                        }
                        results['all_vulnerabilities'].append(vuln_detail)
                        
                        # Group by CWE type
                        cwe_key = cwe['cwe']
                        if cwe_key not in results['vulnerabilities_by_cwe']:
                            results['vulnerabilities_by_cwe'][cwe_key] = []
                        results['vulnerabilities_by_cwe'][cwe_key].append(vuln_detail)
                else:
                    results['safe_files'] += 1
                
                print(f"  ✓ Scanned: {relative_path} - {scan_result['risk_level']} ({len(scan_result['cwe_patterns'])} issues)")
            
            except Exception as e:
                print(f"  ✗ Error scanning {relative_path}: {e}")
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
    
    # Top vulnerabilities with LOCATIONS
    top_cwes = sorted(
        results['vulnerabilities_by_cwe'].items(),
        key=lambda x: len(x[1]),
        reverse=True
    )[:10]
    
    report = {
        'project_name': project_name,
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_files': results['total_files'],
            'scanned_files': results['scanned_files'],
            'vulnerable_files': vuln,
            'safe_files': safe,
            'security_score': security_score,
            'overall_risk': overall_risk,
            'total_vulnerabilities': len(results['all_vulnerabilities'])
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
                'count': len(locations),
                'severity': locations[0]['severity'] if locations else 'UNKNOWN',
                'locations': locations[:5]  # Show top 5 locations per CWE
            }
            for cwe, locations in top_cwes
        ],
        'all_vulnerabilities': results['all_vulnerabilities'],  # Complete list with file:line
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

@app.route('/api/fix', methods=['POST'])
def fix_vulnerability():
    """Fix a single vulnerability"""
    try:
        data = request.get_json()
        code = data.get('code', '')
        vulnerability = data.get('vulnerability', {})
        language = data.get('language', 'c')
        
        if not code or not vulnerability:
            return jsonify({'error': 'Missing code or vulnerability data'}), 400
        
        print(f"\n=== Fixing vulnerability: {vulnerability.get('cwe')} ===")
        
        # Generate fix
        fix_result = fixer.generate_fix(vulnerability, code, language)
        
        return jsonify(fix_result)
    
    except Exception as e:
        print(f"ERROR in /api/fix: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Fix failed: {str(e)}'}), 500

@app.route('/api/fix-file', methods=['POST'])
def fix_file():
    """Fix all vulnerabilities in a file"""
    try:
        data = request.get_json()
        code = data.get('code', '')
        vulnerabilities = data.get('vulnerabilities', [])
        language = data.get('language', 'c')
        
        if not code:
            return jsonify({'error': 'No code provided'}), 400
        
        print(f"\n=== Fixing {len(vulnerabilities)} vulnerabilities ===")
        
        # Fix all vulnerabilities
        fixed_code, fixes_applied = fixer.fix_file(code, vulnerabilities, language)
        
        # Count successes
        successful_fixes = sum(1 for fix in fixes_applied if fix.get('success'))
        
        return jsonify({
            'success': True,
            'original_code': code,
            'fixed_code': fixed_code,
            'fixes_applied': fixes_applied,
            'total_fixes': len(fixes_applied),
            'successful_fixes': successful_fixes,
            'failed_fixes': len(fixes_applied) - successful_fixes
        })
    
    except Exception as e:
        print(f"ERROR in /api/fix-file: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Fix failed: {str(e)}'}), 500

@app.route('/api/fix-project', methods=['POST'])
def fix_project():
    """Fix vulnerabilities in entire project and download fixed version"""
    try:
        data = request.get_json()
        project_data = data.get('project_data', {})
        
        if not project_data:
            return jsonify({'error': 'No project data provided'}), 400
        
        # Create a temporary directory for fixed files
        fix_dir = os.path.join(app.config['UPLOAD_FOLDER'], f'fixed_{os.getpid()}')
        os.makedirs(fix_dir, exist_ok=True)
        
        fixes_summary = []
        
        # Process each vulnerable file
        for file_data in project_data.get('files', []):
            filepath = file_data.get('path')
            vulnerabilities = file_data.get('cwe_patterns', [])
            
            if not vulnerabilities:
                continue
            
            try:
                # Read original file
                original_path = file_data.get('original_path')
                if original_path and os.path.exists(original_path):
                    with open(original_path, 'r', encoding='utf-8', errors='ignore') as f:
                        original_code = f.read()
                    
                    # Determine language from extension
                    ext = filepath.split('.')[-1].lower()
                    language = 'python' if ext == 'py' else 'javascript' if ext in ['js', 'jsx'] else 'c'
                    
                    # Fix vulnerabilities
                    fixed_code, fixes_applied = fixer.fix_file(original_code, vulnerabilities, language)
                    
                    # Save fixed file
                    fixed_path = os.path.join(fix_dir, filepath)
                    os.makedirs(os.path.dirname(fixed_path), exist_ok=True)
                    
                    with open(fixed_path, 'w', encoding='utf-8') as f:
                        f.write(fixed_code)
                    
                    fixes_summary.append({
                        'file': filepath,
                        'fixes': fixes_applied,
                        'success': True
                    })
            except Exception as e:
                fixes_summary.append({
                    'file': filepath,
                    'error': str(e),
                    'success': False
                })
        
        # Create ZIP of fixed files
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], f'fixed_project_{os.getpid()}.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(fix_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, fix_dir)
                    zipf.write(file_path, arcname)
        
        return jsonify({
            'success': True,
            'fixes_summary': fixes_summary,
            'download_url': f'/api/download-fixed/{os.path.basename(zip_path)}'
        })
    
    except Exception as e:
        print(f"ERROR in /api/fix-project: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Project fix failed: {str(e)}'}), 500

@app.route('/api/download-fixed/<filename>')
def download_fixed(filename):
    """Download fixed project ZIP"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        return send_file(filepath, as_attachment=True, download_name='fixed_project.zip')
    except Exception as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

if __name__ == '__main__':
    print("🔐 Starting ZeroDayGuard Web Server (Enhanced with Auto-Fix)...")
    print("📍 Open: http://localhost:5000")
    print("✅ Scanner loaded with detailed location tracking!")
    print("🔧 Auto-fix engine ready!")
    app.run(debug=True, host='0.0.0.0', port=5000)
