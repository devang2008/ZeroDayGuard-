"""
Code Parser for C/C++ Source Code
Parses C/C++ code using tree-sitter and extracts AST
"""

import re
from typing import Dict, List, Optional
import numpy as np

class CodeParser:
    """
    Simple C/C++ code parser without tree-sitter dependency
    Extracts basic code structure and tokens
    """
    
    def __init__(self, language='c'):
        self.language = language
        
    def parse(self, source_code: str) -> Dict:
        """
        Parse source code and extract basic information
        
        Args:
            source_code: String containing C/C++ source code
            
        Returns:
            Dictionary with parsed code information
        """
        return {
            'source': source_code,
            'tokens': self._tokenize(source_code),
            'lines': source_code.split('\n'),
            'functions': self._extract_functions(source_code),
            'variables': self._extract_variables(source_code),
            'calls': self._extract_function_calls(source_code),
            'keywords': self._extract_keywords(source_code)
        }
    
    def _tokenize(self, code: str) -> List[str]:
        """Simple tokenization"""
        # Remove comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        
        # Extract tokens
        tokens = re.findall(r'\b\w+\b|[^\w\s]', code)
        return tokens
    
    def _extract_functions(self, code: str) -> List[Dict]:
        """Extract function definitions"""
        functions = []
        
        # Simple pattern for function definitions
        pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*\{'
        matches = re.finditer(pattern, code)
        
        for match in matches:
            functions.append({
                'return_type': match.group(1),
                'name': match.group(2),
                'position': match.start()
            })
        
        return functions
    
    def _extract_variables(self, code: str) -> List[str]:
        """Extract variable declarations"""
        # Common C/C++ types
        types = r'\b(int|char|float|double|void|long|short|unsigned|signed|struct|union)\b'
        pattern = types + r'\s+(\w+)'
        
        variables = re.findall(pattern, code)
        return [var[1] for var in variables]
    
    def _extract_function_calls(self, code: str) -> List[str]:
        """Extract function calls"""
        pattern = r'(\w+)\s*\('
        calls = re.findall(pattern, code)
        
        # Filter out keywords and type definitions
        keywords = {'if', 'while', 'for', 'switch', 'sizeof', 'return'}
        return [call for call in calls if call not in keywords]
    
    def _extract_keywords(self, code: str) -> Dict[str, int]:
        """Count C/C++ keywords"""
        keywords = {
            'if': 0, 'else': 0, 'while': 0, 'for': 0, 'switch': 0,
            'case': 0, 'break': 0, 'continue': 0, 'return': 0,
            'malloc': 0, 'free': 0, 'strcpy': 0, 'strcat': 0,
            'sprintf': 0, 'gets': 0, 'scanf': 0, 'printf': 0
        }
        
        for keyword in keywords.keys():
            keywords[keyword] = len(re.findall(r'\b' + keyword + r'\b', code))
        
        return keywords
    
    def extract_features(self, parsed_code: Dict) -> np.ndarray:
        """
        Extract numerical features from parsed code
        
        Args:
            parsed_code: Dictionary from parse() method
            
        Returns:
            NumPy array of features
        """
        features = []
        
        # Basic metrics
        features.append(len(parsed_code['lines']))  # LOC
        features.append(len(parsed_code['tokens']))  # Token count
        features.append(len(parsed_code['functions']))  # Function count
        features.append(len(parsed_code['variables']))  # Variable count
        features.append(len(parsed_code['calls']))  # Function call count
        
        # Keyword counts
        for count in parsed_code['keywords'].values():
            features.append(count)
        
        # Dangerous function usage
        dangerous_funcs = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf']
        dangerous_count = sum(parsed_code['keywords'].get(func, 0) 
                             for func in dangerous_funcs)
        features.append(dangerous_count)
        
        # Control flow complexity (approximation)
        control_keywords = ['if', 'while', 'for', 'switch']
        complexity = sum(parsed_code['keywords'].get(kw, 0) 
                        for kw in control_keywords)
        features.append(complexity)
        
        return np.array(features, dtype=np.float32)


def get_code_features(source_code: str) -> np.ndarray:
    """
    Convenience function to extract features from source code
    
    Args:
        source_code: String containing source code
        
    Returns:
        NumPy array of features
    """
    parser = CodeParser()
    parsed = parser.parse(source_code)
    return parser.extract_features(parsed)
