# agents/scanner.py
import ast
import re
import os
from pathlib import Path
from typing import List, Dict, Any

class RepositoryScanner:
    """Agent 1: Scans repositories for AI/ML code patterns and security issues"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'unsafe_loading': {
                'patterns': [r'pickle\.load\(', r'torch\.load\(.*map_location=None', r'joblib\.load\('],
                'severity': 'HIGH',
                'description': 'Unsafe model/data loading detected'
            },
            'missing_validation': {
                'patterns': [r'model\.predict\(', r'model\(.*\)', r'\.forward\('],
                'severity': 'MEDIUM', 
                'description': 'Model inference without apparent input validation'
            },
            'hardcoded_secrets': {
                'patterns': [r'api_key\s*=\s*["\'][^"\']{10,}["\']', r'password\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\'][^"\']+["\']'],
                'severity': 'HIGH',
                'description': 'Hardcoded credentials or API keys detected'
            },
            'unsafe_data_loading': {
                'patterns': [r'pd\.read_csv\([^)]*sep\s*=', r'open\([^)]*["\']rb?["\']'],
                'severity': 'MEDIUM',
                'description': 'Data loading without apparent sanitization'
            }
        }
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Main scanning function"""
        
        print(f"Scanning repository: {repo_path}")
        
        if not os.path.exists(repo_path):
            return {
                'error': f'Repository path does not exist: {repo_path}',
                'frameworks': [],
                'code_patterns': [],
                'risk_indicators': [],
                'file_count': 0
            }
        
        frameworks = self._detect_frameworks(repo_path)
        code_patterns = self._analyze_code_patterns(repo_path)
        risk_indicators = self._identify_risks(code_patterns)
        file_count = len(list(Path(repo_path).rglob('*.py')))
        
        return {
            'repository_path': repo_path,
            'frameworks': frameworks,
            'code_patterns': code_patterns,
            'risk_indicators': risk_indicators,
            'file_count': file_count,
            'scan_summary': {
                'total_files': file_count,
                'frameworks_detected': len(frameworks),
                'patterns_found': len(code_patterns),
                'high_risk_patterns': len([p for p in code_patterns if p['severity'] == 'HIGH'])
            }
        }
    
    def _detect_frameworks(self, repo_path: str) -> List[str]:
        """Detect AI/ML frameworks used in the repository"""
        
        frameworks = set()
        
        # Check requirements files
        req_files = ['requirements.txt', 'setup.py', 'pyproject.toml', 'environment.yml']
        for req_file in req_files:
            req_path = Path(repo_path) / req_file
            if req_path.exists():
                try:
                    content = req_path.read_text(encoding='utf-8', errors='ignore').lower()
                    if 'tensorflow' in content or 'tf-' in content: frameworks.add('TensorFlow')
                    if 'torch' in content or 'pytorch' in content: frameworks.add('PyTorch')
                    if 'transformers' in content: frameworks.add('HuggingFace')
                    if 'sklearn' in content or 'scikit-learn' in content: frameworks.add('Scikit-learn')
                    if 'keras' in content: frameworks.add('Keras')
                    if 'onnx' in content: frameworks.add('ONNX')
                    if 'opencv' in content or 'cv2' in content: frameworks.add('OpenCV')
                except Exception:
                    continue
        
        # Check Python import statements
        for py_file in list(Path(repo_path).rglob('*.py'))[:50]:  # Limit to 50 files for performance
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                if re.search(r'import\s+(tensorflow|tf)\b', content): frameworks.add('TensorFlow')
                if re.search(r'import\s+(torch|pytorch)', content): frameworks.add('PyTorch')
                if re.search(r'import\s+transformers', content): frameworks.add('HuggingFace')
                if re.search(r'import\s+sklearn', content): frameworks.add('Scikit-learn')
                if re.search(r'import\s+keras', content): frameworks.add('Keras')
                if re.search(r'import\s+cv2', content): frameworks.add('OpenCV')
                
            except Exception:
                continue
                
        return sorted(list(frameworks))
    
    def _analyze_code_patterns(self, repo_path: str) -> List[Dict]:
        """Analyze code for security patterns"""
        
        patterns_found = []
        
        for py_file in Path(repo_path).rglob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Check each vulnerability pattern
                for pattern_name, pattern_info in self.vulnerability_patterns.items():
                    for regex_pattern in pattern_info['patterns']:
                        matches = re.finditer(regex_pattern, content, re.IGNORECASE)
                        for match in matches:
                            # Get line number
                            line_num = content[:match.start()].count('\n') + 1
                            
                            # Get context (the line with the match)
                            lines = content.split('\n')
                            context_line = lines[line_num - 1] if line_num <= len(lines) else ""
                            
                            patterns_found.append({
                                'type': pattern_name,
                                'severity': pattern_info['severity'],
                                'description': pattern_info['description'],
                                'file': str(py_file.relative_to(repo_path)),
                                'line': line_num,
                                'context': context_line.strip()[:100],  # Limit context length
                                'pattern_matched': regex_pattern
                            })
                            
            except Exception as e:
                continue  # Skip files that can't be read
                
        return patterns_found
    
    def _identify_risks(self, code_patterns: List[Dict]) -> List[str]:
        """Identify high-level risk categories from patterns"""
        
        risks = set()
        
        for pattern in code_patterns:
            if pattern['type'] == 'unsafe_loading':
                risks.add('unsafe_model_loading')
            elif pattern['type'] == 'missing_validation':
                risks.add('unvalidated_input')
            elif pattern['type'] == 'hardcoded_secrets':
                risks.add('credential_exposure')
            elif pattern['type'] == 'unsafe_data_loading':
                risks.add('data_injection')
                
        return sorted(list(risks))