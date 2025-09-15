# agents/analyzer.py - CLI-optimized version
import sys
import os
from typing import List, Dict, Any

# Get package root directory dynamically
def get_package_root():
    """Get the package root directory"""
    current_file = os.path.abspath(__file__)
    agents_dir = os.path.dirname(current_file)
    package_root = os.path.dirname(agents_dir)
    return package_root

class VulnerabilityAnalyzer:
    """Agent 2: Uses TiDB Vector Search to find similar vulnerabilities"""
    
    def __init__(self):
        print("Initializing VulnerabilityAnalyzer...")
        
        # Add package root to Python path
        package_root = get_package_root()
        if package_root not in sys.path:
            sys.path.insert(0, package_root)
        
        try:
            from data.vector_store import ArgusVectorStore
            self.vector_store = ArgusVectorStore()
            
            # Test if vector store has data
            test_search = self.vector_store.search_similar_vulnerabilities("test", k=1)
            self.has_data = len(test_search) > 0
            
            print(f"Vector store initialized. Has data: {self.has_data}")
            
        except Exception as e:
            print(f"Warning: Vector store initialization failed: {e}")
            print("The analyzer will use fallback analysis.")
            self.vector_store = None
            self.has_data = False
    
    def analyze_patterns(self, scan_results: Dict[str, Any]) -> List[Dict]:
        """Analyze scan results using vector similarity search with fallback"""
        
        print("Analyzing patterns with vector search...")
        
        # Always try vector search first, fall back if needed
        if self.vector_store and self.has_data:
            try:
                return self._vector_analysis(scan_results)
            except Exception as e:
                print(f"Vector analysis failed: {e}")
                print("Falling back to pattern-based analysis...")
        
        # Fallback analysis when vector store isn't available
        return self._fallback_analysis(scan_results)
    
    def _vector_analysis(self, scan_results: Dict[str, Any]) -> List[Dict]:
        """Perform vector-based vulnerability analysis"""
        
        all_matches = []
        
        # Search for framework-specific vulnerabilities
        frameworks = scan_results.get('frameworks', [])
        for framework in frameworks:
            query = f"{framework} security vulnerability bias risk"
            matches = self._semantic_search(query, k=3, context=f"Framework: {framework}")
            all_matches.extend(matches)
        
        # Search for code pattern vulnerabilities
        risk_indicators = scan_results.get('risk_indicators', [])
        for risk in risk_indicators:
            query = f"{risk} AI ML security vulnerability"
            matches = self._semantic_search(query, k=2, context=f"Risk: {risk}")
            all_matches.extend(matches)
        
        # Search for general AI security issues if frameworks detected
        if frameworks:
            query = "AI model security vulnerability adversarial attack bias"
            matches = self._semantic_search(query, k=3, context="General AI Security")
            all_matches.extend(matches)
        
        # Remove duplicates and sort by relevance
        unique_matches = self._deduplicate_matches(all_matches)
        final_matches = sorted(unique_matches, key=lambda x: x.get('relevance_score', 0), reverse=True)[:10]
        
        return final_matches if final_matches else self._fallback_analysis(scan_results)
    
    def _fallback_analysis(self, scan_results: Dict[str, Any]) -> List[Dict]:
        """Provide comprehensive fallback analysis when vector store isn't available"""
        
        fallback_matches = []
        frameworks = scan_results.get('frameworks', [])
        risk_indicators = scan_results.get('risk_indicators', [])
        code_patterns = scan_results.get('code_patterns', [])
        
        # Framework-specific risk analysis
        framework_risks = {
            'TensorFlow': {
                'title': 'TensorFlow Security Considerations',
                'description': 'TensorFlow models may be vulnerable to adversarial attacks, model inversion, and unsafe deserialization. Consider implementing input validation, model versioning, and secure model serving practices.',
                'severity': 'MEDIUM',
                'category': 'Framework Security'
            },
            'PyTorch': {
                'title': 'PyTorch Security Risks',
                'description': 'PyTorch applications can be vulnerable to pickle-based attacks through torch.load(), adversarial examples, and model extraction attacks. Use safe loading practices and input validation.',
                'severity': 'HIGH',
                'category': 'Framework Security'
            },
            'HuggingFace': {
                'title': 'Pre-trained Model Security',
                'description': 'Using models from HuggingFace Hub introduces risks from malicious models, data poisoning, and model backdoors. Verify model sources and implement model validation.',
                'severity': 'MEDIUM',
                'category': 'Model Integrity'
            },
            'Scikit-learn': {
                'title': 'ML Pipeline Security',
                'description': 'Scikit-learn pipelines may be vulnerable to data poisoning and model inversion attacks. Implement input validation and secure data handling practices.',
                'severity': 'LOW',
                'category': 'Pipeline Security'
            }
        }
        
        for framework in frameworks:
            if framework in framework_risks:
                risk_info = framework_risks[framework]
                fallback_matches.append({
                    'query_context': f'Framework Analysis: {framework}',
                    'similarity': 0.8,
                    'relevance_score': 0.8,
                    'source': 'Built-in Knowledge Base',
                    'title': risk_info['title'],
                    'description': risk_info['description'],
                    'risk_category': risk_info['category'],
                    'severity': risk_info['severity'],
                    'vulnerability_id': f'BUILTIN-FW-{framework.upper()}',
                    'metadata': {'type': 'framework_analysis', 'framework': framework}
                })
        
        # Code pattern risk analysis
        pattern_severities = {}
        for pattern in code_patterns:
            severity = pattern.get('severity', 'MEDIUM')
            pattern_type = pattern.get('type', 'unknown')
            pattern_severities[pattern_type] = pattern_severities.get(pattern_type, [])
            pattern_severities[pattern_type].append(severity)
        
        for pattern_type, severities in pattern_severities.items():
            high_count = severities.count('HIGH')
            medium_count = severities.count('MEDIUM')
            total_count = len(severities)
            
            if high_count > 0:
                fallback_matches.append({
                    'query_context': 'Code Pattern Analysis',
                    'similarity': 0.9,
                    'relevance_score': 0.9,
                    'source': 'Built-in Knowledge Base',
                    'title': f'High-Risk {pattern_type.replace("_", " ").title()} Patterns',
                    'description': f'Found {high_count} high-severity {pattern_type} patterns. These require immediate attention to prevent security vulnerabilities.',
                    'risk_category': 'Code Security',
                    'severity': 'HIGH',
                    'vulnerability_id': f'BUILTIN-PAT-{pattern_type.upper()}',
                    'metadata': {'type': 'pattern_analysis', 'pattern_type': pattern_type, 'count': high_count}
                })
            elif medium_count > 0:
                fallback_matches.append({
                    'query_context': 'Code Pattern Analysis', 
                    'similarity': 0.7,
                    'relevance_score': 0.7,
                    'source': 'Built-in Knowledge Base',
                    'title': f'{pattern_type.replace("_", " ").title()} Security Patterns',
                    'description': f'Found {total_count} {pattern_type} patterns that may indicate security concerns. Review and implement appropriate safeguards.',
                    'risk_category': 'Code Security',
                    'severity': 'MEDIUM',
                    'vulnerability_id': f'BUILTIN-PAT-{pattern_type.upper()}',
                    'metadata': {'type': 'pattern_analysis', 'pattern_type': pattern_type, 'count': total_count}
                })
        
        # Risk-based analysis
        risk_recommendations = {
            'unsafe_model_loading': {
                'title': 'Unsafe Model Loading Detected',
                'description': 'Code patterns suggest unsafe model loading practices using pickle or similar methods. This can lead to arbitrary code execution. Use safe loading methods and validate model integrity.',
                'severity': 'HIGH'
            },
            'unvalidated_input': {
                'title': 'Missing Input Validation',
                'description': 'Model inference code lacks apparent input validation. This can lead to adversarial attacks and unexpected behavior. Implement comprehensive input validation.',
                'severity': 'MEDIUM'
            },
            'credential_exposure': {
                'title': 'Credential Exposure Risk',
                'description': 'Hardcoded credentials or API keys detected in code. This poses a significant security risk. Move secrets to environment variables or secure credential management systems.',
                'severity': 'HIGH'
            },
            'data_injection': {
                'title': 'Data Injection Vulnerabilities',
                'description': 'Data loading patterns suggest potential injection vulnerabilities. Implement input sanitization and validation for all data sources.',
                'severity': 'MEDIUM'
            }
        }
        
        for risk in risk_indicators:
            if risk in risk_recommendations:
                risk_info = risk_recommendations[risk]
                fallback_matches.append({
                    'query_context': f'Risk Analysis: {risk}',
                    'similarity': 0.85,
                    'relevance_score': 0.85,
                    'source': 'Built-in Knowledge Base',
                    'title': risk_info['title'],
                    'description': risk_info['description'],
                    'risk_category': 'Security Risk',
                    'severity': risk_info['severity'],
                    'vulnerability_id': f'BUILTIN-RISK-{risk.upper()}',
                    'metadata': {'type': 'risk_analysis', 'risk_type': risk}
                })
        
        # General AI/ML security recommendations
        if frameworks and not fallback_matches:
            fallback_matches.append({
                'query_context': 'General AI Security',
                'similarity': 0.6,
                'relevance_score': 0.6,
                'source': 'Built-in Knowledge Base',
                'title': 'AI/ML Security Best Practices',
                'description': 'Implement comprehensive security measures including input validation, model versioning, bias testing, secure deployment, and monitoring for adversarial attacks.',
                'risk_category': 'General Security',
                'severity': 'LOW',
                'vulnerability_id': 'BUILTIN-GENERAL-SECURITY',
                'metadata': {'type': 'best_practices'}
            })
        
        print(f"Generated {len(fallback_matches)} fallback vulnerability matches")
        return fallback_matches
    
    def _semantic_search(self, query: str, k: int = 5, context: str = "") -> List[Dict]:
        """Perform semantic search and format results"""
        
        try:
            results = self.vector_store.search_similar_vulnerabilities(query, k=k)
            
            formatted_results = []
            for result in results:
                formatted_result = {
                    'query_context': context,
                    'similarity': getattr(result, 'distance', 0),
                    'relevance_score': 1 - getattr(result, 'distance', 0),
                    'source': getattr(result, 'metadata', {}).get('source', 'Unknown'),
                    'title': getattr(result, 'metadata', {}).get('title', 'Untitled'),
                    'description': getattr(result, 'document', ''),
                    'risk_category': getattr(result, 'metadata', {}).get('risk_category', ''),
                    'severity': getattr(result, 'metadata', {}).get('severity', 'MEDIUM'),
                    'vulnerability_id': getattr(result, 'metadata', {}).get('vulnerability_id', ''),
                    'report_id': getattr(result, 'metadata', {}).get('report_id', ''),
                    'affected_models': getattr(result, 'metadata', {}).get('affected_models', []),
                    'metadata': getattr(result, 'metadata', {})
                }
                formatted_results.append(formatted_result)
                
            return formatted_results
            
        except Exception as e:
            print(f"Error in semantic search for '{query}': {e}")
            return []
    
    def _deduplicate_matches(self, matches: List[Dict]) -> List[Dict]:
        """Remove duplicate matches based on content similarity"""
        
        unique_matches = []
        seen_titles = set()
        seen_descriptions = set()
        
        for match in matches:
            title = match.get('title', '')
            desc_start = match.get('description', '')[:50]
            
            if title not in seen_titles and desc_start not in seen_descriptions:
                unique_matches.append(match)
                seen_titles.add(title)
                seen_descriptions.add(desc_start)
                
        return unique_matches