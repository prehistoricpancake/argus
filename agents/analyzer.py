# agents/analyzer.py
import sys
import os
sys.path.append('..')

from data.vector_store import ArgusVectorStore
from typing import List, Dict, Any

class VulnerabilityAnalyzer:
    """Agent 2: Uses TiDB Vector Search to find similar vulnerabilities"""
    
    def __init__(self):
        self.vector_store = ArgusVectorStore()
    
    def analyze_patterns(self, scan_results: Dict[str, Any]) -> List[Dict]:
        """Analyze scan results using vector similarity search"""
        
        print("Analyzing patterns with vector search...")
        
        all_matches = []
        
        # Search for framework-specific vulnerabilities
        for framework in scan_results['frameworks']:
            query = f"{framework} security vulnerability bias risk"
            matches = self._semantic_search(query, k=3, context=f"Framework: {framework}")
            all_matches.extend(matches)
        
        # Search for code pattern vulnerabilities
        for risk in scan_results['risk_indicators']:
            query = f"{risk} AI ML security vulnerability"
            matches = self._semantic_search(query, k=2, context=f"Risk: {risk}")
            all_matches.extend(matches)
        
        # Search for general AI security issues if frameworks detected
        if scan_results['frameworks']:
            query = "AI model security vulnerability adversarial attack bias"
            matches = self._semantic_search(query, k=3, context="General AI Security")
            all_matches.extend(matches)
        
        # Remove duplicates and sort by relevance
        unique_matches = self._deduplicate_matches(all_matches)
        return sorted(unique_matches, key=lambda x: x['similarity'])[:10]
    
    def _semantic_search(self, query: str, k: int = 5, context: str = "") -> List[Dict]:
        """Perform semantic search and format results"""
        
        try:
            results = self.vector_store.search_similar_vulnerabilities(query, k=k)
            
            formatted_results = []
            for result in results:
                formatted_result = {
                    'query_context': context,
                    'similarity': result.distance,
                    'relevance_score': 1 - result.distance,  # Higher is better
                    'source': result.metadata.get('source', 'Unknown'),
                    'title': result.metadata.get('title', 'Untitled'),
                    'description': result.document,
                    'risk_category': result.metadata.get('risk_category', ''),
                    'severity': result.metadata.get('severity', 'MEDIUM'),
                    'vulnerability_id': result.metadata.get('vulnerability_id', ''),
                    'report_id': result.metadata.get('report_id', ''),
                    'affected_models': result.metadata.get('affected_models', []),
                    'metadata': result.metadata
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
            desc_start = match.get('description', '')[:50]  # First 50 chars
            
            if title not in seen_titles and desc_start not in seen_descriptions:
                unique_matches.append(match)
                seen_titles.add(title)
                seen_descriptions.add(desc_start)
                
        return unique_matches
    
    def get_vulnerability_insights(self, matches: List[Dict]) -> Dict[str, Any]:
        """Generate insights from vulnerability matches"""
        
        insights = {
            'total_matches': len(matches),
            'high_relevance_matches': len([m for m in matches if m['relevance_score'] > 0.7]),
            'sources': list(set([m['source'] for m in matches])),
            'severity_distribution': {},
            'common_risk_categories': {},
            'affected_models': set()
        }
        
        # Count severities
        for match in matches:
            severity = match['severity']
            insights['severity_distribution'][severity] = insights['severity_distribution'].get(severity, 0) + 1
        
        # Count risk categories
        for match in matches:
            category = match['risk_category']
            if category:
                insights['common_risk_categories'][category] = insights['common_risk_categories'].get(category, 0) + 1
        
        # Collect affected models
        for match in matches:
            for model in match.get('affected_models', []):
                insights['affected_models'].add(model)
        
        insights['affected_models'] = list(insights['affected_models'])
        
        return insights