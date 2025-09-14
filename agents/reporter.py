# agents/reporter.py
from typing import List, Dict, Any
import json
from datetime import datetime

class ReportGenerator:
    """Agent 3: Generates comprehensive security assessment reports"""
    
    def generate_report(self, scan_results: Dict, vulnerability_matches: List[Dict]) -> Dict[str, Any]:
        """Generate a comprehensive security report"""
        
        print("Generating security assessment report...")
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(scan_results, vulnerability_matches)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(scan_results, vulnerability_matches)
        
        # Create executive summary
        executive_summary = self._create_executive_summary(scan_results, vulnerability_matches, risk_score)
        
        # Detailed findings
        detailed_findings = self._create_detailed_findings(scan_results, vulnerability_matches)
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'repository_path': scan_results.get('repository_path', ''),
                'argus_version': '1.0.0'
            },
            'executive_summary': executive_summary,
            'risk_assessment': {
                'overall_score': round(risk_score, 1),
                'risk_level': self._risk_level(risk_score),
                'confidence': self._calculate_confidence(scan_results, vulnerability_matches)
            },
            'repository_analysis': {
                'frameworks_detected': scan_results.get('frameworks', []),
                'files_scanned': scan_results.get('file_count', 0),
                'patterns_detected': len(scan_results.get('code_patterns', [])),
                'high_risk_patterns': len([p for p in scan_results.get('code_patterns', []) if p.get('severity') == 'HIGH'])
            },
            'vulnerability_analysis': {
                'similar_vulnerabilities_found': len(vulnerability_matches),
                'high_relevance_matches': len([m for m in vulnerability_matches if m.get('relevance_score', 0) > 0.7]),
                'knowledge_sources_used': list(set([m.get('source') for m in vulnerability_matches if m.get('source')]))
            },
            'detailed_findings': detailed_findings,
            'recommendations': recommendations,
            'similar_incidents': self._format_similar_incidents(vulnerability_matches[:5])
        }
        
        return report
    
    def _calculate_risk_score(self, scan_results: Dict, matches: List[Dict]) -> float:
        """Calculate overall risk score (0-10 scale)"""
        
        base_score = 0.0
        
        # Score from code patterns
        code_patterns = scan_results.get('code_patterns', [])
        for pattern in code_patterns:
            if pattern.get('severity') == 'HIGH':
                base_score += 2.0
            elif pattern.get('severity') == 'MEDIUM':
                base_score += 1.0
            else:
                base_score += 0.5
        
        # Score from similar vulnerabilities (relevance weighted)
        for match in matches:
            relevance = match.get('relevance_score', 0)
            if relevance > 0.8:
                base_score += 1.5
            elif relevance > 0.6:
                base_score += 1.0
            else:
                base_score += 0.5
        
        # Bonus for high-risk frameworks
        frameworks = scan_results.get('frameworks', [])
        if 'TensorFlow' in frameworks or 'PyTorch' in frameworks:
            base_score += 0.5  # Major ML frameworks have more attack surface
        
        # Cap at 10.0
        return min(10.0, base_score)
    
    def _risk_level(self, score: float) -> str:
        """Convert numeric score to risk level"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 1.0:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _calculate_confidence(self, scan_results: Dict, matches: List[Dict]) -> str:
        """Calculate confidence level of the assessment"""
        
        patterns_found = len(scan_results.get('code_patterns', []))
        matches_found = len(matches)
        frameworks_detected = len(scan_results.get('frameworks', []))
        
        total_indicators = patterns_found + matches_found + frameworks_detected
        
        if total_indicators >= 10:
            return "HIGH"
        elif total_indicators >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _create_executive_summary(self, scan_results: Dict, matches: List[Dict], risk_score: float) -> Dict[str, Any]:
        """Create executive summary"""
        
        frameworks = scan_results.get('frameworks', [])
        high_risk_patterns = [p for p in scan_results.get('code_patterns', []) if p.get('severity') == 'HIGH']
        
        summary = {
            'risk_level': self._risk_level(risk_score),
            'key_findings': [],
            'immediate_actions_required': len(high_risk_patterns) > 0,
            'frameworks_at_risk': frameworks
        }
        
        # Key findings
        if high_risk_patterns:
            summary['key_findings'].append(f"Found {len(high_risk_patterns)} high-severity security patterns")
        
        if frameworks:
            summary['key_findings'].append(f"Detected {len(frameworks)} AI/ML frameworks: {', '.join(frameworks)}")
        
        if matches:
            relevant_matches = [m for m in matches if m.get('relevance_score', 0) > 0.7]
            if relevant_matches:
                summary['key_findings'].append(f"Found {len(relevant_matches)} highly relevant vulnerability matches")
        
        return summary
    
    def _create_detailed_findings(self, scan_results: Dict, matches: List[Dict]) -> Dict[str, Any]:
        """Create detailed findings section"""
        
        return {
            'code_analysis': {
                'patterns_by_severity': self._group_patterns_by_severity(scan_results.get('code_patterns', [])),
                'files_with_issues': list(set([p.get('file') for p in scan_results.get('code_patterns', []) if p.get('file')]))
            },
            'vulnerability_matching': {
                'top_matches': matches[:5],
                'severity_breakdown': self._get_severity_breakdown(matches),
                'source_breakdown': self._get_source_breakdown(matches)
            }
        }
    
    def _group_patterns_by_severity(self, patterns: List[Dict]) -> Dict[str, List[Dict]]:
        """Group code patterns by severity"""
        
        grouped = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        
        for pattern in patterns:
            severity = pattern.get('severity', 'MEDIUM')
            if severity in grouped:
                grouped[severity].append({
                    'type': pattern.get('type'),
                    'description': pattern.get('description'),
                    'file': pattern.get('file'),
                    'line': pattern.get('line'),
                    'context': pattern.get('context')
                })
        
        return grouped
    
    def _get_severity_breakdown(self, matches: List[Dict]) -> Dict[str, int]:
        """Get severity breakdown of vulnerability matches"""
        
        breakdown = {}
        for match in matches:
            severity = match.get('severity', 'MEDIUM')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        
        return breakdown
    
    def _get_source_breakdown(self, matches: List[Dict]) -> Dict[str, int]:
        """Get source breakdown of vulnerability matches"""
        
        breakdown = {}
        for match in matches:
            source = match.get('source', 'Unknown')
            breakdown[source] = breakdown.get(source, 0) + 1
        
        return breakdown
    
    def _generate_recommendations(self, scan_results: Dict, matches: List[Dict]) -> List[Dict]:
        """Generate actionable security recommendations"""
        
        recommendations = []
        
        # Recommendations based on code patterns
        patterns = scan_results.get('code_patterns', [])
        pattern_types = set([p.get('type') for p in patterns])
        
        if 'unsafe_loading' in pattern_types:
            recommendations.append({
                'category': 'Model Security',
                'priority': 'HIGH',
                'title': 'Implement Safe Model Loading',
                'description': 'Replace unsafe pickle/torch.load with secure alternatives',
                'action_items': [
                    'Use torch.load with map_location parameter',
                    'Validate model integrity before loading',
                    'Consider using ONNX format for model serialization'
                ]
            })
        
        if 'missing_validation' in pattern_types:
            recommendations.append({
                'category': 'Input Security',
                'priority': 'MEDIUM',
                'title': 'Add Input Validation',
                'description': 'Implement comprehensive input validation for model inference',
                'action_items': [
                    'Validate input data types and ranges',
                    'Sanitize user inputs before processing',
                    'Implement rate limiting for API endpoints'
                ]
            })
        
        if 'hardcoded_secrets' in pattern_types:
            recommendations.append({
                'category': 'Credential Security',
                'priority': 'HIGH',
                'title': 'Secure Credential Management',
                'description': 'Remove hardcoded credentials from source code',
                'action_items': [
                    'Move secrets to environment variables',
                    'Use secure credential management systems',
                    'Rotate any exposed credentials immediately'
                ]
            })
        
        # Recommendations based on similar vulnerabilities
        if matches:
            bias_matches = [m for m in matches if 'bias' in m.get('description', '').lower()]
            if bias_matches:
                recommendations.append({
                    'category': 'AI Ethics',
                    'priority': 'MEDIUM',
                    'title': 'Implement Bias Testing',
                    'description': 'Add fairness evaluation to prevent discriminatory outcomes',
                    'action_items': [
                        'Test models with datasets like BOLD or WinoBias',
                        'Implement continuous bias monitoring',
                        'Document fairness evaluation procedures'
                    ]
                })
        
        # Framework-specific recommendations
        frameworks = scan_results.get('frameworks', [])
        if 'HuggingFace' in frameworks:
            recommendations.append({
                'category': 'Model Security',
                'priority': 'MEDIUM',
                'title': 'HuggingFace Security Best Practices',
                'description': 'Follow security guidelines for HuggingFace models',
                'action_items': [
                    'Verify model sources and signatures',
                    'Use model cards to understand limitations',
                    'Implement model versioning and rollback procedures'
                ]
            })
        
        return recommendations
    
    def _format_similar_incidents(self, matches: List[Dict]) -> List[Dict]:
        """Format similar incidents for the report"""
        
        incidents = []
        
        for match in matches:
            incident = {
                'source': match.get('source', 'Unknown'),
                'title': match.get('title', 'Untitled'),
                'description': match.get('description', '')[:150] + '...',
                'relevance_score': round(match.get('relevance_score', 0), 3),
                'severity': match.get('severity', 'MEDIUM'),
                'vulnerability_id': match.get('vulnerability_id', ''),
                'affected_models': match.get('affected_models', [])[:3]  # Limit to first 3
            }
            incidents.append(incident)
        
        return incidents
    
    def export_report(self, report: Dict, format: str = 'json', output_path: str = None) -> str:
        """Export report to file"""
        
        if format.lower() == 'json':
            content = json.dumps(report, indent=2, default=str)
            extension = '.json'
        else:
            # Simple text format
            content = self._format_text_report(report)
            extension = '.txt'
        
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f'argus_security_report_{timestamp}{extension}'
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        return output_path
    
    def _format_text_report(self, report: Dict) -> str:
        """Format report as readable text"""
        
        text = f"""
ARGUS AI SECURITY ASSESSMENT REPORT
Generated: {report['report_metadata']['generated_at']}

EXECUTIVE SUMMARY
Risk Level: {report['risk_assessment']['risk_level']}
Overall Score: {report['risk_assessment']['overall_score']}/10
Confidence: {report['risk_assessment']['confidence']}

REPOSITORY ANALYSIS
Files Scanned: {report['repository_analysis']['files_scanned']}
Frameworks: {', '.join(report['repository_analysis']['frameworks_detected'])}
Patterns Found: {report['repository_analysis']['patterns_detected']}
High-Risk Patterns: {report['repository_analysis']['high_risk_patterns']}

RECOMMENDATIONS
"""
        
        for i, rec in enumerate(report['recommendations'], 1):
            text += f"{i}. [{rec['priority']}] {rec['title']}\n"
            text += f"   {rec['description']}\n\n"
        
        return text