# agents/test_agents.py
import sys
import os
sys.path.append('..')

from scanner import RepositoryScanner
from analyzer import VulnerabilityAnalyzer  
from reporter import ReportGenerator

def test_agents():
    """Test the complete multi-agent workflow"""
    
    print("=== Testing Multi-Agent System ===")
    
    # Initialize agents
    scanner = RepositoryScanner()
    analyzer = VulnerabilityAnalyzer()
    reporter = ReportGenerator()
    
    # Test repository (use current directory as example)
    test_repo = "../"  # Scan the argus project itself
    
    print(f"\n1. Testing Repository Scanner...")
    scan_results = scanner.scan_repository(test_repo)
    
    if 'error' in scan_results:
        print(f"Scanner Error: {scan_results['error']}")
        return
    
    print(f"   Frameworks detected: {scan_results['frameworks']}")
    print(f"   Files scanned: {scan_results['file_count']}")
    print(f"   Patterns found: {len(scan_results['code_patterns'])}")
    print(f"   Risk indicators: {scan_results['risk_indicators']}")
    
    print(f"\n2. Testing Vulnerability Analyzer...")
    vulnerability_matches = analyzer.analyze_patterns(scan_results)
    
    print(f"   Similar vulnerabilities found: {len(vulnerability_matches)}")
    if vulnerability_matches:
        print("   Top matches:")
        for i, match in enumerate(vulnerability_matches[:3], 1):
            print(f"     {i}. [{match['source']}] {match['title'][:60]}...")
            print(f"        Relevance: {match['relevance_score']:.3f}")
    
    print(f"\n3. Testing Report Generator...")
    report = reporter.generate_report(scan_results, vulnerability_matches)
    
    print(f"   Risk Level: {report['risk_assessment']['risk_level']}")
    print(f"   Risk Score: {report['risk_assessment']['overall_score']}/10")
    print(f"   Recommendations: {len(report['recommendations'])}")
    
    # Export report
    report_file = reporter.export_report(report, format='json')
    print(f"   Report exported to: {report_file}")
    
    print(f"\n✅ Multi-agent system test completed successfully!")
    
    return {
        'scan_results': scan_results,
        'vulnerability_matches': vulnerability_matches,
        'report': report
    }

if __name__ == "__main__":
    test_agents()