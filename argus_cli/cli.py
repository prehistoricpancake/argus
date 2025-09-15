"""
Argus AI Security Scanner CLI
Main entry point for the command-line interface
"""

import click
import os
import sys
import tempfile
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

# Add the current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from agents.scanner import RepositoryScanner
from agents.analyzer import VulnerabilityAnalyzer
from agents.reporter import ReportGenerator
from data.processor import DataProcessor


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    Argus AI Security Scanner - AI-powered security analysis for ML projects
    
    Scan repositories for AI/ML security vulnerabilities and get detailed reports.
    """
    pass


@cli.command()
@click.argument('target', required=True)
@click.option('--output', '-o', default=None, help='Output file path for the report')
@click.option('--format', '-f', type=click.Choice(['json', 'pdf', 'txt']), default='json', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--temp-dir', default=None, help='Custom temporary directory for clones')
def scan(target, output, format, verbose, temp_dir):
    """
    Scan a repository or local directory for AI/ML security vulnerabilities.
    
    TARGET can be:
    - A GitHub/GitLab URL (https://github.com/user/repo)
    - A local directory path (/path/to/repo)
    """
    
    if verbose:
        click.echo(f"🔍 Argus AI Security Scanner v1.0.0")
        click.echo(f"Target: {target}")
        click.echo(f"Output format: {format}")
    
    try:
        # Initialize agents
        if verbose:
            click.echo("🤖 Initializing AI agents...")
        
        scanner = RepositoryScanner()
        analyzer = VulnerabilityAnalyzer()
        reporter = ReportGenerator()
        
        # Determine if target is URL or local path
        if target.startswith(('https://github.com', 'https://gitlab.com')):
            if verbose:
                click.echo(f"📥 Cloning repository: {target}")
            repo_path = clone_repository(target, temp_dir, verbose)
            cleanup_needed = True
        elif os.path.exists(target):
            repo_path = target
            cleanup_needed = False
            if verbose:
                click.echo(f"📁 Scanning local directory: {repo_path}")
        else:
            raise click.ClickException(f"Target not found or invalid: {target}")
        
        # Run the scan
        if verbose:
            click.echo("🔍 Step 1: Scanning repository for code patterns...")
        scan_results = scanner.scan_repository(repo_path)
        
        if 'error' in scan_results:
            raise click.ClickException(f"Scan failed: {scan_results['error']}")
        
        if verbose:
            click.echo(f"   Found {scan_results.get('file_count', 0)} files")
            click.echo(f"   Detected frameworks: {', '.join(scan_results.get('frameworks', []))}")
            click.echo(f"   Found {len(scan_results.get('code_patterns', []))} security patterns")
        
        if verbose:
            click.echo("🔍 Step 2: Analyzing with AI vulnerability database...")
        vulnerability_matches = analyzer.analyze_patterns(scan_results)
        
        if verbose:
            click.echo(f"   Found {len(vulnerability_matches)} similar vulnerabilities")
        
        if verbose:
            click.echo("📊 Step 3: Generating security report...")
        report = reporter.generate_report(scan_results, vulnerability_matches)
        
        # Generate output
        if not output:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            repo_name = os.path.basename(repo_path) if cleanup_needed else os.path.basename(os.path.abspath(repo_path))
            output = f"argus_report_{repo_name}_{timestamp}.{format}"
        
        # Save report
        if format == 'json':
            save_json_report(report, scan_results, vulnerability_matches, output)
        elif format == 'pdf':
            save_pdf_report(report, scan_results, vulnerability_matches, output)
        elif format == 'txt':
            save_text_report(report, output)
        
        # Cleanup
        if cleanup_needed:
            cleanup_temp_directory(repo_path, verbose)
        
        # Display summary
        risk_level = report.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        risk_score = report.get('risk_assessment', {}).get('overall_score', 0)
        
        click.echo("\n" + "="*60)
        click.echo("🛡️  ARGUS SECURITY SCAN COMPLETE")
        click.echo("="*60)
        click.echo(f"Risk Level: {risk_level}")
        click.echo(f"Risk Score: {risk_score}/10")
        click.echo(f"Files Scanned: {scan_results.get('file_count', 0)}")
        click.echo(f"Security Patterns: {len(scan_results.get('code_patterns', []))}")
        click.echo(f"Similar Vulnerabilities: {len(vulnerability_matches)}")
        click.echo(f"Report saved: {output}")
        click.echo("="*60)
        
    except Exception as e:
        if verbose:
            import traceback
            traceback.print_exc()
        raise click.ClickException(f"Scan failed: {str(e)}")


@cli.command()
@click.option('--excel-path', default='ai_risk_report.xlsx', help='Path to Excel risk database')
@click.option('--avid-path', default='avid-db', help='Path to AVID vulnerability database')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def setup(excel_path, avid_path, verbose):
    """
    Set up the Argus vulnerability database by loading data into TiDB Vector Store.
    
    This command loads your AI risk taxonomy and AVID vulnerability data
    into the vector database for similarity search.
    """
    
    if verbose:
        click.echo("🔧 Setting up Argus vulnerability database...")
    
    try:
        processor = DataProcessor()
        
        # Check if files exist
        excel_exists = os.path.exists(excel_path)
        avid_exists = os.path.exists(avid_path)
        
        if verbose:
            click.echo(f"Excel database: {excel_path} ({'✓' if excel_exists else '✗'})")
            click.echo(f"AVID database: {avid_path} ({'✓' if avid_exists else '✗'})")
        
        if not excel_exists and not avid_exists:
            raise click.ClickException("No data sources found. Please check your file paths.")
        
        # Load data
        total_docs = processor.load_knowledge_base(
            excel_path=excel_path if excel_exists else None,
            avid_repo_path=avid_path if avid_exists else None
        )
        
        if total_docs > 0:
            click.echo(f"✅ Successfully loaded {total_docs} vulnerability records into database")
            click.echo("🚀 Argus is ready to scan repositories!")
        else:
            raise click.ClickException("Failed to load vulnerability data")
            
    except Exception as e:
        if verbose:
            import traceback
            traceback.print_exc()
        raise click.ClickException(f"Setup failed: {str(e)}")


@cli.command()
def check():
    """
    Check the status of the Argus vector database.
    """
    
    try:
        from data.vector_store import ArgusVectorStore
        
        click.echo("🔍 Checking Argus vector database...")
        
        vector_store = ArgusVectorStore()
        test_results = vector_store.search_similar_vulnerabilities("test", k=1)
        
        if test_results:
            click.echo("✅ Vector database is operational")
            click.echo(f"📊 Sample results found: {len(test_results)}")
            sample = test_results[0]
            source = getattr(sample, 'metadata', {}).get('source', 'Unknown')
            click.echo(f"🔬 Sample source: {source}")
        else:
            click.echo("⚠️  Vector database is empty")
            click.echo("💡 Run 'argus setup' to populate the database")
            
    except Exception as e:
        click.echo(f"❌ Vector database check failed: {str(e)}")
        click.echo("💡 Make sure your TiDB connection is configured correctly")


def clone_repository(repo_url: str, temp_dir: str = None, verbose: bool = False) -> str:
    """Clone a Git repository to a temporary directory"""
    
    if temp_dir:
        base_temp = temp_dir
    else:
        base_temp = tempfile.mkdtemp(prefix="argus_scan_")
    
    repo_name = repo_url.split('/')[-1].replace('.git', '')
    clone_path = os.path.join(base_temp, repo_name)
    
    try:
        if verbose:
            click.echo(f"   Cloning to: {clone_path}")
        
        result = subprocess.run([
            'git', 'clone', '--depth', '1', repo_url, clone_path
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            raise Exception(f"Git clone failed: {result.stderr}")
        
        if not os.path.exists(clone_path) or not os.listdir(clone_path):
            raise Exception("Repository appears to be empty")
        
        return clone_path
        
    except subprocess.TimeoutExpired:
        raise Exception("Repository clone timed out")
    except Exception as e:
        if os.path.exists(base_temp):
            shutil.rmtree(base_temp, ignore_errors=True)
        raise e


def cleanup_temp_directory(repo_path: str, verbose: bool = False):
    """Clean up temporary directory"""
    
    try:
        temp_base = os.path.dirname(repo_path)
        if '/tmp' in temp_base or 'argus_scan_' in temp_base:
            if verbose:
                click.echo(f"🧹 Cleaning up: {temp_base}")
            shutil.rmtree(temp_base, ignore_errors=True)
    except Exception as e:
        if verbose:
            click.echo(f"Warning: Cleanup failed: {e}")


def save_json_report(report, scan_results, vulnerability_matches, output_path):
    """Save report as JSON"""
    
    import json
    
    full_report = {
        "argus_version": "1.0.0",
        "generated_at": datetime.now().isoformat(),
        "scan_results": scan_results,
        "vulnerability_matches": vulnerability_matches,
        "report": report
    }
    
    with open(output_path, 'w') as f:
        json.dump(full_report, f, indent=2, default=str)


def save_pdf_report(report, scan_results, vulnerability_matches, output_path):
    """Save report as PDF (simplified version)"""
    
    # For CLI, we'll save as text first, then you can enhance with reportlab later
    text_path = output_path.replace('.pdf', '.txt')
    save_text_report(report, text_path)
    
    click.echo(f"📄 PDF generation not yet implemented. Text report saved as: {text_path}")


def save_text_report(report, output_path):
    """Save report as readable text"""
    
    text = f"""
ARGUS AI SECURITY ASSESSMENT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
================
Risk Level: {report.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')}
Overall Score: {report.get('risk_assessment', {}).get('overall_score', 0)}/10
Confidence: {report.get('risk_assessment', {}).get('confidence', 'UNKNOWN')}

REPOSITORY ANALYSIS
==================
Files Scanned: {report.get('repository_analysis', {}).get('files_scanned', 0)}
Frameworks: {', '.join(report.get('repository_analysis', {}).get('frameworks_detected', []))}
Patterns Found: {report.get('repository_analysis', {}).get('patterns_detected', 0)}
High-Risk Patterns: {report.get('repository_analysis', {}).get('high_risk_patterns', 0)}

RECOMMENDATIONS
===============
"""
    
    for i, rec in enumerate(report.get('recommendations', []), 1):
        text += f"{i}. [{rec.get('priority', 'MEDIUM')}] {rec.get('title', 'Recommendation')}\n"
        text += f"   {rec.get('description', 'No description')}\n\n"
    
    with open(output_path, 'w') as f:
        f.write(text)


if __name__ == '__main__':
    cli()