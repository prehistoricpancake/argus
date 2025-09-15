from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import sys
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.append('..')
from agents.scanner import RepositoryScanner
from agents.analyzer import VulnerabilityAnalyzer
from agents.reporter import ReportGenerator

app = FastAPI(title="Argus AI Security Scanner", version="1.0.0")

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize agents (will be loaded once at startup)
scanner = None
analyzer = None
reporter = None

@app.on_event("startup")
async def startup_event():
    """Initialize agents on startup"""
    global scanner, analyzer, reporter
    try:
        print("Initializing Argus agents...")
        scanner = RepositoryScanner()
        analyzer = VulnerabilityAnalyzer()
        reporter = ReportGenerator()
        print("Agents initialized successfully")
        
        # Test scan
        test_results = scanner.scan_repository('../')
        print(f"Test scan found {test_results.get('file_count', 0)} files")
        
    except Exception as e:
        print(f"Error initializing agents: {e}")
        import traceback
        traceback.print_exc()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "agents_loaded": scanner is not None}

@app.post("/api/scan")
async def scan_repository(
    repository_url: str = Form(...),
    scan_local_path: str = Form(default="")
):
    """Scan a repository and return security analysis"""
    
    if not scanner or not analyzer or not reporter:
        raise HTTPException(status_code=500, detail="Agents not initialized")
    
    try:
        # Determine scan target
        if scan_local_path:
            # Scan local directory
            repo_path = scan_local_path
            if not os.path.exists(repo_path):
                raise HTTPException(status_code=400, detail=f"Local path does not exist: {repo_path}")
        else:
            # Clone repository to temporary directory
            repo_path = await clone_repository(repository_url)
        
        # Run multi-agent analysis
        print(f"Scanning repository: {repo_path}")
        
        # Step 1: Repository scanning
        scan_results = scanner.scan_repository(repo_path)
        if 'error' in scan_results:
            raise HTTPException(status_code=400, detail=scan_results['error'])
        
        # Step 2: Vulnerability analysis using vector search
        vulnerability_matches = analyzer.analyze_patterns(scan_results)
        
        # Step 3: Report generation
        report = reporter.generate_report(scan_results, vulnerability_matches)
        
        # Cleanup temporary directory if it was a cloned repo
        if not scan_local_path and repo_path.startswith('/tmp'):
            shutil.rmtree(repo_path, ignore_errors=True)
        
        return {
            "status": "success",
            "scan_results": scan_results,
            "vulnerability_matches": vulnerability_matches[:10],  # Limit for response size
            "report": report
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/api/demo-scan")
async def demo_scan():
    """Demo scan using the argus project itself"""
    
    if not scanner or not analyzer or not reporter:
        raise HTTPException(status_code=500, detail="Agents not initialized")
    
    try:
        # Scan the parent directory (argus project)
        repo_path = ".."
        
        print(f"Scanning path: {repo_path}")
        scan_results = scanner.scan_repository(repo_path)
        print(f"Scan results: {scan_results}")
        
        vulnerability_matches = analyzer.analyze_patterns(scan_results)
        print(f"Vulnerability matches: {len(vulnerability_matches)}")
        
        report = reporter.generate_report(scan_results, vulnerability_matches)
        print(f"Report generated: {report.keys()}")
        
        return {
            "status": "success",
            "demo": True,
            "scan_results": scan_results,
            "vulnerability_matches": vulnerability_matches[:5],
            "report": report
        }
        
    except Exception as e:
        print(f"Demo scan error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Demo scan failed: {str(e)}")
@app.get("/api/check-vector-store")
async def check_vector_store():
    """Check if the vector store has data"""
    
    try:
        from data.vector_store import ArgusVectorStore
        
        # Test vector store connection
        vector_store = ArgusVectorStore()
        
        # Try a simple search to see if there's any data
        test_results = vector_store.search_similar_vulnerabilities("test", k=1)
        
        result = {
            "status": "success",
            "vector_store_initialized": True,
            "has_data": len(test_results) > 0,
            "sample_results_count": len(test_results)
        }
        
        if test_results:
            first_result = test_results[0]
            result["sample_result"] = {
                "distance": getattr(first_result, 'distance', 'unknown'),
                "document_preview": getattr(first_result, 'document', '')[:100],
                "metadata_source": getattr(first_result, 'metadata', {}).get('source', 'unknown')
            }
        
        return result
        
    except Exception as e:
        import traceback
        return {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }


# Add this endpoint to populate your vector store if it's empty
@app.post("/api/populate-vector-store")
async def populate_vector_store():
    """Populate the vector store with data from your local files"""
    
    try:
        # Import from the data directory
        import sys
        sys.path.append('..')
        from data.processor import DataProcessor
        
        processor = DataProcessor()
        
        # Use absolute paths to find your data files
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        
        excel_path = os.path.join(project_root, "ai_risk_report.xlsx")
        avid_path = os.path.join(project_root, "avid-db")
        
        print(f"Looking for files:")
        print(f"  Excel: {excel_path} (exists: {os.path.exists(excel_path)})")
        print(f"  AVID: {avid_path} (exists: {os.path.exists(avid_path)})")
        
        # Load data into vector store
        total_docs = processor.load_knowledge_base(
            excel_path=excel_path if os.path.exists(excel_path) else None,
            avid_repo_path=avid_path if os.path.exists(avid_path) else None
        )
        
        return {
            "status": "success",
            "documents_loaded": total_docs,
            "excel_path": excel_path,
            "avid_path": avid_path,
            "excel_exists": os.path.exists(excel_path),
            "avid_exists": os.path.exists(avid_path)
        }
        
    except Exception as e:
        import traceback
        return {
            "status": "error", 
            "error": str(e),
            "traceback": traceback.format_exc()
        }

@app.post("/api/export-pdf")
async def export_pdf(scan_data: dict):
    """Export scan results as PDF"""
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1*inch)
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#1f2937')
    )
    
    # Title
    story.append(Paragraph("Argus AI Security Assessment Report", title_style))
    story.append(Spacer(1, 20))
    
    # Executive Summary
    report = scan_data.get('report', {})
    risk_assessment = report.get('risk_assessment', {})
    
    story.append(Paragraph("Executive Summary", heading_style))
    
    summary_data = [
        ['Risk Level', risk_assessment.get('risk_level', 'Unknown')],
        ['Risk Score', f"{risk_assessment.get('overall_score', 0)}/10"],
        ['Confidence', risk_assessment.get('confidence', 'Unknown')],
        ['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Repository Analysis
    scan_results = scan_data.get('scan_results', {})
    repo_analysis = report.get('repository_analysis', {})
    
    story.append(Paragraph("Repository Analysis", heading_style))
    
    repo_data = [
        ['Files Scanned', str(scan_results.get('file_count', 0))],
        ['Frameworks Detected', ', '.join(scan_results.get('frameworks', []))],
        ['Security Patterns Found', str(len(scan_results.get('code_patterns', [])))],
        ['High-Risk Patterns', str(len([p for p in scan_results.get('code_patterns', []) if p.get('severity') == 'HIGH']))]
    ]
    
    repo_table = Table(repo_data, colWidths=[2*inch, 3*inch])
    repo_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(repo_table)
    story.append(Spacer(1, 20))
    
    # Security Patterns (show top 10)
    patterns = scan_results.get('code_patterns', [])[:10]
    if patterns:
        story.append(Paragraph("Security Patterns Found", heading_style))
        
        for i, pattern in enumerate(patterns, 1):
            pattern_text = f"<b>{i}. {pattern.get('description', 'Security Pattern')}</b><br/>"
            pattern_text += f"File: {pattern.get('file', 'Unknown')}<br/>"
            pattern_text += f"Severity: {pattern.get('severity', 'MEDIUM')}<br/>"
            pattern_text += f"Context: {pattern.get('context', 'No context')[:100]}..."
            
            story.append(Paragraph(pattern_text, styles['Normal']))
            story.append(Spacer(1, 10))
    
    # Recommendations
    recommendations = report.get('recommendations', [])
    if recommendations:
        story.append(Paragraph("Security Recommendations", heading_style))
        
        for i, rec in enumerate(recommendations, 1):
            rec_text = f"<b>{i}. [{rec.get('priority', 'MEDIUM')}] {rec.get('title', 'Recommendation')}</b><br/>"
            rec_text += f"{rec.get('description', 'No description')}<br/>"
            
            if rec.get('action_items'):
                rec_text += "Action Items:<br/>"
                for item in rec['action_items']:
                    rec_text += f"• {item}<br/>"
            
            story.append(Paragraph(rec_text, styles['Normal']))
            story.append(Spacer(1, 15))
    
    # Build PDF
    doc.build(story)
    
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=argus_security_report.pdf"}
    )

async def clone_repository(repo_url: str) -> str:
    """Clone a Git repository to a temporary directory"""
    
    # Basic URL validation
    if not repo_url.startswith(('https://github.com', 'https://gitlab.com')):
        raise HTTPException(status_code=400, detail="Only GitHub and GitLab repositories are supported")
    
    # Create temporary directory
    temp_base = tempfile.mkdtemp(prefix="argus_scan_")
    
    # Extract repo name from URL for the clone directory
    repo_name = repo_url.split('/')[-1].replace('.git', '')
    clone_path = os.path.join(temp_base, repo_name)
    
    try:
        print(f"Cloning {repo_url} to {clone_path}")
        
        # Clone repository (shallow clone for speed)
        result = subprocess.run([
            'git', 'clone', '--depth', '1', repo_url, clone_path
        ], capture_output=True, text=True, timeout=120)  # Increased timeout
        
        if result.returncode != 0:
            print(f"Git clone failed: {result.stderr}")
            shutil.rmtree(temp_base, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Failed to clone repository: {result.stderr}")
        
        # Verify the clone worked
        if not os.path.exists(clone_path) or not os.listdir(clone_path):
            shutil.rmtree(temp_base, ignore_errors=True)
            raise HTTPException(status_code=400, detail="Repository appears to be empty or clone failed")
        
        print(f"Successfully cloned to {clone_path}")
        print(f"Directory contents: {os.listdir(clone_path)[:10]}")  # Show first 10 files
        
        return clone_path
        
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_base, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Repository clone timed out")
    except Exception as e:
        print(f"Clone exception: {e}")
        shutil.rmtree(temp_base, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Clone failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# if __name__ == '__main__':
#     import os
#     port = int(os.environ.get('PORT', 5000))
#     # app.run(host='0.0.0.0', port=port, debug=False)