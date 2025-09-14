from processor import DataProcessor
import os
from pathlib import Path

def run_complete_test():
    """Test both Excel and AVID data processing"""
    
    print("=== Argus Data Loading Test ===")
    
    processor = DataProcessor()
    
    # File paths
    excel_path = "../ai_risk_report.xlsx"  # Your uploaded file
    avid_path = "../avid-db"
    
    # Check file existence
    print(f"Checking files...")
    print(f"Excel file exists: {os.path.exists(excel_path)}")
    print(f"AVID repo exists: {os.path.exists(avid_path)}")
    
    if os.path.exists(avid_path):
        reports_dir = f"{avid_path}/reports"
        json_files = []
        if os.path.exists(reports_dir):
            json_files = list(Path(reports_dir).rglob('AVID-*.json'))
        print(f"Found {len(json_files)} AVID JSON files")
    
    # Load knowledge base
    print(f"\nLoading knowledge base...")
    total_docs = processor.load_knowledge_base(
        excel_path=excel_path if os.path.exists(excel_path) else None,
        avid_repo_path=avid_path if os.path.exists(avid_path) else None
    )
    
    if total_docs > 0:
        print(f"\n✅ SUCCESS: Loaded {total_docs} documents total")
        
        # Test semantic search with different queries
        test_queries = [
            "model loading security vulnerability",
            "AI bias in language models",
            "adversarial attack on neural networks",
            "data poisoning machine learning",
            "fairness evaluation AI systems"
        ]
        
        print(f"\n=== Testing Semantic Search ===")
        for i, query in enumerate(test_queries, 1):
            print(f"\n{i}. Query: '{query}'")
            try:
                results = processor.vector_store.search_similar_vulnerabilities(query, k=3)
                for j, result in enumerate(results, 1):
                    source = result.metadata.get('source', 'Unknown')
                    severity = result.metadata.get('severity', 'N/A')
                    print(f"   {j}. [{source}] {result.document[:80]}...")
                    print(f"      Distance: {result.distance:.4f}, Severity: {severity}")
            except Exception as e:
                print(f"   Error searching: {e}")
                
    else:
        print("\n❌ FAILED: No documents loaded")
        print("Check that your files are in the right location:")
        print(f"  - Excel file: {excel_path}")
        print(f"  - AVID repo: {avid_path}")

if __name__ == "__main__":
    run_complete_test()