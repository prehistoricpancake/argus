import pandas as pd
import json
from pathlib import Path
import uuid
import time
from .vector_store import ArgusVectorStore

class DataProcessor:
    def __init__(self):
        self.vector_store = ArgusVectorStore()
        
    def process_excel_file(self, excel_path):
        """Process your uploaded Excel file (ai_risk_report.xlsx)"""
        print(f"Processing Excel file: {excel_path}")
        
        try:
            # Read the AI Risk Database sheet with header at row 2 (0-indexed)
            df = pd.read_excel(excel_path, sheet_name='AI Risk Database v3', header=2)
            print(f"Loaded {len(df)} rows from Excel")
            
            documents = []
            processed_count = 0
            
            for idx, row in df.iterrows():
                # Skip empty rows or rows with no title
                title = str(row.iloc[0]) if pd.notna(row.iloc[0]) else ""
                if not title or title.strip() == '' or title == 'nan':
                    continue
                
                # Extract fields based on column positions from analysis
                risk_category = str(row.iloc[8]) if len(row) > 8 and pd.notna(row.iloc[8]) else ""
                risk_subcategory = str(row.iloc[9]) if len(row) > 9 and pd.notna(row.iloc[9]) else ""
                description = str(row.iloc[10]) if len(row) > 10 and pd.notna(row.iloc[10]) else ""
                domain = str(row.iloc[17]) if len(row) > 17 and pd.notna(row.iloc[17]) else ""
                subdomain = str(row.iloc[18]) if len(row) > 18 and pd.notna(row.iloc[18]) else ""
                entity = str(row.iloc[14]) if len(row) > 14 and pd.notna(row.iloc[14]) else ""
                intent = str(row.iloc[15]) if len(row) > 15 and pd.notna(row.iloc[15]) else ""
                timing = str(row.iloc[16]) if len(row) > 16 and pd.notna(row.iloc[16]) else ""
                
                # Create rich text for embedding
                text_content = f"AI Risk: {title}"
                
                if risk_category and risk_category != 'nan':
                    text_content += f" | Category: {risk_category}"
                    
                if risk_subcategory and risk_subcategory != 'nan':
                    text_content += f" | Subcategory: {risk_subcategory}"
                    
                if description and description != 'nan':
                    # Limit description length for embedding
                    desc_text = description[:300] + "..." if len(description) > 300 else description
                    text_content += f" | Description: {desc_text}"
                    
                if domain and domain != 'nan':
                    text_content += f" | Domain: {domain}"
                    
                if subdomain and subdomain != 'nan':
                    text_content += f" | Subdomain: {subdomain}"
                
                # Determine severity from risk category
                severity = self._determine_severity(risk_category, description)
                
                doc = {
                    "id": f"mit-{uuid.uuid4().hex[:12]}",
                    "text": text_content,
                    "embedding": self.vector_store.text_to_embedding(text_content),
                    "metadata": {
                        "source": "MIT",
                        "title": title,
                        "risk_category": risk_category,
                        "risk_subcategory": risk_subcategory,
                        "domain": domain,
                        "subdomain": subdomain,
                        "entity": entity,
                        "intent": intent,
                        "timing": timing,
                        "severity": severity,
                        "type": "risk_taxonomy"
                    }
                }
                documents.append(doc)
                processed_count += 1
                
                # Print progress every 100 entries
                if processed_count % 100 == 0:
                    print(f"Processed {processed_count} MIT risks...")
                    
                # Limit for testing (remove this for full processing)
                if processed_count >= 100:  # Reduced for faster testing
                    break
            
            print(f"Successfully processed {len(documents)} MIT risk entries")
            return documents
            
        except Exception as e:
            print(f"Error processing Excel file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def process_avid_reports(self, avid_repo_path):
        """Process AVID JSON reports from nested directory structure"""
        print(f"Processing AVID reports from: {avid_repo_path}")
        
        reports_dir = Path(avid_repo_path) / 'reports'
        if not reports_dir.exists():
            print(f"AVID reports directory not found: {reports_dir}")
            return []
        
        documents = []
        processed_count = 0
        
        # Use rglob to search recursively through all subdirectories
        for json_file in reports_dir.rglob('AVID-*.json'):
            try:
                # Limit for faster testing
                if processed_count >= 20:
                    break
                    
                with open(json_file, 'r') as f:
                    report = json.load(f)
                
                # Extract key information - handle missing fields gracefully
                report_id = report.get('metadata', {}).get('report_id', str(json_file.stem))
                
                problemtype = report.get('problemtype')
                if problemtype and problemtype.get('description'):
                    problem_desc = problemtype.get('description', {}).get('value', '')
                else:
                    problem_desc = ''
                
                description = report.get('description')
                if description:
                    full_desc = description.get('value', '')
                else:
                    full_desc = ''
                
                if problemtype:
                    problem_class = problemtype.get('classof', '')
                else:
                    problem_class = ''
                
                # Extract affected models and datasets
                models = []
                datasets = []
                affects = report.get('affects', {})
                if affects and affects.get('artifacts'):
                    for artifact in affects.get('artifacts', []):
                        if artifact.get('type') == 'Model':
                            models.append(artifact.get('name', ''))
                        elif artifact.get('type') == 'Dataset':
                            datasets.append(artifact.get('name', ''))
                
                # Extract other metadata
                developers = affects.get('developer', []) if affects else []
                deployers = affects.get('deployer', []) if affects else []
                
                impact = report.get('impact', {})
                avid_impact = impact.get('avid', {}) if impact else {}
                risk_domains = avid_impact.get('risk_domain', []) if avid_impact else []
                vuln_id = avid_impact.get('vuln_id', '') if avid_impact else ''
                
                # Create rich text for embedding
                text_content = f"AI Vulnerability Report: {problem_desc}"
                
                if full_desc:
                    desc_text = full_desc[:400] + "..." if len(full_desc) > 400 else full_desc
                    text_content += f" | Details: {desc_text}"
                    
                if models:
                    text_content += f" | Affected Models: {', '.join(models[:5])}"  # Limit to first 5
                    
                if datasets:
                    text_content += f" | Datasets: {', '.join(datasets[:3])}"  # Limit to first 3
                    
                if risk_domains:
                    text_content += f" | Risk Domains: {', '.join(risk_domains)}"
                
                doc = {
                    "id": f"avid-{uuid.uuid4().hex[:12]}",
                    "text": text_content,
                    "embedding": self.vector_store.text_to_embedding(text_content),
                    "metadata": {
                        "source": "AVID",
                        "report_id": report_id,
                        "problem_class": problem_class,
                        "affected_models": models,
                        "affected_datasets": datasets,
                        "developers": developers,
                        "deployers": deployers,
                        "risk_domains": risk_domains,
                        "vulnerability_id": vuln_id,
                        "year": json_file.parent.name,
                        "severity": "HIGH",  # AVID reports are generally high severity
                        "type": "vulnerability_report"
                    }
                }
                documents.append(doc)
                processed_count += 1
                
            except Exception as e:
                print(f"Error processing {json_file}: {e}")
                continue
        
        print(f"Successfully processed {len(documents)} AVID reports")
        return documents
    
    def _determine_severity(self, risk_category, description):
        """Determine severity level from risk category and description"""
        if not risk_category or risk_category == 'nan':
            return "MEDIUM"
            
        risk_text = (risk_category + " " + str(description)).lower()
        
        high_risk_keywords = [
            'harm', 'attack', 'adversarial', 'manipulation', 'weaponization',
            'discrimination', 'bias', 'privacy violation', 'security breach'
        ]
        
        medium_risk_keywords = [
            'performance', 'accuracy', 'reliability', 'fairness', 'transparency'
        ]
        
        if any(keyword in risk_text for keyword in high_risk_keywords):
            return "HIGH"
        elif any(keyword in risk_text for keyword in medium_risk_keywords):
            return "MEDIUM"
        else:
            return "MEDIUM"  # Default
    
    def load_knowledge_base(self, excel_path=None, avid_repo_path=None):
        """Load all data sources into the vector store using raw SQL"""
        all_documents = []
        
        # Process Excel file if provided
        if excel_path and Path(excel_path).exists():
            excel_docs = self.process_excel_file(excel_path)
            all_documents.extend(excel_docs)
        else:
            print(f"Excel file not found: {excel_path}")
        
        # Process AVID data if provided  
        if avid_repo_path and Path(avid_repo_path).exists():
            avid_docs = self.process_avid_reports(avid_repo_path)
            all_documents.extend(avid_docs)
        else:
            print(f"AVID repository not found: {avid_repo_path}")
        
        if not all_documents:
            print("No documents to load!")
            return 0
        
        print(f"Storing {len(all_documents)} documents in TiDB Vector Search using raw SQL...")
        
        successful_inserts = 0
        failed_inserts = 0
        
        # Insert documents using the raw SQL method
        for i, doc in enumerate(all_documents):
            try:
                # Validate document
                if not doc.get("id") or not doc.get("text") or not doc.get("embedding"):
                    print(f"Skipping invalid document {i+1}")
                    failed_inserts += 1
                    continue
                
                # Insert using raw SQL method
                success = self.vector_store.insert_document(
                    doc["id"],
                    doc["text"],
                    doc["embedding"],
                    doc["metadata"]
                )
                
                if success:
                    successful_inserts += 1
                else:
                    failed_inserts += 1
                
                # Progress reporting
                if (i + 1) % 25 == 0:
                    print(f"Progress: {i + 1}/{len(all_documents)} processed, {successful_inserts} successful, {failed_inserts} failed")
                    
            except Exception as e:
                print(f"Error processing document {i+1}: {e}")
                failed_inserts += 1
                continue
        
        print(f"Insertion completed: {successful_inserts} successful, {failed_inserts} failed")
        
        if successful_inserts == 0:
            print("No documents were successfully inserted!")
            return 0
        
        # Verify insertion with document count
        print("Verifying insertion...")
        doc_count = self.vector_store.count_documents()
        print(f"Total documents in database: {doc_count}")
        
        # Test sample documents
        samples = self.vector_store.get_sample_documents(3)
        print(f"Sample documents: {len(samples)}")
        for sample in samples:
            print(f"  - {sample[0]}: {sample[1]}")
        
        # Test vector search functionality
        print("Testing vector search...")
        test_queries = ["tensorflow security", "AI bias", "machine learning vulnerability"]
        
        for query in test_queries:
            try:
                results = self.vector_store.search_similar_vulnerabilities(query, k=2)
                print(f"Query '{query}': {len(results)} results")
                if results:
                    print(f"  Top result: {results[0]['document'][:80]}...")
            except Exception as e:
                print(f"Search failed for '{query}': {e}")
        
        print(f"✅ TiDB Vector Search setup completed with {successful_inserts} documents")
        return successful_inserts