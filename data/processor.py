import pandas as pd
import json
from pathlib import Path
import uuid
from vector_store import ArgusVectorStore

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
                    "id": f"mit-{uuid.uuid4()}",
                    "id": self.vector_store.generate_short_id("mit", title),
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
                if processed_count >= 500:  # Process first 500 for testing
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
        
        # Use rglob to search recursively through all subdirectories
        for json_file in reports_dir.rglob('AVID-*.json'):
            try:
                with open(json_file, 'r') as f:
                    report = json.load(f)
                
                # Extract key information
                report_id = report.get('metadata', {}).get('report_id', str(json_file.stem))
                problem_desc = report.get('problemtype', {}).get('description', {}).get('value', '')
                full_desc = report.get('description', {}).get('value', '')
                problem_class = report.get('problemtype', {}).get('classof', '')
                
                # Extract affected models and datasets
                models = []
                datasets = []
                for artifact in report.get('affects', {}).get('artifacts', []):
                    if artifact.get('type') == 'Model':
                        models.append(artifact.get('name', ''))
                    elif artifact.get('type') == 'Dataset':
                        datasets.append(artifact.get('name', ''))
                
                # Extract other metadata
                developers = report.get('affects', {}).get('developer', [])
                deployers = report.get('affects', {}).get('deployer', [])
                risk_domains = report.get('impact', {}).get('avid', {}).get('risk_domain', [])
                vuln_id = report.get('impact', {}).get('avid', {}).get('vuln_id', '')
                
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
                    "id": self.vector_store.generate_short_id("avid", report_id),
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
        """Load all data sources into the vector store"""
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
        
        print(f"Storing {len(all_documents)} documents in TiDB Vector Search...")
        
        try:
            # Insert in batches to avoid memory issues
            batch_size = 100
            for i in range(0, len(all_documents), batch_size):
                batch = all_documents[i:i+batch_size]
                
                self.vector_store.vulnerability_store.insert(
                    ids=[doc["id"] for doc in batch],
                    texts=[doc["text"] for doc in batch], 
                    embeddings=[doc["embedding"] for doc in batch],
                    metadatas=[doc["metadata"] for doc in batch],
                )
                
                print(f"Inserted batch {i//batch_size + 1}: {len(batch)} documents")
            
            print(f"Successfully loaded {len(all_documents)} documents into knowledge base")
            return len(all_documents)
            
        except Exception as e:
            print(f"Error storing documents: {e}")
            import traceback
            traceback.print_exc()
            return 0
