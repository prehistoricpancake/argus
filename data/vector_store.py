import os
import json
import hashlib
import pymysql
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
from urllib.parse import urlparse

class ArgusVectorStore:
    def __init__(self):
        load_dotenv()
        
        try:
            self.embed_model = SentenceTransformer('all-MiniLM-L6-v2')
            self.embed_dims = self.embed_model.get_sentence_embedding_dimension()
            print(f"Embedding model loaded: {self.embed_dims} dimensions")
        except Exception as e:
            print(f"Could not load sentence-transformers: {e}")
            self.embed_model = None
            self.embed_dims = 384
        
        # Parse TiDB connection URL
        connection_string = os.environ.get('TIDB_DATABASE_URL')
        self.connection_params = self._parse_connection_string(connection_string)
        self.table_name = 'argus_vulnerabilities_v4'  # New table name
        
        # Test connection and create table
        self._create_table()
        print("Vector store initialized with PyMySQL")

    def _parse_connection_string(self, connection_string):
        """Parse TiDB connection string to PyMySQL parameters"""
        parsed = urlparse(connection_string)
        
        # TiDB Cloud requires SSL
        ssl_params = {}
        if 'tidbcloud.com' in parsed.hostname:
            ssl_params = {
                'ssl_verify_cert': True,
                'ssl_verify_identity': True
            }
        
        return {
            'host': parsed.hostname,
            'port': parsed.port or 4000,
            'user': parsed.username,
            'password': parsed.password,
            'database': parsed.path.lstrip('/'),
            'charset': 'utf8mb4',
            **ssl_params
        }

    def _get_connection(self):
        """Get a new database connection"""
        return pymysql.connect(**self.connection_params)

    def _create_table(self):
        """Create the vector table"""
        create_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.table_name} (
            id VARCHAR(255) PRIMARY KEY,
            document TEXT NOT NULL,
            embedding LONGTEXT NOT NULL,
            metadata TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(create_sql)
            conn.commit()
            cursor.close()
            conn.close()
            print(f"Table {self.table_name} created/verified")
        except Exception as e:
            print(f"Error creating table: {e}")

    def generate_short_id(self, prefix, text):
        """Generate shorter IDs"""
        hash_obj = hashlib.md5(text.encode())
        short_hash = hash_obj.hexdigest()[:8]
        return f"{prefix}-{short_hash}"

    def text_to_embedding(self, text):
        if self.embed_model:
            return self.embed_model.encode(text).tolist()
        else:
            # Fallback
            import hashlib
            hash_val = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
            return [(hash_val >> i) & 1 for i in range(self.embed_dims)]

    def insert_document(self, doc_id, text, embedding, metadata):
        """Insert a single document"""
        insert_sql = f"""
        INSERT INTO {self.table_name} (id, document, embedding, metadata) 
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        document = VALUES(document),
        embedding = VALUES(embedding),
        metadata = VALUES(metadata)
        """
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(insert_sql, (
                doc_id,
                text,
                json.dumps(embedding),
                json.dumps(metadata)
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error inserting document {doc_id}: {e}")
            return False

    def search_similar_vulnerabilities(self, query_text, k=5):
        """Search for similar vulnerabilities"""
        query_embedding = self.text_to_embedding(query_text)
        
        select_sql = f"SELECT id, document, embedding, metadata FROM {self.table_name}"
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(select_sql)
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            
            if not rows:
                return []
            
            similarities = []
            for row in rows:
                try:
                    stored_embedding = json.loads(row[2])  # embedding column
                    similarity = self._cosine_similarity(query_embedding, stored_embedding)
                    
                    similarities.append({
                        'id': row[0],
                        'document': row[1],
                        'metadata': json.loads(row[3]),
                        'similarity': similarity,
                        'distance': 1 - similarity
                    })
                except Exception as e:
                    continue
            
            # Sort by similarity and return top k
            similarities.sort(key=lambda x: x['similarity'], reverse=True)
            return similarities[:k]
            
        except Exception as e:
            print(f"Error searching documents: {e}")
            return []

    def _cosine_similarity(self, vec1, vec2):
        """Calculate cosine similarity"""
        import math
        
        try:
            dot_product = sum(a * b for a, b in zip(vec1, vec2))
            magnitude1 = math.sqrt(sum(a * a for a in vec1))
            magnitude2 = math.sqrt(sum(a * a for a in vec2))
            
            if magnitude1 == 0 or magnitude2 == 0:
                return 0
            
            return dot_product / (magnitude1 * magnitude2)
        except Exception:
            return 0

    def count_documents(self):
        """Count total documents"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {self.table_name}")
            result = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return result
        except Exception as e:
            print(f"Error counting documents: {e}")
            return 0

    def get_sample_documents(self, limit=5):
        """Get sample documents"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(f"SELECT id, LEFT(document, 100) FROM {self.table_name} LIMIT {limit}")
            results = cursor.fetchall()
            cursor.close()
            conn.close()
            return results
        except Exception as e:
            print(f"Error getting samples: {e}")
            return []

    # Legacy compatibility
    class VulnerabilityStore:
        def __init__(self, parent):
            self.parent = parent
        
        def insert(self, ids, texts, embeddings, metadatas):
            success_count = 0
            for i in range(len(ids)):
                if self.parent.insert_document(ids[i], texts[i], embeddings[i], metadatas[i]):
                    success_count += 1
            return success_count
        
        def query(self, embedding, k=5):
            class ResultObject:
                def __init__(self, doc_data):
                    self.document = doc_data['document']
                    self.distance = doc_data['distance']
                    self.metadata = doc_data['metadata']
            
            results = self.parent.search_similar_vulnerabilities("AI security", k=k)
            formatted_results = []
            for result in results[:k]:
                formatted_results.append(ResultObject(result))
            return formatted_results

    def __getattr__(self, name):
        if name == 'vulnerability_store':
            return self.VulnerabilityStore(self)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")