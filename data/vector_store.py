# # Replace the TiDBVectorClient initialization with shorter IDs
# import os
# from tidb_vector.integrations import TiDBVectorClient
# from sentence_transformers import SentenceTransformer
# from dotenv import load_dotenv
# import hashlib

# class ArgusVectorStore:
#     def __init__(self):
#         load_dotenv()
        
#         try:
#             self.embed_model = SentenceTransformer('all-MiniLM-L6-v2')
#             self.embed_dims = self.embed_model.get_sentence_embedding_dimension()
#             print(f"Embedding model loaded: {self.embed_dims} dimensions")
#         except Exception as e:
#             print(f"Could not load sentence-transformers: {e}")
#             self.embed_model = None
#             self.embed_dims = 384
        
#         connection_string = os.environ.get('TIDB_DATABASE_URL')
#         if connection_string and 'mysql://' in connection_string and 'mysql+pymysql://' not in connection_string:
#             connection_string = connection_string.replace('mysql://', 'mysql+pymysql://')
        
#         self.vulnerability_store = TiDBVectorClient(
#             table_name='argus_vulnerabilities',
#             connection_string=connection_string,
#             vector_dimension=self.embed_dims,
#             drop_existing_table=True,  # Reset table with proper schema
#         )
        
#         print("Vector store initialized")

#     def generate_short_id(self, prefix, text):
#         """Generate shorter IDs to avoid column length issues"""
#         hash_obj = hashlib.md5(text.encode())
#         short_hash = hash_obj.hexdigest()[:8]
#         return f"{prefix}-{short_hash}"

#     def text_to_embedding(self, text):
#         if self.embed_model:
#             return self.embed_model.encode(text).tolist()
#         else:
#             import hashlib
#             hash_val = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
#             return [(hash_val >> i) & 1 for i in range(self.embed_dims)]

#     def search_similar_vulnerabilities(self, query_text, k=5):
#         query_embedding = self.text_to_embedding(query_text)
#         return self.vulnerability_store.query(query_embedding, k=k)




import os
from tidb_vector.integrations import TiDBVectorClient
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
import hashlib

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
        
        connection_string = os.environ.get('TIDB_DATABASE_URL')
        if connection_string and 'mysql://' in connection_string and 'mysql+pymysql://' not in connection_string:
            connection_string = connection_string.replace('mysql://', 'mysql+pymysql://')
        
        self.vulnerability_store = TiDBVectorClient(
            table_name='argus_vulnerabilities',
            connection_string=connection_string,
            vector_dimension=self.embed_dims,
            drop_existing_table=True,  # Reset table with proper schema
        )
        
        print("Vector store initialized")

    def generate_short_id(self, prefix, text):
        """Generate shorter IDs to avoid column length issues"""
        hash_obj = hashlib.md5(text.encode())
        short_hash = hash_obj.hexdigest()[:8]
        return f"{prefix}-{short_hash}"

    def text_to_embedding(self, text):
        if self.embed_model:
            return self.embed_model.encode(text).tolist()
        else:
            import hashlib
            hash_val = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
            return [(hash_val >> i) & 1 for i in range(self.embed_dims)]

    def search_similar_vulnerabilities(self, query_text, k=5):
        query_embedding = self.text_to_embedding(query_text)
        return self.vulnerability_store.query(query_embedding, k=k)