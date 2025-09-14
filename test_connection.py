import os
from tidb_vector.integrations import TiDBVectorClient
from dotenv import load_dotenv

def test_tidb_connection():
    load_dotenv()
    
    try:
        original_url = os.environ.get('TIDB_DATABASE_URL')
        if not original_url:
            print("No TIDB_DATABASE_URL found in .env file")
            return False
            
        # Convert mysql:// to mysql+pymysql://
        converted_url = original_url.replace('mysql://', 'mysql+pymysql://', 1)
        
        print("Testing TiDB connection...")
        
        vector_store = TiDBVectorClient(
            table_name='test_argus_setup',
            connection_string=converted_url,
            vector_dimension=3,
            drop_existing_table=True,
        )
        
        vector_store.insert(
            ids=["vuln-1", "vuln-2"],
            texts=["unsafe model loading vulnerability", "input validation security issue"],
            embeddings=[[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
            metadatas=[{"severity": "HIGH"}, {"severity": "MEDIUM"}]
        )
        
        results = vector_store.query([0.15, 0.25, 0.35], k=2)
        
        print("SUCCESS: TiDB Vector connection working!")
        print(f"Vector search returned {len(results)} results:")
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result.document}")
            print(f"     Distance: {result.distance:.4f}")
        
        return True
        
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

if __name__ == "__main__":
    test_tidb_connection()

