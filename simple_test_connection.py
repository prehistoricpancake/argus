# Create the simple test file
import os
import mysql.connector
from dotenv import load_dotenv
import json

def test_basic_tidb_connection():
    load_dotenv()
    
    db_url = os.environ.get('TIDB_DATABASE_URL')
    if not db_url:
        print("No TIDB_DATABASE_URL in .env file")
        return False
    
    try:
        import re
        match = re.match(r'mysql\+pymysql://([^:]+):([^@]+)@([^:]+):(\d+)/([^?]+)', db_url)
        
        if not match:
            print("Invalid connection string format")
            return False
            
        user, password, host, port, database = match.groups()
        
        config = {
            'host': host,
            'port': int(port),
            'user': user,
            'password': password,
            'database': database,
            'ssl_disabled': False
        }
        
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()
        
        cursor.execute("SELECT 1 as test")
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        print("Basic TiDB connection successful!")
        return True
        
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

if __name__ == "__main__":
    test_basic_tidb_connection()
