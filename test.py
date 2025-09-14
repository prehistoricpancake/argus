import os
import sys
sys.path.append('.')

def check_files():
    print("Current directory:", os.getcwd())
    print("Files in parent directory:")
    for f in os.listdir(".."):
        if f.endswith('.xlsx') or f.startswith('avid'):
            print(f"  Found: {f}")
    
    # Check AVID reports
    avid_reports_path = "../avid-db/reports"
    if os.path.exists(avid_reports_path):
        json_files = [f for f in os.listdir(avid_reports_path) if f.endswith('.json')]
        print(f"Found {len(json_files)} JSON files in AVID reports")
        if json_files:
            print(f"  Example: {json_files[0]}")
    else:
        print("AVID reports directory not found")

if __name__ == "__main__":
    check_files()