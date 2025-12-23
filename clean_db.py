#!/usr/bin/env python3
"""
Script to clean database - remove all documents and codes
"""
import os
import sys
import psycopg
from dotenv import load_dotenv

load_dotenv()

def clean_database():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("ERROR: DATABASE_URL not set")
        print("Usage: set DATABASE_URL=postgresql://... && python clean_db.py")
        sys.exit(1)
    
    try:
        conn = psycopg.connect(db_url)
        cur = conn.cursor()
        
        # Count before delete
        cur.execute('SELECT COUNT(*) FROM generated_documents')
        docs_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM one_time_codes')
        codes_count = cur.fetchone()[0]
        
        print(f"Found {docs_count} documents and {codes_count} codes")
        
        # Delete all
        print("Deleting all documents...")
        cur.execute('DELETE FROM generated_documents')
        
        print("Deleting all codes...")
        cur.execute('DELETE FROM one_time_codes')
        
        conn.commit()
        
        print(f"✓ Deleted {docs_count} documents")
        print(f"✓ Deleted {codes_count} codes")
        print("✓ Database cleaned!")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    confirm = input("This will DELETE ALL documents and codes. Type 'yes' to confirm: ")
    if confirm.lower() == 'yes':
        clean_database()
    else:
        print("Cancelled")
