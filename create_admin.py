#!/usr/bin/env python3
"""
SECURITY: Admin User Management Script
This script creates or updates admin users with bcrypt-hashed passwords.
Usage: python create_admin.py <username> <password>
"""

import os
import sys
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
import bcrypt

load_dotenv()

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_admin(username, password):
    """Create or update admin user with hashed password"""
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("ERROR: DATABASE_URL environment variable not set")
        sys.exit(1)
    
    try:
        conn = psycopg.connect(db_url)
        cur = conn.cursor(row_factory=dict_row)
        
        # Hash the password
        hashed_password = hash_password(password)
        
        # Check if user exists
        cur.execute('SELECT id, is_admin FROM users WHERE username = %s', (username,))
        existing = cur.fetchone()
        
        if existing:
            # Update existing user
            cur.execute('''
                UPDATE users 
                SET password = %s, is_admin = TRUE, has_access = TRUE 
                WHERE username = %s
            ''', (hashed_password, username))
            print(f"✓ Admin user '{username}' updated with new hashed password")
        else:
            # Create new user
            cur.execute('''
                INSERT INTO users (username, password, has_access, is_admin)
                VALUES (%s, %s, TRUE, TRUE)
            ''', (username, hashed_password))
            print(f"✓ Admin user '{username}' created with hashed password")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("\n⚠️  IMPORTANT: Store this password securely!")
        print(f"   Username: {username}")
        print(f"   Password: {password}")
        print("\n   The password is now bcrypt-hashed in the database.")
        
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

def migrate_existing_passwords():
    """Migrate existing plaintext passwords to bcrypt hashes"""
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("ERROR: DATABASE_URL environment variable not set")
        sys.exit(1)
    
    try:
        conn = psycopg.connect(db_url)
        cur = conn.cursor(row_factory=dict_row)
        
        # Get all users
        cur.execute('SELECT id, username, password FROM users')
        users = cur.fetchall()
        
        migrated = 0
        for user in users:
            password = user['password']
            # Check if already hashed (bcrypt hashes start with $2b$)
            if not password.startswith('$2b$'):
                hashed = hash_password(password)
                cur.execute('UPDATE users SET password = %s WHERE id = %s', (hashed, user['id']))
                print(f"✓ Migrated password for user: {user['username']}")
                migrated += 1
        
        conn.commit()
        cur.close()
        conn.close()
        
        if migrated > 0:
            print(f"\n✓ Migrated {migrated} user passwords to bcrypt")
        else:
            print("\n✓ All passwords are already hashed")
        
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Create/update admin:  python create_admin.py <username> <password>")
        print("  Migrate passwords:    python create_admin.py --migrate")
        sys.exit(1)
    
    if sys.argv[1] == '--migrate':
        migrate_existing_passwords()
    elif len(sys.argv) >= 3:
        create_admin(sys.argv[1], sys.argv[2])
    else:
        print("ERROR: Please provide both username and password")
        sys.exit(1)
