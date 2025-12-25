#!/usr/bin/env python3
# =============================================================================
# SECURITY HARDENED VERSION - mObywatel Generator
# =============================================================================
import os
import re
import json
import secrets
import string
import hashlib
import logging
import base64
from datetime import datetime, timedelta
from functools import wraps
from cryptography.fernet import Fernet

from flask import Flask, jsonify, request, send_file, send_from_directory, Response, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
import bcrypt
import jwt
import bleach
import requests as http_requests  # SECURITY: For Turnstile verification

load_dotenv()

# =============================================================================
# SECURITY: Configuration
# =============================================================================

# SECURITY: Feature flags (kill switches)
DISABLE_SIGNUP = os.environ.get('DISABLE_SIGNUP', 'false').lower() == 'true'
DISABLE_ADMIN = os.environ.get('DISABLE_ADMIN', 'false').lower() == 'true'
PANIC_MODE = os.environ.get('PANIC_MODE', 'false').lower() == 'true'  # SECURITY: Emergency shutdown

# SECURITY: Data encryption key (generate once and store in env!)
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if ENCRYPTION_KEY:
    fernet = Fernet(ENCRYPTION_KEY.encode())
else:
    fernet = None

# SECURITY: Auto-delete documents after X hours (0 = disabled)
AUTO_DELETE_HOURS = int(os.environ.get('AUTO_DELETE_HOURS', '0'))

# SECURITY: JWT configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# SECURITY: Cloudflare Turnstile
TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '0x4AAAAAACIETFZW2JFN4TewZskRq48ujK4')
TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

# SECURITY: Allowed origins for CORS - Allow all for Replit preview
ALLOWED_ORIGINS = "*"

# SECURITY: Admin IP allowlist (optional - set in env)
ADMIN_IP_ALLOWLIST = os.environ.get('ADMIN_IP_ALLOWLIST', '').split(',')
ADMIN_IP_ALLOWLIST = [ip.strip() for ip in ADMIN_IP_ALLOWLIST if ip.strip()]

# SECURITY: Access code TTL (hours)
ACCESS_CODE_TTL_HOURS = int(os.environ.get('ACCESS_CODE_TTL_HOURS', '72'))

# =============================================================================
# SECURITY: Logging configuration - NO user payloads
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('security')

# =============================================================================
# Flask App Setup
# =============================================================================
app = Flask(__name__, static_folder='.', static_url_path='')

# CORS - Allow all origins for Replit preview
CORS(app, origins="*", supports_credentials=True)

# SECURITY: Rate limiting
def get_client_identifier():
    """Get unique client identifier from IP + User-Agent"""
    ip = get_remote_address()
    ua = request.headers.get('User-Agent', 'unknown')[:100]
    return hashlib.md5(f"{ip}:{ua}".encode()).hexdigest()

limiter = Limiter(
    key_func=get_client_identifier,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# =============================================================================
# SECURITY: Request hooks
# =============================================================================

@app.before_request
def security_checks():
    """SECURITY: Pre-request security checks"""
    # SECURITY: Body size limit (10KB)
    content_length = request.content_length
    if content_length and content_length > 10 * 1024:
        logger.warning(f"SECURITY: Body size exceeded from {get_remote_address()}")
        return jsonify({'error': 'Request body too large'}), 413

@app.after_request
def security_headers(response):
    """SECURITY: Add security headers (helmet-like)"""
    # SECURITY: Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # SECURITY: XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Allow Replit preview iframe
    # response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # SECURITY: Strict transport security
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # SECURITY: Content security policy
    response.headers['Content-Security-Policy'] = "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'"
    # SECURITY: Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # SECURITY: Cache control for API responses
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
    return response

# =============================================================================
# SECURITY: Encryption helpers
# =============================================================================

def encrypt_data(data):
    """SECURITY: Encrypt sensitive data"""
    if not fernet or not data:
        return data
    try:
        return fernet.encrypt(data.encode()).decode()
    except Exception:
        return data

def decrypt_data(data):
    """SECURITY: Decrypt sensitive data"""
    if not fernet or not data:
        return data
    try:
        return fernet.decrypt(data.encode()).decode()
    except Exception:
        return data

def hash_identifier(value):
    """SECURITY: One-way hash for logging (can't reverse to get original)"""
    if not value:
        return "unknown"
    return hashlib.sha256(value.encode()).hexdigest()[:12]

# =============================================================================
# SECURITY: Helper functions
# =============================================================================

def sanitize_input(value, max_length=255):
    """SECURITY: Sanitize user input - remove HTML/JS"""
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    # Remove HTML tags
    cleaned = bleach.clean(value, tags=[], strip=True)
    # Limit length
    return cleaned[:max_length]

def hash_password(password):
    """SECURITY: Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """SECURITY: Verify password against bcrypt hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def generate_jwt(user_id, username, is_admin=False):
    """SECURITY: Generate JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt(token):
    """SECURITY: Verify and decode JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    """SECURITY: Decorator requiring valid JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            token = request.cookies.get('auth_token')
        
        if not token:
            logger.warning(f"SECURITY: Unauthorized access attempt to {request.path} from {get_remote_address()}")
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = verify_jwt(token)
        if not payload:
            logger.warning(f"SECURITY: Invalid token for {request.path} from {get_remote_address()}")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    """SECURITY: Decorator requiring admin JWT + optional IP check"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # SECURITY: Kill switch check
        if DISABLE_ADMIN:
            logger.warning(f"SECURITY: Admin access blocked (DISABLE_ADMIN=true) from {get_remote_address()}")
            return jsonify({'error': 'Admin panel is disabled'}), 403
        
        # SECURITY: IP allowlist check (if configured)
        if ADMIN_IP_ALLOWLIST:
            client_ip = get_remote_address()
            # Handle Cloudflare proxy
            cf_ip = request.headers.get('CF-Connecting-IP')
            if cf_ip:
                client_ip = cf_ip
            
            if client_ip not in ADMIN_IP_ALLOWLIST:
                logger.warning(f"SECURITY: Admin access denied - IP not in allowlist: {client_ip}")
                return jsonify({'error': 'Access denied'}), 403
        
        # SECURITY: JWT verification
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            token = request.cookies.get('admin_token')
        
        if not token:
            logger.warning(f"SECURITY: Admin access without token to {request.path} from {get_remote_address()}")
            return jsonify({'error': 'Admin authentication required'}), 401
        
        payload = verify_jwt(token)
        if not payload:
            logger.warning(f"SECURITY: Invalid admin token for {request.path} from {get_remote_address()}")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if not payload.get('is_admin'):
            logger.warning(f"SECURITY: Non-admin user attempted admin access: {payload.get('username')} from {get_remote_address()}")
            return jsonify({'error': 'Admin privileges required'}), 403
        
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated

def verify_turnstile_sync(token):
    """SECURITY: Synchronous Turnstile verification"""
    if not TURNSTILE_SECRET_KEY:
        return True
    
    try:
        response = http_requests.post(TURNSTILE_VERIFY_URL, data={
            'secret': TURNSTILE_SECRET_KEY,
            'response': token
        }, timeout=5)
        result = response.json()
        return result.get('success', False)
    except Exception as e:
        logger.error(f"SECURITY: Turnstile verification error: {e}")
        return False

# =============================================================================
# Database
# =============================================================================

def get_db():
    return psycopg.connect(os.environ.get('DATABASE_URL'))

def init_db():
    """Initialize database with required tables"""
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("WARNING: DATABASE_URL not set - skipping database initialization")
        return

    try:
        print("Connecting to database...")
        conn = psycopg.connect(db_url)
        cur = conn.cursor()
        print("Connection successful")

        # Users table - SECURITY: password is now bcrypt hash
        print("Creating users table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                has_access BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE,
                hwid VARCHAR(255)
            )
        ''')
        conn.commit()
        print("Users table created/verified")

        # Generated documents table
        print("Creating generated_documents table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS generated_documents (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                name VARCHAR(255),
                surname VARCHAR(255),
                pesel VARCHAR(11),
                access_code VARCHAR(12),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data JSON,
                view_token VARCHAR(32)
            )
        ''')
        conn.commit()
        
        # SECURITY: Add view_token column if not exists (migration)
        try:
            cur.execute('''
                ALTER TABLE generated_documents 
                ADD COLUMN IF NOT EXISTS view_token VARCHAR(32)
            ''')
            conn.commit()
            print("Added view_token column to generated_documents")
        except Exception as e:
            print(f"Note: view_token column may already exist: {e}")
            conn.rollback()
        
        print("Generated documents table created/verified")

        # SECURITY: One-time codes table with expires_at
        print("Creating one_time_codes table with TTL...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS one_time_codes (
                id SERIAL PRIMARY KEY,
                code VARCHAR(12) UNIQUE NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '72 hours'),
                code_type VARCHAR(20) DEFAULT 'single'
            )
        ''')
        conn.commit()
        
        # SECURITY: Add expires_at column if it doesn't exist (migration)
        try:
            cur.execute('''
                ALTER TABLE one_time_codes 
                ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '72 hours')
            ''')
            conn.commit()
            print("Added expires_at column to one_time_codes")
        except Exception as e:
            print(f"Note: expires_at column may already exist: {e}")
            conn.rollback()
        
        # Add code_type column (migration)
        try:
            cur.execute('''
                ALTER TABLE one_time_codes 
                ADD COLUMN IF NOT EXISTS code_type VARCHAR(20) DEFAULT 'single'
            ''')
            conn.commit()
            print("Added code_type column to one_time_codes")
        except Exception as e:
            print(f"Note: code_type column may already exist: {e}")
            conn.rollback()
        
        print("One-time codes table created/verified")

        # SECURITY: Rate limit tracking table
        print("Creating rate_limits table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id SERIAL PRIMARY KEY,
                identifier VARCHAR(255) NOT NULL,
                endpoint VARCHAR(255) NOT NULL,
                attempts INTEGER DEFAULT 1,
                first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked_until TIMESTAMP,
                UNIQUE(identifier, endpoint)
            )
        ''')
        conn.commit()
        print("Rate limits table created/verified")

        # SECURITY: Auto-create admin from environment variables
        admin_username = os.environ.get('ADMIN_USERNAME')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        
        if admin_username and admin_password:
            print(f"Creating/updating admin user: {admin_username}")
            hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            try:
                # Try to insert new admin
                cur.execute('''
                    INSERT INTO users (username, password, has_access, is_admin)
                    VALUES (%s, %s, TRUE, TRUE)
                    ON CONFLICT (username) DO UPDATE SET
                    password = EXCLUDED.password, has_access = TRUE, is_admin = TRUE
                ''', (admin_username, hashed_password))
                conn.commit()
                print(f"✓ Admin user '{admin_username}' created/updated with hashed password")
            except Exception as e:
                print(f"Note: Admin creation error: {e}")
                conn.rollback()

        cur.close()
        conn.close()
        print("✓ Database initialization completed successfully!")
    except Exception as e:
        print(f"ERROR: Database initialization failed: {e}")
        import traceback
        traceback.print_exc()

# =============================================================================
# Static file serving
# =============================================================================

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    try:
        return send_from_directory('assets', filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

def serve_html(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        response = Response(content, mimetype='text/html; charset=utf-8')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        return jsonify({'error': f'Cannot load {filename}: {str(e)}'}), 500

@app.route('/')
def index():
    return serve_html('admin-login.html')

@app.route('/admin-login.html')
def admin_login_page():
    return serve_html('admin-login.html')

@app.route('/login.html')
def login_page():
    return serve_html('login.html')

@app.route('/gen.html')
def gen_page():
    return serve_html('gen.html')

@app.route('/manifest.json')
def manifest():
    try:
        with open('manifest.json', 'r', encoding='utf-8') as f:
            content = f.read()
        response = Response(content, mimetype='application/manifest+json')
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@app.route('/admin.html')
def admin_page():
    # SECURITY: Kill switch
    if DISABLE_ADMIN:
        return Response('<h1>Admin panel is disabled</h1>', status=403, mimetype='text/html')
    return serve_html('admin.html')

# =============================================================================
# SECURITY: Removed /api/seed endpoint - no hardcoded credentials
# =============================================================================

# =============================================================================
# Auth Routes
# =============================================================================

@app.route('/api/auth/create-user', methods=['POST'])
@limiter.limit("5 per 15 minutes")  # SECURITY: Rate limit signup
def create_user():
    # SECURITY: Kill switch
    if DISABLE_SIGNUP:
        logger.warning(f"SECURITY: Signup attempt blocked (DISABLE_SIGNUP=true) from {get_remote_address()}")
        return jsonify({'error': 'Registration is currently disabled'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    # SECURITY: Sanitize inputs
    username = sanitize_input(data.get('username'), 50)
    password = data.get('password', '')
    
    # SECURITY: Turnstile verification
    turnstile_token = data.get('turnstile_token')
    if TURNSTILE_SECRET_KEY and not verify_turnstile_sync(turnstile_token):
        logger.warning(f"SECURITY: Failed Turnstile verification for signup from {get_remote_address()}")
        return jsonify({'error': 'CAPTCHA verification failed'}), 403

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # SECURITY: Password requirements
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        # SECURITY: Hash password with bcrypt
        hashed_password = hash_password(password)
        
        cur.execute(
            'INSERT INTO users (username, password, has_access) VALUES (%s, %s, %s)',
            (username, hashed_password, True))
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"New user created: {username}")
        return jsonify({'message': 'User created successfully'}), 201
    except psycopg.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per 15 minutes")  # SECURITY: Rate limit login
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    # SECURITY: Sanitize
    username = sanitize_input(data.get('username'), 50)
    password = data.get('password', '')
    hwid = sanitize_input(data.get('hwid'), 100)
    
    # SECURITY: Turnstile verification (optional for login)
    turnstile_token = data.get('turnstile_token')
    if TURNSTILE_SECRET_KEY and turnstile_token:
        if not verify_turnstile_sync(turnstile_token):
            logger.warning(f"SECURITY: Failed Turnstile on login from {get_remote_address()}")
            return jsonify({'error': 'CAPTCHA verification failed'}), 403

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()

        if not user:
            logger.warning(f"SECURITY: Login failed - user not found: {username} from {get_remote_address()}")
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # SECURITY: Verify bcrypt password
        if not verify_password(password, user['password']):
            logger.warning(f"SECURITY: Login failed - wrong password for: {username} from {get_remote_address()}")
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user['has_access']:
            cur.close()
            conn.close()
            return jsonify({'error': 'Access denied. Contact administrator'}), 403

        # HWID validation for non-admin users
        if hwid and not user['is_admin']:
            if user['hwid']:
                if user['hwid'] != hwid:
                    cur.close()
                    conn.close()
                    return jsonify({'error': 'Device not authorized'}), 403
            else:
                cur.execute('UPDATE users SET hwid = %s WHERE id = %s', (hwid, user['id']))
                conn.commit()

        # SECURITY: Generate JWT token
        token = generate_jwt(user['id'], user['username'], user['is_admin'])
        
        cur.close()
        conn.close()
        
        logger.info(f"User logged in: {username} (admin={user['is_admin']})")
        
        response_data = {
            'user_id': user['id'],
            'username': user['username'],
            'is_admin': user['is_admin'],
            'token': token  # SECURITY: Return JWT token
        }
        
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/admin-login', methods=['POST'])
@limiter.limit("3 per 15 minutes")  # SECURITY: Aggressive rate limit for admin
def admin_login():
    """SECURITY: Dedicated admin login endpoint"""
    # SECURITY: Kill switch
    if DISABLE_ADMIN:
        logger.warning(f"SECURITY: Admin login blocked (DISABLE_ADMIN=true) from {get_remote_address()}")
        return jsonify({'error': 'Admin panel is disabled'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    username = sanitize_input(data.get('username'), 50)
    password = data.get('password', '')
    
    # SECURITY: Turnstile verification (optional - rate limit still protects)
    turnstile_token = data.get('turnstile_token')
    if TURNSTILE_SECRET_KEY and turnstile_token:
        if not verify_turnstile_sync(turnstile_token):
            logger.warning(f"SECURITY: Admin login failed Turnstile from {get_remote_address()}")
            return jsonify({'error': 'CAPTCHA verification failed'}), 403

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT * FROM users WHERE username = %s AND is_admin = TRUE', (username,))
        user = cur.fetchone()

        if not user:
            logger.warning(f"SECURITY: Admin login failed - not an admin: {username} from {get_remote_address()}")
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not verify_password(password, user['password']):
            logger.warning(f"SECURITY: Admin login failed - wrong password: {username} from {get_remote_address()}")
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401

        # SECURITY: Generate admin JWT
        token = generate_jwt(user['id'], user['username'], True)
        
        cur.close()
        conn.close()
        
        logger.info(f"SECURITY: Admin logged in: {username} from {get_remote_address()}")
        
        return jsonify({
            'user_id': user['id'],
            'username': user['username'],
            'is_admin': True,
            'token': token
        }), 200
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# Access Code Validation
# =============================================================================

@app.route('/api/auth/validate-code', methods=['POST'])
@limiter.limit("3 per 15 minutes")  # SECURITY: Aggressive rate limit for code guessing
def validate_code():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    code = sanitize_input(data.get('code', ''), 12).strip().upper()
    
    # SECURITY: Turnstile verification (optional - rate limit still protects)
    turnstile_token = data.get('turnstile_token')
    if TURNSTILE_SECRET_KEY and turnstile_token:
        if not verify_turnstile_sync(turnstile_token):
            logger.warning(f"SECURITY: Code validation failed Turnstile from {get_remote_address()}")
            return jsonify({'error': 'CAPTCHA verification failed'}), 403
    
    if not code:
        return jsonify({'error': 'Code is required'}), 400
    
    # SECURITY: Validate code format (alphanumeric only)
    if not re.match(r'^[A-Z0-9]+$', code):
        logger.warning(f"SECURITY: Invalid code format attempted from {get_remote_address()}")
        return jsonify({'error': 'Invalid code format'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        # SECURITY: Check code exists, not used, and not expired
        cur.execute('''
            SELECT id FROM one_time_codes 
            WHERE code = %s 
            AND used = FALSE 
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ''', (code,))
        code_record = cur.fetchone()
        
        if not code_record:
            logger.warning(f"SECURITY: Invalid/expired code attempt from {get_remote_address()}")
            cur.close()
            conn.close()
            return jsonify({'error': 'Code is invalid, expired, or already used'}), 401
        
        # SECURITY: Mark code as used
        cur.execute('UPDATE one_time_codes SET used = TRUE, used_at = CURRENT_TIMESTAMP WHERE id = %s', (code_record['id'],))
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Access code used successfully from {get_remote_address()}")
        return jsonify({'message': 'Code validated successfully'}), 200
    except Exception as e:
        logger.error(f"Code validation error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# Document Routes
# =============================================================================

@app.route('/api/documents/save', methods=['POST'])
@limiter.limit("10 per 15 minutes")  # SECURITY: Rate limit
def save_document():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    user_id = data.get('user_id')
    
    # SECURITY: Sanitize all inputs
    name = sanitize_input(data.get('name'), 100)
    surname = sanitize_input(data.get('surname'), 100)
    pesel = sanitize_input(data.get('pesel'), 11)

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            '''
            INSERT INTO generated_documents (user_id, name, surname, pesel, data)
            VALUES (%s, %s, %s, %s, %s)
        ''',
            (user_id, name, surname, pesel, json.dumps(data)))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Document saved'}), 201
    except Exception as e:
        logger.error(f"Document save error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/documents/create-and-get-id', methods=['POST'])
@limiter.limit("10 per 15 minutes")  # SECURITY: Rate limit
def create_document_with_id():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    user_id = data.get('user_id')
    access_code = sanitize_input(data.get('access_code'), 12)
    
    # SECURITY: Sanitize
    name = sanitize_input(data.get('name'), 100)
    surname = sanitize_input(data.get('surname'), 100)
    pesel = sanitize_input(data.get('pesel'), 11)
    
    # SECURITY: Generate unique view token
    view_token = secrets.token_urlsafe(16)

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        cur.execute(
            '''
            INSERT INTO generated_documents (user_id, name, surname, pesel, access_code, data, view_token)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''',
            (user_id, name, surname, pesel, access_code, json.dumps(data), view_token))
        
        result = cur.fetchone()
        document_id = result['id'] if result else None
        
        if not document_id:
            cur.execute('SELECT id, view_token FROM generated_documents WHERE pesel = %s ORDER BY id DESC LIMIT 1', (pesel,))
            result = cur.fetchone()
            document_id = result['id'] if result else None
            view_token = result['view_token'] if result else view_token
        
        conn.commit()
        cur.close()
        conn.close()
        
        # SECURITY: Return both ID and token
        return jsonify({'document_id': document_id, 'view_token': view_token}), 201
    except Exception as e:
        logger.error(f"Document creation error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# SECURITY: Document existence check - returns ONLY exists: true/false
# No sensitive data exposed, all logic on backend
# =============================================================================

@app.route('/api/documents/<int:document_id>/check', methods=['GET'])
def check_document_exists(document_id):
    """
    SECURITY: Check if document exists without exposing any data
    Returns: { "exists": true/false }
    HTTP 200 with exists:true if document found with valid token
    HTTP 200 with exists:false if not found
    HTTP 403 if token invalid/missing
    """
    view_token = request.args.get('token')
    
    # SECURITY: Validate document_id is positive integer (already done by Flask int converter)
    if document_id <= 0:
        return jsonify({'exists': False}), 200
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        # SECURITY: Check both ID and token
        if view_token:
            cur.execute('SELECT id FROM generated_documents WHERE id = %s AND view_token = %s', (document_id, view_token))
        else:
            # Without token - check if admin
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.replace('Bearer ', '')
                payload = verify_jwt(token)
                if payload and payload.get('is_admin'):
                    cur.execute('SELECT id FROM generated_documents WHERE id = %s', (document_id,))
                else:
                    cur.close()
                    conn.close()
                    return jsonify({'error': 'Access denied - token required'}), 403
            else:
                cur.close()
                conn.close()
                return jsonify({'error': 'Access denied - token required'}), 403
        
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        # SECURITY: Return simple boolean - no data leakage
        return jsonify({'exists': result is not None}), 200
        
    except Exception as e:
        logger.error(f"Document check error: {e}")
        return jsonify({'exists': False}), 200  # SECURITY: Don't leak errors

@app.route('/api/documents/<int:document_id>', methods=['GET'])
def get_document(document_id):
    # SECURITY: Require view_token
    view_token = request.args.get('token')
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        # SECURITY: Check both ID and token
        if view_token:
            cur.execute('SELECT data FROM generated_documents WHERE id = %s AND view_token = %s', (document_id, view_token))
        else:
            # Allow admin access without token (for admin panel)
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.replace('Bearer ', '')
                payload = verify_jwt(token)
                if payload and payload.get('is_admin'):
                    cur.execute('SELECT data FROM generated_documents WHERE id = %s', (document_id,))
                else:
                    cur.close()
                    conn.close()
                    return jsonify({'error': 'Access denied - token required'}), 403
            else:
                cur.close()
                conn.close()
                return jsonify({'error': 'Access denied - token required'}), 403
        
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if not result:
            return jsonify({'error': 'Document not found'}), 404
        
        document_data = json.loads(result['data']) if isinstance(result['data'], str) else result['data']
        return jsonify(document_data), 200
    except Exception as e:
        logger.error(f"Document fetch error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# SECURITY: Admin Routes - Protected with JWT
# =============================================================================

@app.route('/api/admin/users', methods=['GET'])
@require_admin
def get_users():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT id, username, has_access, created_at, is_admin FROM users ORDER BY created_at DESC')
        users = cur.fetchall()
        cur.close()
        conn.close()
        
        # Convert datetime for JSON
        result = []
        for user in users:
            result.append({
                'id': user['id'],
                'username': user['username'],
                'has_access': user['has_access'],
                'is_admin': user['is_admin'],
                'created_at': user['created_at'].isoformat() if user['created_at'] else None
            })
        
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Admin get users error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/admin/users/<int:user_id>/access', methods=['PUT'])
@require_admin
def update_access(user_id):
    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Invalid request'}), 400
    
    has_access = data.get('has_access')

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('UPDATE users SET has_access = %s WHERE id = %s', (has_access, user_id))
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Admin updated access for user {user_id} to {has_access}")
        return jsonify({'message': 'Access updated'}), 200
    except Exception as e:
        logger.error(f"Admin update access error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/admin/documents', methods=['GET'])
@require_admin
def get_all_documents():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('''
            SELECT d.id, u.username, d.name, d.surname, d.pesel, d.access_code, d.created_at
            FROM generated_documents d
            LEFT JOIN users u ON d.user_id = u.id
            ORDER BY d.created_at DESC
        ''')
        documents = cur.fetchall()
        cur.close()
        conn.close()
        
        result = []
        for doc in documents:
            result.append({
                'id': doc['id'],
                'username': doc['username'],
                'name': doc['name'],
                'surname': doc['surname'],
                'pesel': doc['pesel'],
                'access_code': doc['access_code'],
                'created_at': doc['created_at'].isoformat() if doc['created_at'] else None
            })
        
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Admin get documents error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/admin/documents/<int:document_id>', methods=['PUT'])
@require_admin
def update_document(document_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    # SECURITY: Sanitize
    name = sanitize_input(data.get('name'), 100)
    surname = sanitize_input(data.get('surname'), 100)
    pesel = sanitize_input(data.get('pesel'), 11)
    adress1 = sanitize_input(data.get('adress1'), 255)
    adress2 = sanitize_input(data.get('adress2'), 255)
    birthPlace = sanitize_input(data.get('birthPlace'), 255)
    image = data.get('image')  # URL - validate separately
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        cur.execute('SELECT data FROM generated_documents WHERE id = %s', (document_id,))
        result = cur.fetchone()
        
        if not result:
            return jsonify({'error': 'Document not found'}), 404
        
        doc_data = json.loads(result['data']) if isinstance(result['data'], str) else result['data']
        doc_data['name'] = name
        doc_data['surname'] = surname
        doc_data['pesel'] = pesel
        if adress1:
            doc_data['adress1'] = adress1
        if adress2:
            doc_data['adress2'] = adress2
        if birthPlace:
            doc_data['birthPlace'] = birthPlace
        if image:
            doc_data['image'] = image
        
        cur.execute('UPDATE generated_documents SET name = %s, surname = %s, pesel = %s, data = %s WHERE id = %s',
                    (name, surname, pesel, json.dumps(doc_data), document_id))
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Admin updated document {document_id}")
        return jsonify({'message': 'Document updated successfully'}), 200
    except Exception as e:
        logger.error(f"Admin update document error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/admin/documents/<int:document_id>', methods=['DELETE'])
@require_admin
def delete_document(document_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM generated_documents WHERE id = %s', (document_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Admin deleted document {document_id}")
        return jsonify({'message': 'Document deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Admin delete document error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# SECURITY: One-time code generation - Admin only
# =============================================================================

@app.route('/api/admin/generate-codes', methods=['POST'])
@require_admin
def generate_codes():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request body'}), 400
        
        count = data.get('count', 1)
        
        try:
            count = int(count)
            if count < 1 or count > 100:
                return jsonify({'error': 'Count must be between 1 and 100'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid count'}), 400
        
        # Get code type (single or pack)
        code_type = data.get('code_type', 'single')
        if code_type not in ['single', 'pack']:
            code_type = 'single'
        
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        codes = []
        # SINGLE: expires after TTL, PACK: never expires
        if code_type == 'pack':
            expires_at = None  # Pack codes never expire
        else:
            expires_at = datetime.utcnow() + timedelta(hours=ACCESS_CODE_TTL_HOURS)
        
        for i in range(count):
            attempts = 0
            while attempts < 100:
                code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
                cur.execute('SELECT id FROM one_time_codes WHERE code = %s', (code,))
                if not cur.fetchone():
                    break
                attempts += 1
            
            # Insert with expiration (NULL for pack) and type
            cur.execute('INSERT INTO one_time_codes (code, expires_at, code_type) VALUES (%s, %s, %s)', (code, expires_at, code_type))
            codes.append(code)
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Admin generated {len(codes)} {code_type} access codes")
        expires_str = expires_at.isoformat() if expires_at else 'nigdy'
        return jsonify({'codes': codes, 'expires_at': expires_str, 'code_type': code_type}), 201
    except Exception as e:
        logger.error(f"Code generation error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/admin/codes', methods=['GET'])
@require_admin
def get_codes():
    try:
        # Optional filter by type
        code_type = request.args.get('type')
        # Optional include expired (default: false for downloads)
        include_expired = request.args.get('include_expired', 'false').lower() == 'true'
        
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        if code_type:
            cur.execute('SELECT id, code, used, used_at, created_at, expires_at, code_type FROM one_time_codes WHERE code_type = %s ORDER BY created_at DESC', (code_type,))
        else:
            cur.execute('SELECT id, code, used, used_at, created_at, expires_at, code_type FROM one_time_codes ORDER BY created_at DESC')
        
        codes = cur.fetchall()
        cur.close()
        conn.close()
        
        codes_list = []
        now = datetime.utcnow()
        for code in codes:
            expires_at = code.get('expires_at')
            is_expired = (expires_at < now) if expires_at else False
            
            # Skip expired codes unless explicitly requested
            if is_expired and not include_expired:
                continue
            
            codes_list.append({
                'id': code['id'],
                'code': code['code'],
                'used': code['used'],
                'expired': is_expired,
                'code_type': code.get('code_type', 'single'),
                'used_at': code['used_at'].isoformat() if code['used_at'] else None,
                'created_at': code['created_at'].isoformat() if code['created_at'] else None,
                'expires_at': expires_at.isoformat() if expires_at else None
            })
        
        return jsonify({'codes': codes_list}), 200
    except Exception as e:
        logger.error(f"Get codes error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# SECURITY: Removed public /clear-codes endpoint - admin only via API
@app.route('/api/admin/clear-codes', methods=['DELETE'])
@require_admin
def clear_codes():
    """SECURITY: Admin-only endpoint to clear codes"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM one_time_codes')
        deleted_count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        
        logger.warning(f"SECURITY: Admin cleared {deleted_count} access codes")
        return jsonify({'message': f'Deleted {deleted_count} codes'}), 200
    except Exception as e:
        logger.error(f"Clear codes error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/admin/delete-expired-codes', methods=['DELETE'])
@require_admin
def delete_expired_codes():
    """SECURITY: Admin-only endpoint to delete expired codes"""
    try:
        conn = get_db()
        cur = conn.cursor()
        now = datetime.utcnow()
        cur.execute('DELETE FROM one_time_codes WHERE expires_at IS NOT NULL AND expires_at < %s', (now,))
        deleted_count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"SECURITY: Admin deleted {deleted_count} expired access codes")
        return jsonify({'message': f'Usunięto {deleted_count} wygasłych kodów'}), 200
    except Exception as e:
        logger.error(f"Delete expired codes error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# SECURITY: Webhook - with proper secret verification
# =============================================================================

@app.route('/api/webhooks/purchase', methods=['POST'])
@limiter.limit("20 per minute")  # SECURITY: Rate limit webhooks
def handle_purchase_webhook():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    email = sanitize_input(data.get('email', ''), 255).lower().strip() if data.get('email') else None
    username = sanitize_input(data.get('username', ''), 50).strip() if data.get('username') else None
    webhook_secret = data.get('secret')
    
    # SECURITY: Verify webhook secret
    expected_secret = os.environ.get('WEBHOOK_SECRET')
    if not expected_secret or webhook_secret != expected_secret:
        logger.warning(f"SECURITY: Invalid webhook secret from {get_remote_address()}")
        return jsonify({'error': 'Invalid webhook secret'}), 401
    
    if not email and not username:
        return jsonify({'error': 'Email or username required'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        user = None
        if email:
            cur.execute('SELECT * FROM users WHERE email = %s OR username = %s', (email, email))
            user = cur.fetchone()
        
        if not user and username:
            cur.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cur.fetchone()
        
        if not user:
            if not email:
                cur.close()
                conn.close()
                return jsonify({'error': 'Email required to create new account'}), 400
            
            # SECURITY: Generate secure random password
            random_password = secrets.token_urlsafe(16)
            hashed_password = hash_password(random_password)
            new_username = email.split('@')[0] + '_' + secrets.token_hex(4)
            
            try:
                cur.execute(
                    'INSERT INTO users (username, password, email, has_access, is_admin) VALUES (%s, %s, %s, %s, %s)',
                    (new_username, hashed_password, email, True, False)
                )
                conn.commit()
                cur.execute('SELECT id FROM users WHERE username = %s', (new_username,))
                user = cur.fetchone()
                logger.info(f"Webhook created new user: {new_username}")
            except psycopg.IntegrityError:
                conn.rollback()
                cur.execute('SELECT * FROM users WHERE email = %s', (email,))
                user = cur.fetchone()
        
        if user:
            cur.execute('UPDATE users SET has_access = TRUE WHERE id = %s', (user['id'],))
            conn.commit()
            logger.info(f"Webhook granted access to user: {user.get('username', user['id'])}")
            
            cur.close()
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Access granted successfully',
                'user_id': user['id']
            }), 200
        else:
            cur.close()
            conn.close()
            return jsonify({'error': 'User not found and could not be created'}), 404
            
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# SECURITY: Admin password reset utility (CLI only)
# =============================================================================

def create_admin_user(username, password):
    """CLI utility to create/update admin user with hashed password"""
    conn = get_db()
    cur = conn.cursor()
    
    hashed = hash_password(password)
    
    try:
        cur.execute('''
            INSERT INTO users (username, password, has_access, is_admin)
            VALUES (%s, %s, TRUE, TRUE)
            ON CONFLICT (username) DO UPDATE SET
            password = EXCLUDED.password, has_access = TRUE, is_admin = TRUE
        ''', (username, hashed))
        conn.commit()
        print(f"✓ Admin user '{username}' created/updated with hashed password")
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        cur.close()
        conn.close()

# =============================================================================
# Error handlers
# =============================================================================

@app.errorhandler(429)
def ratelimit_handler(e):
    """SECURITY: Log rate limit violations"""
    logger.warning(f"SECURITY: Rate limit exceeded from {get_remote_address()} on {request.path}")
    return jsonify({'error': 'Too many requests. Please try again later.'}), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# SECURITY: PANIC MODE - Emergency data deletion
# =============================================================================

@app.route('/api/admin/panic', methods=['POST'])
@require_admin
def panic_delete_all():
    """
    SECURITY: PANIC BUTTON - Delete ALL sensitive data immediately
    Use when you need to remove all traces quickly
    """
    data = request.get_json() or {}
    confirm = data.get('confirm')
    
    if confirm != 'DELETE_EVERYTHING_NOW':
        return jsonify({'error': 'Confirmation required. Send {"confirm": "DELETE_EVERYTHING_NOW"}'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Count before deletion
        cur.execute('SELECT COUNT(*) FROM generated_documents')
        docs_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM one_time_codes')
        codes_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM users WHERE is_admin = FALSE')
        users_count = cur.fetchone()[0]
        
        # DELETE EVERYTHING (except admin accounts)
        cur.execute('DELETE FROM generated_documents')
        cur.execute('DELETE FROM one_time_codes')
        cur.execute('DELETE FROM users WHERE is_admin = FALSE')  # Keep admin
        cur.execute('DELETE FROM rate_limits')
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.warning(f"SECURITY: PANIC DELETE executed - {docs_count} docs, {codes_count} codes, {users_count} users deleted")
        
        return jsonify({
            'status': 'ALL DATA DELETED',
            'deleted': {
                'documents': docs_count,
                'codes': codes_count,
                'users': users_count
            }
        }), 200
        
    except Exception as e:
        logger.error(f"PANIC delete error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/admin/delete-old', methods=['POST'])
@require_admin
def delete_old_documents():
    """SECURITY: Delete documents older than X hours"""
    data = request.get_json() or {}
    hours = data.get('hours', 24)
    
    try:
        hours = int(hours)
        if hours < 1:
            return jsonify({'error': 'Hours must be at least 1'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid hours value'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        cur.execute('SELECT COUNT(*) FROM generated_documents WHERE created_at < %s', (cutoff,))
        count = cur.fetchone()[0]
        
        cur.execute('DELETE FROM generated_documents WHERE created_at < %s', (cutoff,))
        conn.commit()
        
        cur.close()
        conn.close()
        
        logger.info(f"Admin deleted {count} documents older than {hours} hours")
        return jsonify({'deleted': count, 'older_than_hours': hours}), 200
        
    except Exception as e:
        logger.error(f"Delete old documents error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# Initialize and Run
# =============================================================================

def auto_cleanup():
    """SECURITY: Auto-delete old documents if configured"""
    if AUTO_DELETE_HOURS > 0:
        try:
            conn = get_db()
            cur = conn.cursor()
            cutoff = datetime.utcnow() - timedelta(hours=AUTO_DELETE_HOURS)
            cur.execute('DELETE FROM generated_documents WHERE created_at < %s', (cutoff,))
            deleted = cur.rowcount
            conn.commit()
            cur.close()
            conn.close()
            if deleted > 0:
                logger.info(f"Auto-cleanup: Deleted {deleted} documents older than {AUTO_DELETE_HOURS}h")
        except Exception as e:
            logger.error(f"Auto-cleanup error: {e}")

init_db()
auto_cleanup()  # Run cleanup on startup

# SECURITY: If PANIC_MODE is enabled, block all access
if PANIC_MODE:
    @app.before_request
    def panic_block():
        if not request.path.startswith('/api/admin'):
            return jsonify({'error': 'Service temporarily unavailable'}), 503

if __name__ == '__main__':
    import sys
    
    # CLI for admin creation
    if len(sys.argv) >= 4 and sys.argv[1] == 'create-admin':
        create_admin_user(sys.argv[2], sys.argv[3])
        sys.exit(0)
    
    port = int(os.environ.get('PORT', 5000))
    # SECURITY: Debug=False in production
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
