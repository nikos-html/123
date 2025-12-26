#!/usr/bin/env python3
# ADMIN APP - Tylko panel administracyjny
import os, re, json, secrets, string, logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory, Response, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
import bcrypt, jwt, bleach, requests as http_requests

load_dotenv()

JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
ACCESS_CODE_TTL_HOURS = int(os.environ.get('ACCESS_CODE_TTL_HOURS', '72'))

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('admin')

app = Flask(__name__, 
            static_folder=BASE_DIR,
            static_url_path='',
            template_folder=BASE_DIR)
CORS(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["100 per hour"], storage_uri="memory://")

@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['Cache-Control'] = 'no-store'
    return r

def sanitize(v, m=255):
    return bleach.clean(v, tags=[], strip=True)[:m] if isinstance(v, str) else v

def get_db():
    return psycopg.connect(os.environ.get('DATABASE_URL'))

def verify_password(p, h):
    try: return bcrypt.checkpw(p.encode(), h.encode())
    except: return False

def gen_jwt(uid, uname):
    return jwt.encode({'user_id': uid, 'username': uname, 'is_admin': True, 'exp': datetime.utcnow() + timedelta(hours=24)}, JWT_SECRET, algorithm='HS256')

def verify_jwt(t):
    try: return jwt.decode(t, JWT_SECRET, algorithms=['HS256'])
    except: return None

def require_admin(f):
    @wraps(f)
    def d(*a, **k):
        t = request.headers.get('Authorization', '').replace('Bearer ', '') or request.cookies.get('admin_token')
        p = verify_jwt(t) if t else None
        if not p or not p.get('is_admin'): return jsonify({'error': 'Unauthorized'}), 401
        g.current_user = p
        return f(*a, **k)
    return d

def init_db():
    try:
        conn = psycopg.connect(os.environ.get('DATABASE_URL'))
        cur = conn.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE, password VARCHAR(255), has_access BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_admin BOOLEAN DEFAULT FALSE)')
        cur.execute('CREATE TABLE IF NOT EXISTS generated_documents (id SERIAL PRIMARY KEY, user_id INTEGER, name VARCHAR(255), surname VARCHAR(255), pesel VARCHAR(11), access_code VARCHAR(12), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, data JSON, view_token VARCHAR(32))')
        cur.execute('CREATE TABLE IF NOT EXISTS one_time_codes (id SERIAL PRIMARY KEY, code VARCHAR(12) UNIQUE, used BOOLEAN DEFAULT FALSE, used_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP, code_type VARCHAR(20) DEFAULT \'single\')')
        au, ap = os.environ.get('ADMIN_USERNAME'), os.environ.get('ADMIN_PASSWORD')
        if au and ap:
            h = bcrypt.hashpw(ap.encode(), bcrypt.gensalt()).decode()
            cur.execute('INSERT INTO users (username, password, has_access, is_admin) VALUES (%s, %s, TRUE, TRUE) ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, is_admin = TRUE', (au, h))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e: print(f"DB error: {e}")

def serve_html(f):
    try:
        with open(f, 'r', encoding='utf-8') as file: 
            return Response(file.read(), mimetype='text/html; charset=utf-8')
    except: 
        return Response('<h1>404</h1>', status=404, mimetype='text/html; charset=utf-8')

@app.route('/')
@app.route('/admin-login.html')
def login_page(): return serve_html('admin-login.html')

@app.route('/admin.html')
def admin_page(): return serve_html('admin.html')

@app.route('/gen.html')
@app.route('/id.html')
@app.route('/home.html')
@app.route('/card.html')
def block(): return Response('<h1>404</h1>', status=404)

@app.route('/assets/<path:f>')
def assets(f): 
    response = send_from_directory('assets', f)
    if f.endswith('.css'):
        response.headers['Content-Type'] = 'text/css; charset=utf-8'
    elif f.endswith('.js'):
        response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return response

@app.route('/api/auth/admin-login', methods=['POST'])
@limiter.limit("3 per 15 minutes")
def admin_login():
    d = request.get_json() or {}
    u, p = sanitize(d.get('username', ''), 50), d.get('password', '')
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT * FROM users WHERE username = %s AND is_admin = TRUE', (u,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not user or not verify_password(p, user['password']): return jsonify({'error': 'Invalid credentials'}), 401
        return jsonify({'user_id': user['id'], 'username': user['username'], 'is_admin': True, 'token': gen_jwt(user['id'], user['username'])}), 200
    except Exception as e:
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/admin/users', methods=['GET'])
@require_admin
def get_users():
    conn = get_db()
    cur = conn.cursor(row_factory=dict_row)
    cur.execute('SELECT id, username, has_access, created_at, is_admin FROM users ORDER BY created_at DESC')
    users = [{'id': u['id'], 'username': u['username'], 'has_access': u['has_access'], 'is_admin': u['is_admin'], 'created_at': u['created_at'].isoformat() if u['created_at'] else None} for u in cur.fetchall()]
    cur.close()
    conn.close()
    return jsonify(users), 200

@app.route('/api/admin/documents', methods=['GET'])
@require_admin
def get_docs():
    conn = get_db()
    cur = conn.cursor(row_factory=dict_row)
    cur.execute('SELECT d.id, u.username, d.name, d.surname, d.pesel, d.access_code, d.created_at, d.view_token FROM generated_documents d LEFT JOIN users u ON d.user_id = u.id ORDER BY d.created_at DESC')
    docs = [{'id': d['id'], 'username': d['username'], 'name': d['name'], 'surname': d['surname'], 'pesel': d['pesel'], 'access_code': d['access_code'], 'created_at': d['created_at'].isoformat() if d['created_at'] else None, 'view_token': d['view_token']} for d in cur.fetchall()]
    cur.close()
    conn.close()
    return jsonify(docs), 200

@app.route('/api/admin/documents/<int:did>', methods=['DELETE'])
@require_admin
def del_doc(did):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM generated_documents WHERE id = %s', (did,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'message': 'Deleted'}), 200

@app.route('/api/admin/documents/<int:did>/data', methods=['GET'])
@require_admin
def get_doc_data(did):
    conn = get_db()
    cur = conn.cursor(row_factory=dict_row)
    cur.execute('SELECT data FROM generated_documents WHERE id = %s', (did,))
    r = cur.fetchone()
    cur.close()
    conn.close()
    if not r: return jsonify({'error': 'Not found'}), 404
    import json
    return jsonify(json.loads(r['data']) if isinstance(r['data'], str) else r['data']), 200

@app.route('/api/admin/generate-codes', methods=['POST'])
@require_admin
def gen_codes():
    d = request.get_json() or {}
    count = min(max(int(d.get('count', 1)), 1), 100)
    ctype = d.get('code_type', 'single')
    exp = None if ctype == 'pack' else datetime.utcnow() + timedelta(hours=ACCESS_CODE_TTL_HOURS)
    conn = get_db()
    cur = conn.cursor()
    codes = []
    for _ in range(count):
        c = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        cur.execute('INSERT INTO one_time_codes (code, expires_at, code_type) VALUES (%s, %s, %s)', (c, exp, ctype))
        codes.append(c)
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'codes': codes, 'expires_at': exp.isoformat() if exp else 'nigdy'}), 201

@app.route('/api/admin/codes', methods=['GET'])
@require_admin
def get_codes():
    # Parametr do włączenia/wyłączenia wygasłych kodów
    include_expired = request.args.get('include_expired', 'true').lower() == 'true'
    code_type = request.args.get('type')
    
    conn = get_db()
    cur = conn.cursor(row_factory=dict_row)
    
    if code_type:
        cur.execute('SELECT * FROM one_time_codes WHERE code_type = %s ORDER BY created_at DESC', (code_type,))
    else:
        cur.execute('SELECT * FROM one_time_codes ORDER BY created_at DESC')
    
    now = datetime.utcnow()
    codes = []
    for c in cur.fetchall():
        is_expired = c['expires_at'] and c['expires_at'] < now
        # Pomijaj wygasłe kody jeśli include_expired=false (dla pobierania)
        if is_expired and not include_expired:
            continue
        codes.append({
            'id': c['id'],
            'code': c['code'],
            'used': c['used'],
            'expired': is_expired,
            'code_type': c.get('code_type', 'single'),
            'created_at': c['created_at'].isoformat() if c['created_at'] else None,
            'expires_at': c['expires_at'].isoformat() if c['expires_at'] else None
        })
    cur.close()
    conn.close()
    return jsonify({'codes': codes}), 200

@app.route('/api/admin/clear-codes', methods=['DELETE'])
@require_admin
def clear_codes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM one_time_codes')
    n = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'message': f'Deleted {n} codes'}), 200

@app.route('/api/admin/delete-expired-codes', methods=['DELETE'])
@require_admin
def delete_expired_codes():
    """Usuń wszystkie wygasłe kody"""
    try:
        conn = get_db()
        cur = conn.cursor()
        now = datetime.utcnow()
        cur.execute('DELETE FROM one_time_codes WHERE expires_at IS NOT NULL AND expires_at < %s', (now,))
        deleted_count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Admin deleted {deleted_count} expired codes")
        return jsonify({'message': f'Usunięto {deleted_count} wygasłych kodów'}), 200
    except Exception as e:
        logger.error(f"Delete expired codes error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
