#!/usr/bin/env python3
# GENERATOR APP - Bez panelu admina
import os, re, json, secrets, logging
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
import bleach, requests as http_requests

load_dotenv()

TURNSTILE_SECRET = os.environ.get('TURNSTILE_SECRET_KEY', '')

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('generator')

app = Flask(__name__)
CORS(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["100 per hour"], storage_uri="memory://")

@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    return r

def sanitize(v, m=255):
    return bleach.clean(v, tags=[], strip=True)[:m] if isinstance(v, str) else v

def get_db():
    return psycopg.connect(os.environ.get('DATABASE_URL'))

def verify_turnstile(t):
    if not TURNSTILE_SECRET: return True
    try: return http_requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={'secret': TURNSTILE_SECRET, 'response': t}, timeout=5).json().get('success', False)
    except: return False

def serve_html(f):
    try:
        filepath = os.path.join(BASE_DIR, f)
        with open(filepath, 'r', encoding='utf-8') as file: 
            return Response(file.read(), mimetype='text/html; charset=utf-8')
    except: 
        return Response('<h1>404</h1>', status=404, mimetype='text/html; charset=utf-8')

# =============================================================================
# Static Assets Routes - MUST BE FIRST for priority
# =============================================================================

@app.route('/assets/<path:f>')
def assets(f): 
    try:
        filepath = os.path.join(BASE_DIR, 'assets', f)
        response = send_from_directory(os.path.join(BASE_DIR, 'assets'), f)
        if f.endswith('.css'):
            response.headers['Content-Type'] = 'text/css; charset=utf-8'
        elif f.endswith('.js'):
            response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
    except Exception as e:
        logger.error(f"Error serving asset {f}: {e}")
        return Response('Not found', status=404)

@app.route('/more_files/<path:f>')
def more_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'more_files'), f)

@app.route('/services_files/<path:f>')
def services_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'services_files'), f)

@app.route('/qr_files/<path:f>')
def qr_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'qr_files'), f)

@app.route('/showqr_files/<path:f>')
def showqr_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'showqr_files'), f)

@app.route('/scanqr_files/<path:f>')
def scanqr_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'scanqr_files'), f)

@app.route('/manifest.json')
def manifest():
    try:
        filepath = os.path.join(BASE_DIR, 'manifest.json')
        with open(filepath, 'r') as f: 
            return Response(f.read(), mimetype='application/manifest+json')
    except: 
        return jsonify({}), 404

# =============================================================================
# HTML Pages Routes
# =============================================================================

@app.route('/')
@app.route('/gen.html')
def gen(): return serve_html('gen.html')

@app.route('/id.html')
def id_page(): return serve_html('id.html')

@app.route('/home.html')
def home(): return serve_html('home.html')

@app.route('/card.html')
def card(): return serve_html('card.html')

@app.route('/more.html')
def more(): return serve_html('more.html')

@app.route('/services.html')
def services(): return serve_html('services.html')

@app.route('/qr.html')
def qr(): return serve_html('qr.html')

@app.route('/showqr.html')
def showqr(): return serve_html('showqr.html')

@app.route('/scanqr.html')
def scanqr(): return serve_html('scanqr.html')

@app.route('/moreid.html')
def moreid(): return serve_html('moreid.html')

@app.route('/pesel.html')
def pesel(): return serve_html('pesel.html')

@app.route('/shortcuts.html')
def shortcuts(): return serve_html('shortcuts.html')

# BLOKADA ADMINA
@app.route('/admin.html')
@app.route('/admin-login.html')
@app.route('/login.html')
def block(): return Response('<h1>404</h1>', status=404)

@app.route('/manifest.json')
def manifest():
    try:
        filepath = os.path.join(BASE_DIR, 'manifest.json')
        with open(filepath, 'r') as f: 
            return Response(f.read(), mimetype='application/manifest+json')
    except: 
        return jsonify({}), 404

@app.route('/assets/<path:f>')
def assets(f): 
    response = send_from_directory(os.path.join(BASE_DIR, 'assets'), f)
    if f.endswith('.css'):
        response.headers['Content-Type'] = 'text/css; charset=utf-8'
    elif f.endswith('.js'):
        response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@app.route('/more_files/<path:f>')
def more_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'more_files'), f)

@app.route('/services_files/<path:f>')
def services_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'services_files'), f)

@app.route('/qr_files/<path:f>')
def qr_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'qr_files'), f)

@app.route('/showqr_files/<path:f>')
def showqr_files(f): 
    return send_from_directory(os.path.join(BASE_DIR, 'showqr_files'), f)

@app.route('/scanqr_files/<path:f>')
def scanqr_files(f): return send_from_directory('scanqr_files', f)

@app.route('/api/auth/validate-code', methods=['POST'])
@limiter.limit("3 per 15 minutes")
def validate_code():
    d = request.get_json() or {}
    code = sanitize(d.get('code', ''), 12).strip().upper()
    if TURNSTILE_SECRET and d.get('turnstile_token') and not verify_turnstile(d.get('turnstile_token')):
        return jsonify({'error': 'CAPTCHA failed'}), 403
    if not code or not re.match(r'^[A-Z0-9]+$', code):
        return jsonify({'error': 'Invalid code'}), 400
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT id FROM one_time_codes WHERE code = %s AND used = FALSE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)', (code,))
        rec = cur.fetchone()
        if not rec:
            cur.close()
            conn.close()
            return jsonify({'error': 'Code invalid or used'}), 401
        cur.execute('UPDATE one_time_codes SET used = TRUE, used_at = CURRENT_TIMESTAMP WHERE id = %s', (rec['id'],))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'OK'}), 200
    except Exception as e:
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/documents/create-and-get-id', methods=['POST'])
@limiter.limit("10 per 15 minutes")
def create_doc():
    d = request.get_json() or {}
    token = secrets.token_urlsafe(16)
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('INSERT INTO generated_documents (user_id, name, surname, pesel, access_code, data, view_token) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id',
            (d.get('user_id'), sanitize(d.get('name'), 100), sanitize(d.get('surname'), 100), sanitize(d.get('pesel'), 11), sanitize(d.get('access_code'), 12), json.dumps(d), token))
        doc_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'document_id': doc_id, 'view_token': token}), 201
    except Exception as e:
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/documents/<int:did>', methods=['GET'])
def get_doc(did):
    token = request.args.get('token')
    if not token: return jsonify({'error': 'Token required'}), 403
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT data FROM generated_documents WHERE id = %s AND view_token = %s', (did, token))
        r = cur.fetchone()
        cur.close()
        conn.close()
        if not r: return jsonify({'error': 'Not found'}), 404
        return jsonify(json.loads(r['data']) if isinstance(r['data'], str) else r['data']), 200
    except: return jsonify({'error': 'Server error'}), 500

@app.route('/api/documents/<int:did>/check', methods=['GET'])
def check_doc(did):
    token = request.args.get('token')
    if not token: return jsonify({'error': 'Token required'}), 403
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT id FROM generated_documents WHERE id = %s AND view_token = %s', (did, token))
        exists = cur.fetchone() is not None
        cur.close()
        conn.close()
        return jsonify({'exists': exists}), 200
    except: return jsonify({'exists': False}), 200

# BLOKADA API ADMINA
@app.route('/api/admin/<path:p>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/api/auth/admin-login', methods=['POST'])
def block_admin_api(p=None): return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
