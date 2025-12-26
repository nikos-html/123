#!/usr/bin/env python3
# GENERATOR APP - Prosty generator dokumentów (bez admin)
import os
import logging
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

load_dotenv()

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
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return r

def get_db():
    return psycopg.connect(os.environ.get('DATABASE_URL'))

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
def index():
    return serve_html('gen.html')

@app.route('/gen.html')
def gen(): 
    return serve_html('gen.html')

@app.route('/id.html')
def id_page(): 
    return serve_html('id.html')

@app.route('/home.html')
def home(): 
    return serve_html('home.html')

@app.route('/card.html')
def card(): 
    return serve_html('card.html')

@app.route('/more.html')
def more(): 
    return serve_html('more.html')

@app.route('/services.html')
def services(): 
    return serve_html('services.html')

@app.route('/qr.html')
def qr(): 
    return serve_html('qr.html')

@app.route('/showqr.html')
def showqr(): 
    return serve_html('showqr.html')

@app.route('/scanqr.html')
def scanqr(): 
    return serve_html('scanqr.html')

@app.route('/moreid.html')
def moreid(): 
    return serve_html('moreid.html')

@app.route('/pesel.html')
def pesel(): 
    return serve_html('pesel.html')

@app.route('/shortcuts.html')
def shortcuts(): 
    return serve_html('shortcuts.html')

# =============================================================================
# API Routes (simplified - no auth needed for generator)
# =============================================================================

# =============================================================================
# API Routes - Document validation with tokens
# =============================================================================

@app.route('/api/documents/<int:document_id>/check', methods=['GET'])
def check_document_exists(document_id):
    """
    Check if document exists with valid token
    """
    view_token = request.args.get('token')
    
    if document_id <= 0:
        return jsonify({'exists': False}), 200
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        if view_token:
            cur.execute('SELECT id FROM generated_documents WHERE id = %s AND view_token = %s', (document_id, view_token))
        else:
            cur.close()
            conn.close()
            return jsonify({'error': 'Token required'}), 403
        
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        return jsonify({'exists': result is not None}), 200
        
    except Exception as e:
        logger.error(f"Document check error: {e}")
        return jsonify({'exists': False}), 200

@app.route('/api/documents/<int:document_id>', methods=['GET'])
def get_document(document_id):
    """
    Get document data with valid token
    """
    view_token = request.args.get('token')
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        if view_token:
            cur.execute('SELECT data FROM generated_documents WHERE id = %s AND view_token = %s', (document_id, view_token))
        else:
            cur.close()
            conn.close()
            return jsonify({'error': 'Token required'}), 403
        
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result:
            return jsonify(result['data']), 200
        else:
            return jsonify({'error': 'Document not found'}), 404
            
    except Exception as e:
        logger.error(f"Get document error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/validate-code', methods=['POST'])
@limiter.limit("3 per 15 minutes")
def validate_code():
    # Simplified version - just return success for testing
    return jsonify({'valid': True}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
