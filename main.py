import os
from flask import Flask, request, jsonify
import hashlib
from datetime import datetime, timedelta
import secrets
import sqlite3
from functools import wraps

app = Flask(__name__)

# Configurações
DATABASE = 'keys.db'
API_KEYS_TABLE = 'api_keys'
LOG_TABLE = 'access_logs'
MASTER_KEY = 'KURIOSOHDUSE7E454sdf564sd56f'  # Troque por uma chave forte

# Inicialização do banco de dados
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Tabela de chaves API
    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS {API_KEYS_TABLE} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_name TEXT NOT NULL,
        api_key TEXT NOT NULL UNIQUE,
        secret_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT,
        is_active INTEGER DEFAULT 1,
        usage_limit INTEGER DEFAULT 1000,
        usage_count INTEGER DEFAULT 0,
        last_used TEXT
    )
    ''')
    
    # Tabela de logs de acesso
    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS {LOG_TABLE} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key_id INTEGER,
        ip_address TEXT,
        endpoint TEXT,
        access_time TEXT DEFAULT CURRENT_TIMESTAMP,
        status_code INTEGER,
        FOREIGN KEY(api_key_id) REFERENCES {API_KEYS_TABLE}(id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Geração de chaves
def generate_api_key(key_name, days_valid=30, usage_limit=1000):
    secret = secrets.token_hex(32)
    api_key = f"kd_{hashlib.sha256(secret.encode()).hexdigest()[:32]}"
    secret_hash = hashlib.sha512((secret + MASTER_KEY).encode()).hexdigest()
    
    expires_at = (datetime.now() + timedelta(days=days_valid)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f'''
    INSERT INTO {API_KEYS_TABLE} 
    (key_name, api_key, secret_hash, expires_at, usage_limit) 
    VALUES (?, ?, ?, ?, ?)
    ''', (key_name, api_key, secret_hash, expires_at, usage_limit))
    conn.commit()
    conn.close()
    
    return {
        'key_name': key_name,
        'api_key': api_key,
        'secret_key': secret,  # Mostrado apenas uma vez!
        'expires_at': expires_at,
        'usage_limit': usage_limit
    }

# Validação de chave
def validate_api_key(api_key, secret):
    try:
        secret_hash = hashlib.sha512((secret + MASTER_KEY).encode()).hexdigest()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(f'''
        SELECT id, key_name, expires_at, is_active, usage_limit, usage_count 
        FROM {API_KEYS_TABLE} 
        WHERE api_key = ? AND secret_hash = ?
        ''', (api_key, secret_hash))
        
        key_data = cursor.fetchone()
        conn.close()
        
        if not key_data:
            return False, "Chave inválida"
            
        key_id, key_name, expires_at, is_active, usage_limit, usage_count = key_data
        
        if not is_active:
            return False, "Chave desativada"
            
        if datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S') < datetime.now():
            return False, "Chave expirada"
            
        if usage_count >= usage_limit:
            return False, "Limite de uso atingido"
            
        return True, {
            'key_id': key_id,
            'key_name': key_name,
            'usage_remaining': usage_limit - usage_count
        }
    except Exception as e:
        return False, f"Erro na validação: {str(e)}"

# Decorator para proteção de endpoints
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        secret = request.headers.get('X-API-SECRET')
        
        if not api_key or not secret:
            return jsonify({'error': 'Credenciais ausentes'}), 401
            
        is_valid, message = validate_api_key(api_key, secret)
        
        if not is_valid:
            log_access(None, request.remote_addr, request.path, 401)
            return jsonify({'error': message}), 403
            
        key_info = message
        log_access(key_info['key_id'], request.remote_addr, request.path, 200)
        
        # Atualiza contagem de uso
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(f'''
        UPDATE {API_KEYS_TABLE} 
        SET usage_count = usage_count + 1, last_used = CURRENT_TIMESTAMP 
        WHERE id = ?
        ''', (key_info['key_id'],))
        conn.commit()
        conn.close()
        
        return f(*args, **kwargs, key_info=key_info)
    return decorated_function

# Log de acesso
def log_access(key_id, ip, endpoint, status_code):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(f'''
        INSERT INTO {LOG_TABLE} 
        (api_key_id, ip_address, endpoint, status_code) 
        VALUES (?, ?, ?, ?)
        ''', (key_id, ip, endpoint, status_code))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao registrar log: {str(e)}")

# Rotas da API
@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    if request.headers.get('X-MASTER-KEY') != MASTER_KEY:
        return jsonify({'error': 'Acesso não autorizado'}), 403
        
    data = request.get_json()
    key_name = data.get('key_name')
    days_valid = data.get('days_valid', 30)
    usage_limit = data.get('usage_limit', 1000)
    
    if not key_name:
        return jsonify({'error': 'Nome da chave é obrigatório'}), 400
        
    new_key = generate_api_key(key_name, days_valid, usage_limit)
    return jsonify(new_key), 201

@app.route('/protected_endpoint', methods=['GET'])
@api_key_required
def protected_endpoint(key_info):
    return jsonify({
        'message': 'Acesso autorizado',
        'key_info': key_info,
        'data': {'exemplo': 'dados_protegidos'}
    })

@app.route('/key_status/<api_key>', methods=['GET'])
def key_status(api_key):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f'''
    SELECT key_name, created_at, expires_at, is_active, usage_limit, usage_count, last_used 
    FROM {API_KEYS_TABLE} 
    WHERE api_key = ?
    ''', (api_key,))
    
    key_data = cursor.fetchone()
    conn.close()
    
    if not key_data:
        return jsonify({'error': 'Chave não encontrada'}), 404
        
    return jsonify({
        'key_name': key_data[0],
        'created_at': key_data[1],
        'expires_at': key_data[2],
        'is_active': bool(key_data[3]),
        'usage_limit': key_data[4],
        'usage_count': key_data[5],
        'last_used': key_data[6],
        'usage_remaining': key_data[4] - key_data[5]
    })

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')