import os
from flask import Flask, request, jsonify
import hashlib
from datetime import datetime, timedelta
import secrets
import sqlite3
from functools import wraps

app = Flask(__name__)

# Configurações melhoradas
DATABASE = 'keys.db'
API_KEYS_TABLE = 'api_keys'
LOG_TABLE = 'access_logs'
MASTER_KEY = 'KURIOSOHDUSE7E454sdf564sd56f'  # Chave mestra - armazenar em variável de ambiente em produção
RATE_LIMIT = 100  # Limite de requisições por minuto por IP

# Melhoria: Adicionando cache simples para rate limiting
from collections import defaultdict
from time import time
request_log = defaultdict(list)

# Inicialização melhorada do banco de dados
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Tabela de chaves API com índices para melhor performance
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
            last_used TEXT,
            last_ip TEXT
        )
        ''')
        
        # Índices para consultas frequentes
        cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_api_key ON {API_KEYS_TABLE}(api_key)')
        cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_secret_hash ON {API_KEYS_TABLE}(secret_hash)')
        
        # Tabela de logs de acesso com mais informações
        cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {LOG_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            endpoint TEXT,
            access_time TEXT DEFAULT CURRENT_TIMESTAMP,
            status_code INTEGER,
            response_time REAL,
            FOREIGN KEY(api_key_id) REFERENCES {API_KEYS_TABLE}(id)
        )
        ''')
        
        cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_logs_time ON {LOG_TABLE}(access_time)')
        cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_logs_ip ON {LOG_TABLE}(ip_address)')

# Melhoria: Rate limiting básico
def check_rate_limit(ip):
    now = time()
    window = 60  # 1 minuto
    
    # Remove registros antigos
    request_log[ip] = [t for t in request_log[ip] if now - t < window]
    
    if len(request_log[ip]) >= RATE_LIMIT:
        return False
    
    request_log[ip].append(now)
    return True

# Geração de chaves melhorada
def generate_api_key(key_name, days_valid=30, usage_limit=1000):
    secret = secrets.token_hex(32)
    api_key = f"kd_{hashlib.sha256((secret + str(time())).encode()).hexdigest()[:32]}"
    secret_hash = hashlib.sha512((secret + MASTER_KEY).encode()).hexdigest()
    
    expires_at = (datetime.now() + timedelta(days=days_valid)).strftime('%Y-%m-%d %H:%M:%S')
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(f'''
        INSERT INTO {API_KEYS_TABLE} 
        (key_name, api_key, secret_hash, expires_at, usage_limit) 
        VALUES (?, ?, ?, ?, ?)
        ''', (key_name, api_key, secret_hash, expires_at, usage_limit))
    
    return {
        'key_name': key_name,
        'api_key': api_key,
        'secret_key': secret,  # Mostrado apenas uma vez!
        'expires_at': expires_at,
        'usage_limit': usage_limit,
        'warning': 'Guarde esta chave secreta com segurança! Ela não pode ser recuperada posteriormente.'
    }

# Validação de chave melhorada
def validate_api_key(api_key, secret, ip_address=None):
    try:
        secret_hash = hashlib.sha512((secret + MASTER_KEY).encode()).hexdigest()
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
            SELECT id, key_name, expires_at, is_active, usage_limit, usage_count, last_ip 
            FROM {API_KEYS_TABLE} 
            WHERE api_key = ? AND secret_hash = ?
            ''', (api_key, secret_hash))
            
            key_data = cursor.fetchone()
            
            if not key_data:
                return False, "Chave inválida"
                
            key_id, key_name, expires_at, is_active, usage_limit, usage_count, last_ip = key_data
            
            if not is_active:
                return False, "Chave desativada"
                
            if datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S') < datetime.now():
                return False, "Chave expirada"
                
            if usage_count >= usage_limit:
                return False, "Limite de uso atingido"
                
            # Atualiza o IP do último acesso
            if ip_address:
                cursor.execute(f'''
                UPDATE {API_KEYS_TABLE} 
                SET last_ip = ? 
                WHERE id = ?
                ''', (ip_address, key_id))
                conn.commit()
                
            return True, {
                'key_id': key_id,
                'key_name': key_name,
                'usage_remaining': usage_limit - usage_count,
                'last_ip': last_ip
            }
    except Exception as e:
        return False, f"Erro na validação: {str(e)}"

# Decorator para proteção de endpoints melhorado
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificação de rate limiting
        if not check_rate_limit(request.remote_addr):
            return jsonify({'error': 'Limite de requisições excedido. Tente novamente mais tarde.'}), 429
        
        api_key = request.headers.get('X-API-KEY')
        secret = request.headers.get('X-API-SECRET')
        
        if not api_key or not secret:
            log_access(None, request.remote_addr, request.user_agent.string, request.path, 401, 0)
            return jsonify({'error': 'Credenciais ausentes'}), 401
            
        start_time = time()
        is_valid, message = validate_api_key(api_key, secret, request.remote_addr)
        response_time = time() - start_time
        
        if not is_valid:
            log_access(None, request.remote_addr, request.user_agent.string, request.path, 403, response_time)
            return jsonify({'error': message}), 403
            
        key_info = message
        log_access(key_info['key_id'], request.remote_addr, request.user_agent.string, request.path, 200, response_time)
        
        # Atualiza contagem de uso
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
            UPDATE {API_KEYS_TABLE} 
            SET usage_count = usage_count + 1, last_used = CURRENT_TIMESTAMP 
            WHERE id = ?
            ''', (key_info['key_id'],))
        
        return f(*args, **kwargs, key_info=key_info)
    return decorated_function

# Log de acesso melhorado
def log_access(key_id, ip, user_agent, endpoint, status_code, response_time):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
            INSERT INTO {LOG_TABLE} 
            (api_key_id, ip_address, user_agent, endpoint, status_code, response_time) 
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (key_id, ip, user_agent, endpoint, status_code, response_time))
    except Exception as e:
        print(f"Erro ao registrar log: {str(e)}")

# Rotas da API melhoradas
@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    # Verificação de rate limiting
    if not check_rate_limit(request.remote_addr):
        return jsonify({'error': 'Limite de requisições excedido. Tente novamente mais tarde.'}), 429
    
    if request.headers.get('X-MASTER-KEY') != MASTER_KEY:
        log_access(None, request.remote_addr, request.user_agent.string, request.path, 403, 0)
        return jsonify({'error': 'Acesso não autorizado'}), 403
        
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados JSON inválidos'}), 400
        
    key_name = data.get('key_name')
    days_valid = data.get('days_valid', 30)
    usage_limit = data.get('usage_limit', 1000)
    
    if not key_name:
        return jsonify({'error': 'Nome da chave é obrigatório'}), 400
        
    try:
        new_key = generate_api_key(key_name, int(days_valid), int(usage_limit))
        log_access(None, request.remote_addr, request.user_agent.string, request.path, 201, 0)
        return jsonify(new_key), 201
    except Exception as e:
        log_access(None, request.remote_addr, request.user_agent.string, request.path, 500, 0)
        return jsonify({'error': str(e)}), 500

@app.route('/protected_endpoint', methods=['GET'])
@api_key_required
def protected_endpoint(key_info):
    # Exemplo de endpoint protegido
    return jsonify({
        'message': 'Acesso autorizado',
        'key_info': {
            'key_name': key_info['key_name'],
            'usage_remaining': key_info['usage_remaining']
        },
        'data': {
            'timestamp': datetime.now().isoformat(),
            'status': 'active'
        }
    })

@app.route('/key_status/<api_key>', methods=['GET'])
def key_status(api_key):
    # Verificação de rate limiting
    if not check_rate_limit(request.remote_addr):
        return jsonify({'error': 'Limite de requisições excedido. Tente novamente mais tarde.'}), 429
    
    start_time = time()
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(f'''
        SELECT key_name, created_at, expires_at, is_active, usage_limit, usage_count, last_used, last_ip 
        FROM {API_KEYS_TABLE} 
        WHERE api_key = ?
        ''', (api_key,))
        
        key_data = cursor.fetchone()
    
    response_time = time() - start_time
    
    if not key_data:
        log_access(None, request.remote_addr, request.user_agent.string, request.path, 404, response_time)
        return jsonify({'error': 'Chave não encontrada'}), 404
        
    log_access(None, request.remote_addr, request.user_agent.string, request.path, 200, response_time)
    
    return jsonify({
        'key_name': key_data[0],
        'created_at': key_data[1],
        'expires_at': key_data[2],
        'is_active': bool(key_data[3]),
        'usage_limit': key_data[4],
        'usage_count': key_data[5],
        'last_used': key_data[6],
        'last_ip': key_data[7],
        'usage_remaining': key_data[4] - key_data[5]
    })

# Rota de saúde para monitoramento
@app.route('/health', methods=['GET'])
def health_check():
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('SELECT 1')
        return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    # Removido o SSL context e adicionado debug=False para produção
    app.run(host='0.0.0.0', port=5000, debug=False)
