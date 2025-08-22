from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
import os #te da herramientas para que tu aplicación sea más flexible y pueda adaptarse a diferentes entornos sin cambiar código usando variables de entorno
import logging
import time
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)
app.secret_key = 'my-super-secret-key-for-sessions-12345'

# Configurar logging para mejor debugging
logging.basicConfig(level=logging.DEBUG)

# Configuración de sesiones para desarrollo local
app.config['SESSION_COOKIE_SECURE'] = False  # False para HTTP
app.config['SESSION_COOKIE_HTTPONLY'] = False  # False para debugging (cambiar a True en producción)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Cambiar de None a Lax para desarrollo local
app.config['SESSION_COOKIE_DOMAIN'] = None  # Sin dominio específico
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hora

# CORS configuración para Ingress - mismo dominio
CORS(app, 
     origins=['http://taskmanager.local'],  # Solo el dominio del Ingress
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     supports_credentials=True,
     expose_headers=['Set-Cookie'])

# ===== MÉTRICAS DE PROMETHEUS =====
# Contadores
requests_total = Counter('taskmanager_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
users_registered_total = Counter('taskmanager_users_registered_total', 'Total users registered')
users_login_total = Counter('taskmanager_users_login_total', 'Total login attempts', ['status'])
tasks_created_total = Counter('taskmanager_tasks_created_total', 'Total tasks created')

# Histogramas para medir tiempo
request_duration = Histogram('taskmanager_request_duration_seconds', 'Request duration', ['endpoint'])
login_duration = Histogram('taskmanager_login_duration_seconds', 'Login duration')

# Gauges para valores actuales
active_sessions = Gauge('taskmanager_active_sessions', 'Number of active sessions')
total_tasks = Gauge('taskmanager_total_tasks', 'Total number of tasks in database')
total_users = Gauge('taskmanager_total_users', 'Total number of users in database')

# Variable para trackear sesiones activas en memoria
active_sessions_count = 0

# Middleware para medir todas las requests
@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    # Medir duración de la request
    duration = time.time() - request.start_time
    
    # Actualizar métricas
    endpoint = request.endpoint or 'unknown'
    requests_total.labels(
        method=request.method,
        endpoint=endpoint,
        status=response.status_code
    ).inc()
    
    request_duration.labels(endpoint=endpoint).observe(duration)
    
    return response

def get_db():
    conn = sqlite3.connect('/app/data/users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/register', methods=['POST'])
def register():
    start_time = time.time()
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password are required'}), 400
        
        app.logger.info(f"[REGISTER] Attempting to register: {email}")
        
        conn = get_db()
        conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password))
        conn.commit()
        conn.close()
        
        # Actualizar métricas
        users_registered_total.inc()
        update_user_count()
        
        app.logger.info(f"[REGISTER] Success for {email}")
        return jsonify({'message': 'User registered successfully', 'success': True})
        
    except sqlite3.IntegrityError:
        app.logger.warning(f"[REGISTER] User already exists: {email}")
        return jsonify({'message': 'User already exists', 'success': False}), 400
    except Exception as e:
        app.logger.error(f"[REGISTER] Error: {e}")
        return jsonify({'message': 'Registration failed', 'success': False}), 500

@app.route('/login', methods=['POST'])
def login():
    start_time = time.time()
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            users_login_total.labels(status='error').inc()
            return jsonify({'message': 'Email and password are required'}), 400
        
        app.logger.info(f"[LOGIN] Attempting login for: {email}")
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND password = ?', 
                          (email, password)).fetchone()
        conn.close()
        
        if user:
            # Limpiar sesión anterior
            session.clear()
            
            # Establecer nueva sesión
            session['email'] = email
            session['logged_in'] = True
            session.permanent = True  # Hacer la sesión permanente
            
            # Actualizar métricas
            users_login_total.labels(status='success').inc()
            login_duration.observe(time.time() - start_time)
            
            # Incrementar sesiones activas
            global active_sessions_count
            active_sessions_count += 1
            active_sessions.set(active_sessions_count)
            
            app.logger.info(f"[LOGIN] SUCCESS - Session set for: {email}")
            app.logger.debug(f"[LOGIN] Session ID: {request.cookies.get('session', 'No session cookie')}")
            app.logger.debug(f"[LOGIN] Session contents after login: {dict(session)}")
            
            # Crear respuesta con headers explícitos para cookies
            response = jsonify({
                'message': 'Login successful',
                'success': True,
                'email': email
            })
            
            # Forzar el guardado de la sesión
            session.modified = True
            
            # Headers adicionales para CORS con credenciales
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            
            return response
        else:
            users_login_total.labels(status='failed').inc()
            app.logger.warning(f"[LOGIN] FAILED - Invalid credentials for: {email}")
            return jsonify({'message': 'Invalid credentials', 'success': False}), 401
            
    except Exception as e:
        users_login_total.labels(status='error').inc()
        app.logger.error(f"[LOGIN] Error: {e}")
        return jsonify({'message': 'Login failed', 'success': False}), 500

@app.route('/tasks', methods=['GET', 'POST', 'OPTIONS'])
def tasks():
    # Manejar preflight OPTIONS
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200
    
    app.logger.info(f"[TASKS] Request method: {request.method}")
    app.logger.info(f"[TASKS] All cookies: {dict(request.cookies)}")
    app.logger.info(f"[TASKS] Session contents: {dict(session)}")
    app.logger.info(f"[TASKS] Origin: {request.headers.get('Origin', 'No origin')}")
    
    # Verificar autenticación
    if 'email' not in session or not session.get('logged_in', False):
        app.logger.warning(f"[TASKS] UNAUTHORIZED - No valid session")
        app.logger.debug(f"[TASKS] Session keys: {list(session.keys())}")
        response = jsonify({'message': 'Unauthorized - Please login first', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 401
    
    email = session['email']
    app.logger.info(f"[TASKS] Authenticated user: {email}")
    
    try:
        conn = get_db()
        
        if request.method == 'GET':
            app.logger.info(f"[TASKS] Getting tasks for: {email}")
            # Obtener tareas propias y compartidas
            tasks = conn.execute('''
                SELECT DISTINCT t.*, 
                       CASE WHEN t.user_email = ? THEN 'owner' ELSE 'shared' END as access_type,
                       t.user_email as original_owner
                FROM tasks t
                LEFT JOIN task_shares ts ON t.id = ts.task_id
                WHERE t.user_email = ? OR ts.shared_with_email = ?
                ORDER BY t.created_at DESC
            ''', (email, email, email)).fetchall()
            
            task_list = []
            for task in tasks:
                task_dict = dict(task)
                # Obtener usuarios con los que está compartida la tarea
                shared_with = conn.execute('''
                    SELECT shared_with_email FROM task_shares WHERE task_id = ?
                ''', (task['id'],)).fetchall()
                task_dict['shared_with'] = [row[0] for row in shared_with]
                task_list.append(task_dict)
                
            app.logger.info(f"[TASKS] Found {len(task_list)} tasks for {email}")
            conn.close()
            
            response = jsonify({
                'tasks': task_list,
                'count': len(task_list),
                'success': True
            })
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
            
        elif request.method == 'POST':
            data = request.json
            title = data.get('title')
            
            if not title or not title.strip():
                response = jsonify({'message': 'Title is required', 'success': False})
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response, 400
            
            app.logger.info(f"[TASKS] Adding task '{title}' for: {email}")
            
            cursor = conn.execute('INSERT INTO tasks (title, user_email) VALUES (?, ?)', 
                                 (title.strip(), email))
            task_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Actualizar métricas
            tasks_created_total.inc()
            update_task_count()
            
            app.logger.info(f"[TASKS] Task added successfully with ID: {task_id}")
            response = jsonify({
                'message': 'Task added successfully',
                'task_id': task_id,
                'success': True
            })
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
            
    except Exception as e:
        app.logger.error(f"[TASKS] Error: {e}")
        response = jsonify({'message': f'Server error: {str(e)}', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 500

@app.route('/tasks/<int:task_id>/toggle', methods=['PUT'])
def toggle_task(task_id):
    """Marcar/desmarcar una tarea como completada"""
    if 'email' not in session or not session.get('logged_in', False):
        response = jsonify({'message': 'Unauthorized', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 401
    
    email = session['email']
    
    try:
        conn = get_db()
        
        # Verificar que el usuario tenga acceso a esta tarea (propietario o compartida)
        task = conn.execute('''
            SELECT t.*, 
                   CASE WHEN t.user_email = ? THEN 1 ELSE 0 END as is_owner
            FROM tasks t
            LEFT JOIN task_shares ts ON t.id = ts.task_id
            WHERE t.id = ? AND (t.user_email = ? OR ts.shared_with_email = ?)
        ''', (email, task_id, email, email)).fetchone()
        
        if not task:
            conn.close()
            response = jsonify({'message': 'Task not found or access denied', 'success': False})
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 404
        
        # Cambiar el estado
        new_status = not bool(task['completed'])
        conn.execute('''
            UPDATE tasks 
            SET completed = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (new_status, task_id))
        conn.commit()
        conn.close()
        
        app.logger.info(f"[TOGGLE] Task {task_id} marked as {'completed' if new_status else 'incomplete'} by {email}")
        
        response = jsonify({
            'message': f"Task marked as {'completed' if new_status else 'incomplete'}",
            'task_id': task_id,
            'completed': new_status,
            'success': True
        })
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        app.logger.error(f"[TOGGLE] Error: {e}")
        response = jsonify({'message': f'Server error: {str(e)}', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 500

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    """Eliminar una tarea (solo el propietario)"""
    if 'email' not in session or not session.get('logged_in', False):
        response = jsonify({'message': 'Unauthorized', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 401
    
    email = session['email']
    
    try:
        conn = get_db()
        
        # Verificar que el usuario sea el propietario
        task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_email = ?', 
                           (task_id, email)).fetchone()
        
        if not task:
            conn.close()
            response = jsonify({'message': 'Task not found or you are not the owner', 'success': False})
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 404
        
        # Eliminar las comparticiones primero
        conn.execute('DELETE FROM task_shares WHERE task_id = ?', (task_id,))
        
        # Eliminar la tarea
        conn.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
        conn.commit()
        conn.close()
        
        # Actualizar métricas
        update_task_count()
        
        app.logger.info(f"[DELETE] Task {task_id} deleted by {email}")
        
        response = jsonify({
            'message': 'Task deleted successfully',
            'task_id': task_id,
            'success': True
        })
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        app.logger.error(f"[DELETE] Error: {e}")
        response = jsonify({'message': f'Server error: {str(e)}', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 500

@app.route('/tasks/bulk-toggle', methods=['PUT'])
def bulk_toggle_tasks():
    """Marcar todas las tareas como completadas o incompletas"""
    if 'email' not in session or not session.get('logged_in', False):
        response = jsonify({'message': 'Unauthorized', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 401
    
    email = session['email']
    data = request.json
    completed = data.get('completed', True)
    
    try:
        conn = get_db()
        
        # Actualizar todas las tareas del usuario (propias y compartidas)
        result = conn.execute('''
            UPDATE tasks 
            SET completed = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id IN (
                SELECT DISTINCT t.id FROM tasks t
                LEFT JOIN task_shares ts ON t.id = ts.task_id
                WHERE t.user_email = ? OR ts.shared_with_email = ?
            )
        ''', (completed, email, email))
        
        affected_rows = result.rowcount
        conn.commit()
        conn.close()
        
        app.logger.info(f"[BULK_TOGGLE] {affected_rows} tasks marked as {'completed' if completed else 'incomplete'} by {email}")
        
        response = jsonify({
            'message': f'{affected_rows} tasks marked as {"completed" if completed else "incomplete"}',
            'affected_count': affected_rows,
            'completed': completed,
            'success': True
        })
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        app.logger.error(f"[BULK_TOGGLE] Error: {e}")
        response = jsonify({'message': f'Server error: {str(e)}', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 500

@app.route('/tasks/<int:task_id>/share', methods=['POST'])
def share_task(task_id):
    """Compartir una tarea con otros usuarios"""
    if 'email' not in session or not session.get('logged_in', False):
        response = jsonify({'message': 'Unauthorized', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 401
    
    email = session['email']
    data = request.json
    share_with_emails = data.get('emails', [])
    
    if not share_with_emails:
        response = jsonify({'message': 'No emails provided', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 400
    
    try:
        conn = get_db()
        
        # Verificar que el usuario sea el propietario de la tarea
        task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_email = ?', 
                           (task_id, email)).fetchone()
        
        if not task:
            conn.close()
            response = jsonify({'message': 'Task not found or you are not the owner', 'success': False})
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 404
        
        shared_count = 0
        errors = []
        
        for share_email in share_with_emails:
            share_email = share_email.strip().lower()
            
            # Verificar que el usuario existe
            user_exists = conn.execute('SELECT email FROM users WHERE email = ?', 
                                     (share_email,)).fetchone()
            
            if not user_exists:
                errors.append(f"User {share_email} does not exist")
                continue
            
            if share_email == email:
                errors.append("Cannot share with yourself")
                continue
            
            # Intentar compartir (ignorar si ya está compartida)
            try:
                conn.execute('''
                    INSERT INTO task_shares (task_id, shared_with_email, shared_by_email)
                    VALUES (?, ?, ?)
                ''', (task_id, share_email, email))
                shared_count += 1
            except sqlite3.IntegrityError:
                errors.append(f"Task already shared with {share_email}")
        
        conn.commit()
        conn.close()
        
        app.logger.info(f"[SHARE] Task {task_id} shared with {shared_count} users by {email}")
        
        response = jsonify({
            'message': f'Task shared with {shared_count} users',
            'shared_count': shared_count,
            'errors': errors,
            'success': True
        })
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        app.logger.error(f"[SHARE] Error: {e}")
        response = jsonify({'message': f'Server error: {str(e)}', 'success': False})
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 500

@app.route('/logout', methods=['POST'])
def logout():
    """Endpoint para cerrar sesión"""
    email = session.get('email', 'Unknown')
    session.clear()
    app.logger.info(f"[LOGOUT] User {email} logged out")
    response = jsonify({'message': 'Logged out successfully', 'success': True})
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

@app.route('/check-auth', methods=['GET'])
def check_auth():
    """Verificar si el usuario está autenticado"""
    app.logger.info(f"[CHECK-AUTH] Session: {dict(session)}")
    app.logger.info(f"[CHECK-AUTH] Cookies: {dict(request.cookies)}")
    
    if 'email' in session and session.get('logged_in', False):
        response = jsonify({
            'authenticated': True,
            'email': session['email'],
            'success': True
        })
    else:
        response = jsonify({
            'authenticated': False,
            'success': True
        })
    
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

@app.route('/debug-session', methods=['GET'])
def debug_session():
    """Endpoint de debugging para verificar el estado de la sesión"""
    session_info = {
        'session_keys': list(session.keys()),
        'email_in_session': 'email' in session,
        'logged_in': session.get('logged_in', False),
        'session_email': session.get('email', 'No email'),
        'session_data': dict(session),
        'cookies': dict(request.cookies),
        'headers': dict(request.headers),
        'origin': request.headers.get('Origin', 'No origin')
    }
    app.logger.debug(f"[DEBUG] Session info: {session_info}")
    response = jsonify(session_info)
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        email = data.get('email')
        new_password = data.get('new_password')
        
        if not email or not new_password:
            return jsonify({'message': 'Email and new password are required', 'success': False}), 400
        
        app.logger.info(f"[RESET] Password reset for: {email}")
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            conn.execute('UPDATE users SET password = ? WHERE email = ?', (new_password, email))
            conn.commit()
            conn.close()
            app.logger.info(f"[RESET] Password updated for {email}")
            return jsonify({'message': 'Password updated successfully', 'success': True})
        else:
            conn.close()
            app.logger.warning(f"[RESET] Email not found: {email}")
            return jsonify({'message': 'Email not found', 'success': False}), 404
            
    except Exception as e:
        app.logger.error(f"[RESET] Error: {e}")
        return jsonify({'message': 'Reset failed', 'success': False}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'task-manager-backend'})

# ===== ENDPOINT DE MÉTRICAS =====
@app.route('/metrics', methods=['GET'])
def metrics():
    """Endpoint que expone métricas para VictoriaMetrics"""
    # Actualizar métricas actuales antes de exportar
    update_all_gauges()
    
    # Generar el formato de métricas de Prometheus
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

# ===== FUNCIONES AUXILIARES PARA MÉTRICAS =====
def update_user_count():
    """Actualizar el conteo total de usuarios"""
    try:
        conn = get_db()
        count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        conn.close()
        total_users.set(count)
    except Exception as e:
        app.logger.error(f"Error updating user count: {e}")

def update_task_count():
    """Actualizar el conteo total de tareas"""
    try:
        conn = get_db()
        count = conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]
        conn.close()
        total_tasks.set(count)
    except Exception as e:
        app.logger.error(f"Error updating task count: {e}")

def update_active_sessions():
    """Actualizar el conteo de sesiones activas"""
    # Para simplificar, asumimos que cada login válido es una sesión activa
    # En un escenario real, tendrías una tabla de sesiones
    active_sessions.inc()

def update_all_gauges():
    """Actualizar todas las métricas tipo Gauge"""
    update_user_count()
    update_task_count()
    # active_sessions ya se actualiza en login/logout

if __name__ == '__main__':
    print("[STARTUP] Starting Task Manager Backend...")
    
    # Asegurar que el directorio existe
    os.makedirs('/app/data', exist_ok=True)
    
    # Crear las tablas
    conn = sqlite3.connect('/app/data/users.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY, 
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        title TEXT NOT NULL, 
        user_email TEXT NOT NULL,
        completed BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_email) REFERENCES users(email)
    )''')
    # Nueva tabla para tareas compartidas
    conn.execute('''CREATE TABLE IF NOT EXISTS task_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        shared_with_email TEXT NOT NULL,
        shared_by_email TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(id),
        FOREIGN KEY (shared_with_email) REFERENCES users(email),
        FOREIGN KEY (shared_by_email) REFERENCES users(email),
        UNIQUE(task_id, shared_with_email)
    )''')
    conn.close()
    
    print("[STARTUP] Database ready. Starting Flask app...")
    app.run(host='0.0.0.0', port=5000, debug=True)