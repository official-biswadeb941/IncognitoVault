# Standard library imports
import string, os, json, secrets, base64, hmac, secrets, hashlib, logging
from io import BytesIO
from datetime import timedelta, datetime
from collections import deque

# Third-party imports
from flask import Flask, render_template, redirect, session, request, make_response, jsonify, Response, current_app
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session 
from flask_cors import CORS
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# Custom module imports
from Modules.error_handler import ErrorHandler
from Modules.redis_manager import *
from Modules.db_manager import db_manager
from Modules.session import generate_session_key, generate_key
from Modules.form import LoginForm
from Modules.captcha_manager import captcha

# functools is not removed since it's probably used for decorators (verify before removing)
from functools import wraps

################### Initialization and Configuration ########################
app = Flask(__name__)
error_handler = ErrorHandler(app)
app.config['error_handler'] = error_handler
app.secret_key = generate_key()
HMAC_SECRET = app.secret_key

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
LOCKOUT_INCREMENT = timedelta(minutes=5)

app.config.update({
    'ENV': 'development',
    'WTF_CSRF_ENABLED': True,
    'SESSION_TYPE': 'redis',
    'SESSION_PERMANENT': False,
    'SESSION_USE_SIGNER': True,
    'SESSION_KEY_PREFIX': 'session:',
    'SEND_FILE_MAX_AGE_DEFAULT': timedelta(days=0),
    #'SESSION_COOKIE_SECURE': True,
    #'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',  # CSRF protection
    'WTF_CSRF_TIME_LIMIT': None,
    'PERMANENT_SESSION_LIFETIME': timedelta(seconds=60)
})

redis_conn = get_redis_connection() 
cache = configure_cache(app)
app.config['SESSION_REDIS'] = redis_conn

Session(app)
csrf = CSRFProtect(app)
csrf.init_app(app)
CORS(app)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=get_redis_uri(),  # Avoid redundant redis_conn here
    app=app,
)

SESSION_TIMEOUT = 60
app.permanent_session_lifetime = timedelta(seconds=SESSION_TIMEOUT)
request_times = deque()  
window_duration = timedelta(minutes=1)

ph = PasswordHasher()

####################### Utility Functions #####################

# Utility Function to get a DB connection
def get_db_connection():
    return db_manager.get_connection()

def create_super_admin():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SHOW TABLES LIKE 'super_admin'")
            if cursor.fetchone():
                print("Super admin table already exists.")
                return None
            else:
                sql = """
                CREATE TABLE super_admin (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    is_super_admin BOOLEAN NOT NULL DEFAULT FALSE,
                    failed_attempts INT DEFAULT 0,
                    lockout_expiration DATETIME DEFAULT NULL
                );
                """
                cursor.execute(sql)
                conn.commit()
                print("Super admin table created successfully.")
            cursor.execute("SELECT COUNT(*) FROM super_admin WHERE is_super_admin = TRUE")
            super_admin_exists = cursor.fetchone()['COUNT(*)'] > 0
            if super_admin_exists:
                print("Super admin already exists in the database.")
                return 
            config_folder = 'Config'
            credentials_file = os.path.join(config_folder, 'creds.json')
            with open(credentials_file, 'r') as f:
                creds = json.load(f)
            default_username = creds.get('username')
            default_password = hash_password(creds.get('password'))
            default_role = creds.get('role')
            cursor.execute(
                "INSERT INTO super_admin (username, password, role, is_super_admin) VALUES (%s, %s, %s, TRUE)",
                (default_username, default_password, default_role)
            )
            conn.commit()
            print("Default super admin user inserted successfully.")
    except Exception as e:
        print(f"Error creating table or default admin user: {e}")
    finally:
        conn.close()

def hash_password(password):
    return ph.hash(password)

def verify_password(stored_hash, password):
    try:
        ph.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False

def generate_random_string(length=8):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_user_id(username):
    return f"{username}-{generate_random_string()}"

def generate_app_id():
    return f"IncognitoVault-{generate_random_string(8)}"

app_id = generate_app_id()
create_super_admin()

###################### Security and Middleware Functions #######################
@app.after_request
def set_security_headers(response):
    if 'user' in session and 'username' in session and 'user_id' in session:
        response.headers['X-Username'] = session['username']
        response.headers['X-User-ID'] = session['user_id']
    response.headers['X-App-ID'] = app_id
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    if app.config['ENV'] == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def generate_session_signature(session_data):
    """Generate a HMAC signature for the session data."""
    return hmac.new(HMAC_SECRET.encode(), session_data.encode(), hashlib.sha256).hexdigest()

def push_data_with_dynamic_ttl(redis_conn, session_id, session_data, timeout):
    try:
        if isinstance(session_data, str):
            session_data = json.loads(session_data)
        if 'lockout_expiration' in session_data and isinstance(session_data['lockout_expiration'], datetime):
            session_data['lockout_expiration'] = session_data['lockout_expiration'].strftime('%Y-%m-%d %H:%M:%S')
        session_data_json = json.dumps(session_data)
        session_signature = generate_session_signature(session_data_json)
        redis_conn.set(f'session:{session_id}', json.dumps({'data': session_data_json, 'signature': session_signature}), ex=timeout)
    except Exception as e:
        logging.error(f"Error pushing data with dynamic TTL: {e}")

def manage_session_and_https():
    session_id = request.cookies.get('session_id')
    if session_id:
        try:
            session_info = redis_conn.get(f'session:{session_id}')
            if session_info:
                session_info = json.loads(session_info.decode('utf-8'))
                session_data = json.loads(session_info['data'])  # Convert string to dictionary here
                stored_signature = session_info['signature']
                if 'lockout_expiration' in session_data:
                    session_data['lockout_expiration'] = datetime.strptime(session_data['lockout_expiration'], '%Y-%m-%d %H:%M:%S')
                if stored_signature != generate_session_signature(session_data):
                    pop_data(redis_conn, f'session:{session_id}')
                    session.clear() 
                    return redirect('/session_error')
                session.update(session_data)
                redis_conn.expire(f'session:{session_id}', SESSION_TIMEOUT)
            else:
                print("No session data found for session_id:", session_id)
                session.clear() 
                return redirect('/login')
        except (json.JSONDecodeError, AttributeError) as e:
            print("Error loading session data:", e)
            pop_data(redis_conn, f'session:{session_id}')
            session.clear()  
            return redirect('/session_error')
        
def manage_session_and_https():
    session_id = request.cookies.get('session_id')
    if session_id:
        try:
            session_info = redis_conn.get(f'session:{session_id}')
            if session_info:
                session_info = json.loads(session_info.decode('utf-8'))
                session_data = json.loads(session_info['data'])  # Convert string to dictionary here
                stored_signature = session_info['signature']
                if 'lockout_expiration' in session_data:
                    session_data['lockout_expiration'] = datetime.strptime(session_data['lockout_expiration'], '%Y-%m-%d %H:%M:%S')
                if stored_signature != generate_session_signature(session_data):
                    pop_data(redis_conn, f'session:{session_id}')
                    session.clear() 
                    return redirect('/session_error')
                session.update(session_data)
                redis_conn.expire(f'session:{session_id}', SESSION_TIMEOUT)
            else:
                print("No session data found for session_id:", session_id)
                session.clear() 
                return redirect('/login')
        except (json.JSONDecodeError, AttributeError) as e:
            print("Error loading session data:", e)
            pop_data(redis_conn, f'session:{session_id}')
            session.clear()  
            return redirect('/session_error')

@app.after_request
def save_session(response: Response):
    if 'session_id' in session:
        try:
            session_data = json.dumps(dict(session))
            push_data_with_dynamic_ttl(redis_conn, session['session_id'], session_data, SESSION_TIMEOUT)
            response.set_cookie('session_id', session.get('session_id', ''), max_age=SESSION_TIMEOUT, httponly=True, secure=True, samesite='Lax')
        except Exception as e:
            logging.error(f"Error saving session: {e}")
    return response

#################### Authentication Routes #######################
def generate_honeypot_fields_for_fields(fields, length=64):
    return {f'{field}_hpot': ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        for field in fields
    }

def login(username, password):
    
        conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            error_handler = current_app.config.get('error_handler')
            return error_handler.render_error_page(403)
        return f(*args, **kwargs)
    return decorated_function

def is_account_locked(user):
    lockout_expiration = user['lockout_expiration']
    if lockout_expiration is None:
        return False
    if isinstance(lockout_expiration, str):
        lockout_expiration = datetime.strptime(lockout_expiration, '%Y-%m-%d %H:%M:%S')
    if datetime.now() < lockout_expiration:
        return True
    else:
        return False

def increase_lockout_time(user):
    """Increase lockout time by 5 minutes."""
    new_lockout_time = datetime.now() + LOCKOUT_INCREMENT
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("UPDATE super_admin SET lockout_expiration = %s WHERE id = %s", (new_lockout_time, user['id']))
        conn.commit()

def reset_failed_attempts(user):
    """Reset failed login attempts after a successful login."""
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("UPDATE super_admin SET failed_attempts = 0, lockout_expiration = NULL WHERE id = %s", (user['id'],))
        conn.commit()

def increment_failed_attempts(user):
    """Increment failed login attempts and lock the account if necessary."""
    conn = get_db_connection()
    with conn.cursor() as cursor:
        new_failed_attempts = user['failed_attempts'] + 1
        if new_failed_attempts >= MAX_FAILED_ATTEMPTS:
            lockout_time = datetime.now() + LOCKOUT_DURATION
            cursor.execute("UPDATE super_admin SET failed_attempts = %s, lockout_expiration = %s WHERE id = %s", 
                           (new_failed_attempts, lockout_time, user['id']))
        else:
            cursor.execute("UPDATE super_admin SET failed_attempts = %s WHERE id = %s", 
                           (new_failed_attempts, user['id']))
        conn.commit()

#################### Route Handlers ######################
@limiter.limit(dynamic_rate_limit)
@app.route('/')
def index():
    login_form = LoginForm()
    captcha_image, captcha_answer = captcha.generate_captcha()
    session['captcha_answer'] = captcha_answer
    buffer = BytesIO()
    captcha_image.save(buffer, format='PNG')
    buffer.seek(0)
    captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    login_fields = ['userType','login_username', 'login_password', 'login_captcha']
    login_honeypots = generate_honeypot_fields_for_fields(login_fields, length=64)
    return render_template('auth.html', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots, app_id=app_id)

@app.route('/login', methods=['POST', 'GET'])
@limiter.limit(dynamic_rate_limit)
def login_route():
    login_form = LoginForm()
    login_honeypots = session.get('login_honeypots', {})
    captcha_answer = session.get('captcha_answer')
    user_captcha_answer = request.form.get('captcha')
    for honeypot_name, expected_value in login_honeypots.items():
        if request.form.get(honeypot_name) != expected_value:
            return render_template('auth.html', login_error='Invalid honeypot value detected.', login_form=login_form, captcha_image_base64=session.get('captcha_image_base64'), login_honeypots=login_honeypots)
    if login_form.validate_on_submit() and captcha.validate_captcha(int(user_captcha_answer) if user_captcha_answer else None, captcha_answer):
        name = login_form.name.data
        password = login_form.password.data
        role = login_form.role.data
        user, error_message = login(name, password)
        if user:
            if role != 'super_admin' and user['is_super_admin']:
                captcha_image, captcha_answer = captcha.generate_captcha()
                buffer = BytesIO()
                captcha_image.save(buffer, format='PNG')
                buffer.seek(0)
                captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
                session.update({'captcha_answer': captcha_answer, 'captcha_image_base64': captcha_image_base64})
                return render_template('auth.html', login_error='Invalid role.', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)
            session.get('_csrf_token')
            session.clear()
            session['user'] = user
            session['user_id'] = generate_user_id(name)
            session['username'] = name
            session['role'] = role
            session['is_super_admin'] = user['is_super_admin']
            session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session.modified = True
            session.permanent = True
            session_data = json.dumps({'user': user, 'user_id': session['user_id'], 'username': session['username'], 'role': session['role'], 'last_activity': session['last_activity']})
            push_data_with_ttl(redis_conn, f"session:{name}", session_data, timeout=1800)  # 30-minute TTL
            response = make_response(redirect('/Dashboard'))
            response.set_cookie('session_id', session.get('session_id', ''), max_age=SESSION_TIMEOUT, httponly=True, secure=True, samesite='Lax')
            return response
        else:
            captcha_image, captcha_answer = captcha.generate_captcha()
            buffer = BytesIO()
            captcha_image.save(buffer, format='PNG')
            buffer.seek(0)
            captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            session.update({'captcha_answer': captcha_answer, 'captcha_image_base64': captcha_image_base64})
            return render_template('auth.html', login_error=error_message, login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)
    captcha_image, captcha_answer = captcha.generate_captcha()
    buffer = BytesIO()
    captcha_image.save(buffer, format='PNG')
    buffer.seek(0)
    captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    session.update({'captcha_answer': captcha_answer, 'captcha_image_base64': captcha_image_base64})
    return render_template('auth.html', login_error='Invalid CAPTCHA', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)

@app.route('/Dashboard')
@login_required
@limiter.limit(dynamic_rate_limit)
def dashboard():
    if 'user' in session:
        user = session['user']
        name = session['username']
        user_id = session['user_id']
        return render_template('Super-Admin/dashboard.html', user=user, user_id=user_id, name=name)
    return redirect('/')

@app.route('/Database')
@login_required
@limiter.limit(dynamic_rate_limit)
def database():
    if 'user' in session:
        user = session['user']
        name = session['username']
        user_id = session['user_id']
    return render_template('Super-Admin/database.html', user=user, user_id=user_id, name=name)

@app.route('/Forms')
@login_required
@limiter.limit(dynamic_rate_limit)
def form():
    if 'user' in session:
        user = session['user']
        name = session['username']
        user_id = session['user_id']
    return render_template('Super-Admin/form.html', user=user, user_id=user_id, name=name)

@app.route('/Logs')
@login_required
@limiter.limit(dynamic_rate_limit)
def logs():
    if 'user' in session:
        user = session['user']
        name = session['username']
        user_id = session['user_id']
    return render_template('Super-Admin/Logs.html', user=user, user_id=user_id, name=name)

@app.route('/Settings')
@login_required
@limiter.limit(dynamic_rate_limit)
def settings():
    if 'user' in session:
        user = session['user']
        name = session['username']
        user_id = session['user_id']
    return render_template('Super-Admin/settings.html', user=user, user_id=user_id, name=name)

@app.route('/Documentation')
@login_required
@limiter.limit(dynamic_rate_limit)
def documentation():
    if 'user' in session:
        user = session['user']
        name = session['username']
        user_id = session['user_id']
    return render_template('Super-Admin/Documentation.html', user=user, user_id=user_id, name=name)

@app.route('/logout', methods=['GET', 'POST'])
@limiter.limit("200 per minute")
def logout_route():
    session_id = session.get('session_id')
    if session_id:
        pop_data(redis_conn, f'session:{session_id}')  # Improved pop_data handles both list and key-value types
    session.clear()
    response = make_response(redirect('/'))
    response.set_cookie('session_id', '', expires=0, secure=True, httponly=True, samesite='Lax')
    return response

@app.route('/keep_alive', methods=['POST'])
@limiter.limit("200 per minute")
def keep_alive():
    session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(message="Session kept alive"), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8800)