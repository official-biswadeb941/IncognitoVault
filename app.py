# Standard library imports
import string, os, json, secrets, base64, hmac, secrets, hashlib
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
import pymysql
from dbutils.pooled_db import PooledDB

# Custom module imports
from Modules.error_handler import ErrorHandler
from Modules.caching import *
from Modules.session import generate_session_key, generate_key
from Modules.form import LoginForm
from Modules.captcha import generate_captcha, validate_captcha

# functools is not removed since it's probably used for decorators (verify before removing)
from functools import wraps


################### Initialization and Configuration ########################
app = Flask(__name__)
error_handler = ErrorHandler(app)
app.config['error_handler'] = error_handler
app.secret_key = generate_key()
HMAC_SECRET = app.secret_key

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

redis_conn = redis_conn()  
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

with open('Database/DB.json', 'r') as f:
    db_config = json.load(f).get('1_DB', {})

ssl_config = db_config.get('ssl', {})
ssl_config['ca'] = os.path.join('Database', ssl_config.get('ca', 'ca.pem'))

# Initialize the connection pool
pool = PooledDB(
    creator=pymysql,  # The database module to use
    maxconnections=20,  # The maximum number of connections allowed
    mincached=5,  # The minimum number of connections to be cached
    maxcached=10,  # The maximum number of connections to be cached
    maxshared=10,  # The maximum number of shared connections
    blocking=True,  # Whether to block if the pool is full
    host=db_config['host'],
    user=db_config['user'],
    password=db_config['password'],
    database=db_config['database'],
    port=int(db_config['port']),
    cursorclass=pymysql.cursors.DictCursor,
    ssl=ssl_config
)


ph = PasswordHasher()


####################### Utility Functions #####################

def get_db_connection():
    return pool.connection()

def create_super_admin():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SHOW TABLES LIKE 'super_admin'")
            if cursor.fetchone():
                return None
            else:
                sql = """
                CREATE TABLE super_admin (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    is_super_admin BOOLEAN NOT NULL DEFAULT FALSE
                )
                """
                cursor.execute(sql)
                conn.commit()
            cursor.execute("SELECT COUNT(*) FROM super_admin WHERE is_super_admin = TRUE")
            super_admin_exists = cursor.fetchone()['COUNT(*)'] > 0
            if super_admin_exists:
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
    session_data_json = json.dumps(session_data)
    session_signature = generate_session_signature(session_data_json)
    # Store both session data and its signature
    redis_conn.set(f'session:{session_id}', json.dumps({'data': session_data_json, 'signature': session_signature}), ex=timeout)

@app.before_request
def manage_session_and_https():
    session_id = request.cookies.get('session_id')
    if session_id:
        try:
            session_info = redis_conn.get(f'session:{session_id}')
            if session_info:
                session_info = json.loads(session_info.decode('utf-8'))
                session_data = session_info['data']
                stored_signature = session_info['signature']
                if stored_signature != generate_session_signature(session_data):
                    pop_data(redis_conn, f'session:{session_id}')
                    session['error'] = 'Session tampered or invalid'
                    return redirect('/session_error')  # Redirect to error page
                cleaned_data = session_data[1:-1].replace('\\"', '"')
                session.update(json.loads(cleaned_data))
                redis_conn.expire(f'session:{session_id}', SESSION_TIMEOUT)
            else:
                print("No session data found for session_id:", session_id)
        except (json.JSONDecodeError, AttributeError) as e:
            print("Error loading session data:", e)
            pop_data(redis_conn, f'session:{session_id}')
    else:
        session_id = generate_session_key(length=128)
        session['session_id'] = session_id

@app.after_request
def save_session(response: Response):
    if 'session_id' in session:
        session_data = json.dumps(dict(session))
        push_data_with_dynamic_ttl(redis_conn, session['session_id'], session_data, SESSION_TIMEOUT)
        response.set_cookie('session_id', session.get('session_id', ''), max_age=SESSION_TIMEOUT, httponly=True, secure=True, samesite='Lax')
    return response

#################### Authentication Routes #######################
def generate_honeypot_fields_for_fields(fields, length=64):
    return {f'{field}_hpot': ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        for field in fields
    }

def login(username, password):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT id, password, is_super_admin FROM super_admin WHERE username = %s"
            cursor.execute(sql, (username,))
            user = cursor.fetchone()
            if user and verify_password(user['password'], password):
                return user
            return None
    except Exception as e:
        print(f"Error logging in: {e}")
        return None
    finally:
        conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            error_handler = current_app.config.get('error_handler')
            return error_handler.render_error_page(403)
        return f(*args, **kwargs)
    return decorated_function

#################### Route Handlers ######################
@limiter.limit(dynamic_rate_limit)
@app.route('/')
def index():
    login_form = LoginForm()
    captcha_image, captcha_answer = generate_captcha()
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
    if login_form.validate_on_submit() and validate_captcha(int(user_captcha_answer) if user_captcha_answer else None, captcha_answer):
        name = login_form.name.data
        password = login_form.password.data
        role = login_form.role.data  # Get the selected role        
        user = login(name, password)
        if user:
            if role != 'super_admin' and user['is_super_admin']:  
                captcha_image, captcha_answer = generate_captcha()
                buffer = BytesIO()
                captcha_image.save(buffer, format='PNG')
                buffer.seek(0)
                captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
                session.update({'captcha_answer': captcha_answer, 'captcha_image_base64': captcha_image_base64})
                return render_template('auth.html', login_error='Invalid role.', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)  
            session.get('_csrf_token')
            session.clear()  # Clear the session
            session['user'] = user
            session['user_id'] = generate_user_id(name)
            session['username'] = name
            session['role'] = role  # Store the role in the session
            session['is_super_admin'] = user['is_super_admin']  # Store user role in session
            session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session.modified = True  # Mark session as modified to regenerate session ID
            session.permanent = True  # Make session permanent
            session_data = json.dumps({'user': user, 'user_id': session['user_id'], 'username': session['username'], 'role': session['role'], 'last_activity': session['last_activity']})
            push_data_with_ttl(redis_conn, f"session:{name}", session_data, timeout=1800)  # 30-minute TTL
            response = make_response(redirect('/Dashboard'))
            response.set_cookie('session_id', session.get('session_id', ''), max_age=SESSION_TIMEOUT, httponly=True, secure=True, samesite='Lax')  # Set secure cookie
            return response
        else:
            captcha_image, captcha_answer = generate_captcha()
            buffer = BytesIO()
            captcha_image.save(buffer, format='PNG')
            buffer.seek(0)
            captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            session.update({'captcha_answer': captcha_answer, 'captcha_image_base64': captcha_image_base64})
            return render_template('auth.html', login_error='Invalid credentials', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)
    captcha_image, captcha_answer = generate_captcha()
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