# Standard library imports
import random, string, logging, os, json, secrets, base64
from io import BytesIO
from datetime import timedelta, datetime
from collections import deque

# Third-party imports
from flask import Flask, render_template, redirect, session, request, make_response, jsonify, Response
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session 
from werkzeug.exceptions import TooManyRequests, BadRequest
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pymysql

# Custom module imports
from modules.caching import configure_cache, push_data_with_ttl, pop_data, get_redis_connection, get_redis_uri
from modules.session import session as session_module
from modules.form import LoginForm
from modules.captcha import generate_captcha, validate_captcha

# functools is not removed since it's probably used for decorators (verify before removing)
from functools import wraps


################### Initialization and Configuration ########################
app = Flask(__name__)
app.secret_key = session_module()

app.config.update({
    'ENV': 'development',
    'WTF_CSRF_ENABLED': True,
    'SESSION_TYPE': 'redis',
    'SESSION_PERMANENT': False,
    'SESSION_USE_SIGNER': True,
    'SESSION_KEY_PREFIX': 'session:',
    'SEND_FILE_MAX_AGE_DEFAULT': timedelta(days=30)
})

redis_conn = get_redis_connection()  
cache = configure_cache(app)
app.config['SESSION_REDIS'] = redis_conn

Session(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

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

db = pymysql.connect(
    host=db_config['host'],
    user=db_config['user'],
    password=db_config['password'],
    database=db_config['database'],
    port=int(db_config['port']),
    cursorclass=pymysql.cursors.DictCursor,
    ssl=ssl_config
)

ph = PasswordHasher()

#################### Rate Limiting using Redis ######################
def record_request_in_redis(user_ip):
    current_time = datetime.now().timestamp()
    key = f'rate_limit:{user_ip}'
    pipeline = redis_conn.pipeline()
    pipeline.lpush(key, current_time)
    pipeline.ltrim(key, 0, 2499) 
    pipeline.expire(key, window_duration.seconds) 
    pipeline.execute()

def get_request_count(user_ip):
    key = f'rate_limit:{user_ip}'
    current_time = datetime.now().timestamp()
    request_times = redis_conn.lrange(key, 0, -1)
    valid_requests = [float(t) for t in request_times if current_time - float(t) <= window_duration.total_seconds()]
    return len(valid_requests)

def dynamic_rate_limit():
    user_ip = get_remote_address()
    record_request_in_redis(user_ip)
    request_count = get_request_count(user_ip)
    if request_count > 2500:
        return "5 per minute"
    elif request_count > 1250:
        return "10 per minute"
    elif request_count > 625:
        return "20 per minute"
    else:
        return "60 per minute"

###################### Session Management ######################
def session_expiry(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id', get_remote_address())
        session_key = f'session:last_activity:{user_id}'
        last_activity = pop_data(redis_conn, session_key)
        current_time = datetime.now()
        current_time_str = current_time.strftime('%Y-%m-%d %H:%M:%S')  # Format once and reuse
        if last_activity:
            if isinstance(last_activity, bytes):
                last_activity = last_activity.decode('utf-8')
            last_activity = datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S')
            if (current_time - last_activity).total_seconds() > SESSION_TIMEOUT:
                session.clear()
                return redirect('/') 
        push_data_with_ttl(redis_conn, session_key, current_time_str, SESSION_TIMEOUT)
        return func(*args, **kwargs)
    return wrapper

####################### Utility Functions #####################
def create_table():
    try:
        with db.cursor() as cursor:
            sql = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
            """
            cursor.execute(sql)
            db.commit()  
    except Exception as e:
        print(f"Error creating table: {e}")

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


###################### Security and Middleware Functions #######################
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-App-ID'] = app_id
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    if app.config['ENV'] == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers.pop('Server', None)
    return response

@app.before_request
def manage_session_and_https():
    if not request.is_secure and app.config['ENV'] != 'development':
        return redirect(request.url.replace("http://", "https://"))
    session_id = request.cookies.get('session_id')
    if session_id:
        session_data = redis_conn.get(f'session:{session_id}')
        if session_data:
            session.update(json.loads(session_data.decode('utf-8')))
    else:
        session_id = generate_random_string(32)  # Generate a unique session ID
        session['session_id'] = session_id

@app.after_request
def save_session(response: Response):
    if 'session_id' in session:
        session_data = json.dumps(dict(session))
        redis_conn.set(f'session:{session["session_id"]}', session_data)
        redis_conn.expire(f'session:{session["session_id"]}', SESSION_TIMEOUT)
    response.set_cookie('session_id', session.get('session_id', ''), max_age=SESSION_TIMEOUT, httponly=True, secure=True, samesite='Lax')
    return response

#################### Authentication Routes #######################
def generate_honeypot_fields_for_fields(fields, length=16):
    return {f'{field}_hpot': ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        for field in fields
    }

def user_exists(name, email):
    try:
        with db.cursor() as cursor:
            sql = "SELECT id FROM users WHERE name = %s OR email = %s"
            cursor.execute(sql, (name, email))
            return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error checking user existence: {e}")
        return False

def login(name, password):
    try:
        with db.cursor() as cursor:
            sql = "SELECT id, password FROM users WHERE name = %s"
            cursor.execute(sql, (name,))
            user = cursor.fetchone()
            if user and verify_password(user['password'], password):
                return user
            return None
    except Exception as e:
        print(f"Error logging in: {e}")
        return None

def signup(name, email, password):
    if user_exists(name, email):
        return jsonify({"error": "User with the same name or email already exists"}), 400
    hashed_password = hash_password(password)
    try:
        with db.cursor() as cursor:
            sql = "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)"
            cursor.execute(sql, (name, email, hashed_password))
            db.commit()
            return jsonify({"message": "User signed up successfully"}), 201
    except Exception as e:
        print(f"Error signing up: {e}")
        db.rollback()  # Rollback in case of error
        return jsonify({"error": "Failed to sign up"}), 500

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
    login_honeypots = generate_honeypot_fields_for_fields(login_fields, length=16)
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
            return render_template('auth.html', login_error='Invalid honeypot value detected.', login_form=login_form, captcha_image_base64=session.get('captcha_image_base64'),login_honeypots=login_honeypots)
        
    if login_form.validate_on_submit() and validate_captcha(int(user_captcha_answer) if user_captcha_answer else None, captcha_answer):
        name = login_form.name.data
        password = login_form.password.data
        user = login(name, password)
        if user:
            session.clear()
            session.update({'user': user, 'user_id': generate_user_id(name), 'last_activity': datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
            session.permanent = True
            response = make_response(redirect('/Dashboard'))
            response.set_cookie('session', '', max_age=0)  # Clear existing cookie
            response.set_cookie('session', 'new', max_age=SESSION_TIMEOUT, httponly=True, secure=True, samesite='Lax')
            return response
        else:
            captcha_image, captcha_answer = generate_captcha()
            buffer = BytesIO()
            captcha_image.save(buffer, format='PNG')
            buffer.seek(0)
            captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            session.update({'captcha_answer': captcha_answer,'captcha_image_base64': captcha_image_base64})
            return render_template('auth.html', login_error='Invalid credentials', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)
    captcha_image, captcha_answer = generate_captcha()
    buffer = BytesIO()
    captcha_image.save(buffer, format='PNG')
    buffer.seek(0)
    captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    session.update({'captcha_answer': captcha_answer,'captcha_image_base64': captcha_image_base64})
    return render_template('auth.html', login_error='Invalid CAPTCHA', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)

@app.route('/Dashboard')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def dashboard():
    if 'user' in session:
        user = session['user']
        user_id = session['user_id']
        return render_template('App/dashboard.html', user=user, user_id=user_id)
    return redirect('/')

@app.route('/Database')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def database():
    return render_template('App/database.html')

@app.route('/Forms')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def form():
    return render_template('App/form.html')

@app.route('/Logs')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def logs():
    return render_template('App/Logs.html')

@app.route('/Settings')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def settings():
    return render_template('App/settings.html')

@app.route('/Documentation')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def documentation():
    return render_template('App/Documentation.html')

@app.route('/logout', methods=['GET', 'POST'])
@limiter.limit("200 per minute")
def logout_route():
    if 'user' in session:
        for key in ['user', 'user_id', 'last_activity']:
            session.pop(key, None)
        response = make_response(redirect('/'))
        response.set_cookie('csrf_token', '', expires=0)
        return response
    return redirect('/')

@app.route('/keep_alive', methods=['POST'])
@limiter.limit("200 per minute")
def keep_alive():
    session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(message="Session kept alive"), 200

#################### Error Handlers ######################
@app.errorhandler(404)
def not_found_error(error):
    user_ip = get_remote_address()
    logging.info(f"404 Not Found error for IP: {user_ip}")
    return render_template('Error-Page/404-Not-Found.html', user_ip=user_ip), 404

@app.errorhandler(500)
def internal_error(error):
    user_ip = get_remote_address()
    logging.error(f"500 Internal Server Error for IP: {user_ip}")
    return render_template('Error-Page/500-Internal-Server-Error.html', user_ip=user_ip), 500

@app.errorhandler(TooManyRequests)
def rate_limit_error(e):
    user_ip = get_remote_address()
    logging.warning(f"Rate limit exceeded for IP: {user_ip}")
    if 'user' in session:
        return jsonify({"error": "Too many requests. Please try again later."}), 429
    return render_template('Error-Page/429-Many-Request.html', user_ip=user_ip), 429

@app.errorhandler(BadRequest)
def csrf_error(e):
    user_ip = get_remote_address()
    logging.error(f"CSRF error for IP: {user_ip}")
    if 'CSRF' in str(e):
        return render_template('Error-Page/419-Authentication-Timeout.html', user_ip=user_ip), 400
    return render_template('Error-Page/500-Internal-Server-Error.html', user_ip=user_ip), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8800)
