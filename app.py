from flask import Flask, render_template, redirect, session, request, make_response, jsonify, Response
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_session import Session 
from modules.caching import configure_cache, push_data_with_ttl, pop_data, get_redis_connection, get_redis_uri
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import TooManyRequests, BadRequest
from modules.session import session as session_module
from modules.form import LoginForm, SignupForm
from datetime import timedelta, datetime
from functools import wraps
from collections import deque
import random, string, logging, pymysql, json, os, secrets, base64, redis
from io import BytesIO
from modules.captcha import generate_captcha, validate_captcha
from flask_sslify import SSLify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


################### Initialization and Configuration ########################
app = Flask(__name__)
app.secret_key = session_module()
app.config['ENV'] = 'development'
app.config['WTF_CSRF_ENABLED'] = True

# Initialize Redis and configure caching
redis_conn = get_redis_connection()
cache = configure_cache(app)
redis_uri = get_redis_uri()
redis_conn = redis.StrictRedis.from_url(redis_uri)

# Configure Flask-Session to use Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_REDIS'] = redis_conn
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = timedelta(days=30)

# Initialize Flask-Session
Session(app)

csrf = CSRFProtect(app)
sslify = SSLify(app)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=redis_uri,
    app=app,
   )

SESSION_TIMEOUT = 60
app.permanent_session_lifetime = timedelta(seconds=SESSION_TIMEOUT)
request_times = deque()
window_duration = timedelta(minutes=1)

# Load MySQL configuration from config.json
with open('Database/DB.json', 'r') as f:
    config = json.load(f)

# Extract the '1_DB' key
db_config = config.get('1_DB', '2_DB')

# MySQL configuration
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
csrf.init_app(app)

#################### Rate Limiting using Redis ######################
def record_request_in_redis(user_ip):
    current_time = datetime.now().timestamp()
    key = f'rate_limit:{user_ip}'
    
    # Push the current time to Redis and trim the list to keep only recent requests
    redis_conn.lpush(key, current_time)
    redis_conn.ltrim(key, 0, 2499)  # Keep the last 2500 requests in Redis
    
    # Set expiration for this key to automatically remove old data after window_duration
    redis_conn.expire(key, window_duration.seconds)

def get_request_count(user_ip):
    key = f'rate_limit:{user_ip}'
    
    # Retrieve all timestamps from Redis for the given IP
    request_times = redis_conn.lrange(key, 0, -1)
    
    # Convert Redis list (byte strings) to float timestamps and filter by time window
    current_time = datetime.now().timestamp()
    valid_requests = [float(t) for t in request_times if current_time - float(t) <= window_duration.total_seconds()]
    
    return len(valid_requests)

def dynamic_rate_limit():
    user_ip = get_remote_address()
    
    # Record the current request in Redis
    record_request_in_redis(user_ip)
    
    # Get the number of requests within the sliding window
    request_count = get_request_count(user_ip)

    # Define dynamic rate limits based on request count
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
        last_activity = pop_data(redis_conn, f'session:last_activity:{user_id}')
        current_time = datetime.now()

        if last_activity:
            # Decode bytes to string if necessary
            if isinstance(last_activity, bytes):
                last_activity = last_activity.decode('utf-8')
            last_activity = datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S')
            if (current_time - last_activity).total_seconds() > SESSION_TIMEOUT:
                session.clear()
                return redirect('/')
            else:
                # Update last activity in Redis
                push_data_with_ttl(redis_conn, f'session:last_activity:{user_id}', current_time.strftime('%Y-%m-%d %H:%M:%S'), SESSION_TIMEOUT)
        else:
            push_data_with_ttl(redis_conn, f'session:last_activity:{user_id}', current_time.strftime('%Y-%m-%d %H:%M:%S'), SESSION_TIMEOUT)
        
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
                email VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL
            )
            """
            cursor.execute(sql)
    except Exception as e:
        print(f"Error creating table: {str(e)}")

create_table()

def hash_password(password):
    return ph.hash(password)

def verify_password(stored_hash, password):
    try:
        ph.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False

def generate_random_string(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for i in range(length))

def generate_user_id(username):
    random_string = generate_random_string()
    return f"{username}-{random_string}"

def generate_app_id():
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"IncognitoVault-{random_string}"


def user_rate_limit():
    user_id = session.get('user_id', get_remote_address())
    return f"5 per minute"

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
def ensure_https():
    if not request.is_secure and app.config['ENV'] != 'development':
        return redirect(request.url.replace("http://", "https://"))
    
@app.before_request
def load_session():
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
    honeypots = {}
    for field in fields:
        honeypot_name = f'{field}_hpot'
        honeypot_value = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        honeypots[honeypot_name] = honeypot_value
    return honeypots

def user_exists(name, email):
    try:
        with db.cursor() as cursor:
            sql = "SELECT * FROM users WHERE name = %s OR email = %s"
            cursor.execute(sql, (name, email))
            user = cursor.fetchone()
            return user
    except Exception as e:
        print(f"Error checking user existence: {str(e)}")
        return None

def login(name, password):
    try:
        with db.cursor() as cursor:
            sql = "SELECT * FROM users WHERE name = %s"
            cursor.execute(sql, (name,))
            user = cursor.fetchone()
            if user and verify_password(user['password'], password):
                return user
            return None
    except Exception as e:
        print(f"Error logging in: {str(e)}")
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
        print(f"Error signing up: {str(e)}")
        return jsonify({"error": "Failed to sign up"}), 500


#################### Rate Limiters ######################
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
    session['login_honeypots'] = login_honeypots
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
            response = make_response(redirect('/Dashboard'))
            session['user'] = user
            session['user_id'] = generate_user_id(name)
            session.permanent = True
            session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            response.set_cookie('session', '', max_age=0)
            response.set_cookie('session', 'new', max_age=SESSION_TIMEOUT, httponly=True, secure=True, samesite='Lax')
            return response
        else:
            # Regenerate CAPTCHA for retry
            captcha_image, captcha_answer = generate_captcha()
            buffer = BytesIO()
            captcha_image.save(buffer, format='PNG')
            buffer.seek(0)
            captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            session['captcha_answer'] = captcha_answer
            session['captcha_image_base64'] = captcha_image_base64
            return render_template('auth.html', login_error='Invalid credentials', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)

    # Handle CAPTCHA failure
    captcha_image, captcha_answer = generate_captcha()
    buffer = BytesIO()
    captcha_image.save(buffer, format='PNG')
    buffer.seek(0)
    captcha_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    session['captcha_answer'] = captcha_answer
    session['captcha_image_base64'] = captcha_image_base64

    return render_template('auth.html', login_error='Invalid CAPTCHA', login_form=login_form, captcha_image_base64=captcha_image_base64, login_honeypots=login_honeypots)

@app.route('/Dashboard') 
@session_expiry
@limiter.limit(dynamic_rate_limit)
def dashboard():
    if 'user' in session:
        user = session['user']
        user_id = session['user_id']
        return render_template('App/dashboard.html', user=user, user_id=user_id)
    else:
        return redirect('/')

@app.route('/Form')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def form():
    return render_template('App/form.html')

@app.route('/Database')
@session_expiry
@limiter.limit(dynamic_rate_limit)
def database():
    return render_template('App/database.html')

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

@app.route('/logout', methods=['GET', 'POST']) 
@limiter.limit("200 per minute")
def logout_route():
    if 'user' in session:
        session.pop('user', None)
        session.pop('user_id', None)
        session.pop('last_activity', None)
        response = make_response(redirect('/'))
        response.set_cookie('csrf_token', '', expires=0)
        return response
    else:
        return redirect('/')

@app.route('/keep_alive', methods=['POST']) 
@limiter.limit("200 per minute")
def keep_alive():
    session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(message="Session kept alive"), 200

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
