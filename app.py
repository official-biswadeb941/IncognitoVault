from flask import Flask, render_template, redirect, session, request, make_response, jsonify, Response
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import TooManyRequests, BadRequest
from modules.session import session as session_module
from modules.form import LoginForm, SignupForm
from datetime import timedelta, datetime
from functools import wraps
import random, string, logging, pymysql, json, os, secrets
from modules.captcha import generate_captcha, validate_captcha
from flask_sslify import SSLify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

################### Initialization and Configuration ########################
app = Flask(__name__)
app.secret_key = session_module()
app.config['ENV'] = 'development'
app.config['WTF_CSRF_ENABLED'] = True

csrf = CSRFProtect(app)
sslify = SSLify(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
)

SESSION_TIMEOUT = 60
app.permanent_session_lifetime = timedelta(seconds=SESSION_TIMEOUT)
MAX_LOGIN_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15

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

def dynamic_rate_limit():
    current_hour = datetime.now().hour
    if 8 <= current_hour <= 18:
        return "10 per minute"
    return "60 per minute"

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

def session_expiry(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'last_activity' in session:
            last_activity = datetime.strptime(session['last_activity'], '%Y-%m-%d %H:%M:%S')
            current_time = datetime.now()
            if (current_time - last_activity).total_seconds() > SESSION_TIMEOUT:
                session.pop('user', None)
                session.pop('user_id', None)
                session.pop('last_activity', None)
                logging.info(f"Session expired for IP: {get_remote_address()}")
                session.clear()
                return redirect('/')
            else:
                session['last_activity'] = current_time.strftime('%Y-%m-%d %H:%M:%S')
        else:
            session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return func(*args, **kwargs)
    return wrapper

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

#################### Route Handlers #####################
@app.route('/')
@limiter.limit("10 per minute")
def index():
    login_form = LoginForm()
    signup_form = SignupForm()
    captcha_question, captcha_answer = generate_captcha()
    signup_fields = ['signup_username', 'signup_email', 'signup_password', 'signup_captcha']
    login_fields = ['login_username', 'login_password', 'login_captcha']
    signup_honeypots = generate_honeypot_fields_for_fields(signup_fields, length=16)
    login_honeypots = generate_honeypot_fields_for_fields(login_fields, length=16)
    session['signup_honeypots'] = signup_honeypots
    session['login_honeypots'] = login_honeypots
    session['captcha_answer'] = captcha_answer
    return render_template('auth.html', login_form=login_form, signup_form=signup_form, captcha_question=captcha_question, signup_honeypots=signup_honeypots, login_honeypots=login_honeypots, app_id=app_id)

@app.route('/signup', methods=['POST', 'GET'])
@limiter.limit("10 per minute")
def signup_route():
    signup_form = SignupForm()
    signup_honeypots = session.get('signup_honeypots', {})
    captcha_answer = session.get('captcha_answer')
    user_captcha_answer = request.form.get('captcha')
    for honeypot_name, expected_value in signup_honeypots.items():
        if request.form.get(honeypot_name) != expected_value:
            return render_template('auth.html', signup_error='Invalid honeypot value detected.', login_error=None, login_form=LoginForm(), signup_form=signup_form,captcha_question=captcha_answer)
    if signup_form.validate_on_submit() and validate_captcha(int(user_captcha_answer) if user_captcha_answer else None, captcha_answer):
        name = signup_form.name.data
        email = signup_form.email.data
        password = signup_form.password.data
        if user_exists(name, email):
            captcha_question, captcha_answer = generate_captcha()
            session['captcha_answer'] = captcha_answer
            return render_template('auth.html', signup_error='User with provided details already exists', login_error=None, login_form=LoginForm(), signup_form=signup_form, captcha_question=captcha_question)
        if signup(name, email, password):
            return redirect('/login')
        else:
            captcha_question, captcha_answer = generate_captcha()
            session['captcha_answer'] = captcha_answer
            return render_template('auth.html', signup_error='Signup failed. Please try again.', login_error=None, login_form=LoginForm(), signup_form=signup_form, captcha_question=captcha_question)
    captcha_question, captcha_answer = generate_captcha()
    session['captcha_answer'] = captcha_answer
    return render_template('auth.html', signup_error='Invalid CAPTCHA', login_error=None, login_form=LoginForm(), signup_form=SignupForm(), captcha_question=captcha_question)

@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("10 per minute")
def login_route():
    login_form = LoginForm()
    login_honeypots = session.get('login_honeypots', {})
    captcha_answer = session.get('captcha_answer')
    user_captcha_answer = request.form.get('captcha')
    for honeypot_name, expected_value in login_honeypots.items():
        if request.form.get(honeypot_name) != expected_value:
            return render_template('auth.html', login_error='Invalid honeypot value detected.', signup_error=None, login_form=login_form, signup_form=SignupForm(), captcha_question=captcha_answer)
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
            captcha_question, captcha_answer = generate_captcha()
            session['captcha_answer'] = captcha_answer
            return render_template('auth.html', login_error='Invalid credentials', signup_error=None, login_form=login_form, signup_form=SignupForm(), captcha_question=captcha_question)
    captcha_question, captcha_answer = generate_captcha()
    session['captcha_answer'] = captcha_answer
    return render_template('auth.html', login_error='Invalid CAPTCHA', signup_error=None, login_form=login_form, signup_form=SignupForm(), captcha_question=captcha_question)

@app.route('/Dashboard') 
@session_expiry
@limiter.limit(user_rate_limit)
def dashboard():
    if 'user' in session:
        user = session['user']
        user_id = session['user_id']
        return render_template('App/dashboard.html', user=user, user_id=user_id)
    else:
        return redirect('/')

@app.route('/Form')
@session_expiry
@limiter.limit(user_rate_limit)
def form():
    return render_template('App/form.html')

@app.route('/Database')
@session_expiry
@limiter.limit(user_rate_limit)
def database():
    return render_template('App/database.html')

@app.route('/Logs')
@session_expiry
@limiter.limit(user_rate_limit)
def logs():
    return render_template('App/Logs.html')

@app.route('/Settings')
@session_expiry
@limiter.limit(user_rate_limit)
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

