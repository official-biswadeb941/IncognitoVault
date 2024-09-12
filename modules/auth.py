from flask import jsonify
import pymysql
import json
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Load MySQL configuration from config.json
with open('Database/DB.json', 'r') as f:
    config = json.load(f)

# Extract the '1_DB' key
db_config = config.get('1_DB', {})

# MySQL configuration
ssl_config = db_config.get('ssl', {})  # Get the 'ssl' section from db_config
ssl_config['ca'] = os.path.join('Database', ssl_config.get('ca', 'ca.pem'))  # Use 'ca.pem' as default if 'ca' is not defined

db = pymysql.connect(
    host=db_config['host'],
    user=db_config['user'],
    password=db_config['password'],
    database=db_config['database'],
    port=int(db_config['port']),
    cursorclass=pymysql.cursors.DictCursor,
    ssl=ssl_config  # Use the ssl_config dictionary
)

ph = PasswordHasher()

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
