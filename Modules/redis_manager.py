import json, os, redis, logging, hmac, hashlib
from flask_caching import Cache
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
from .session import *

HMAC_SECRET =  generate_key()

window_duration = timedelta(minutes=1)

# Initialize Redis connection
def get_redis_connection():
    with open('Database/caching.json') as config_file:
        config_data = json.load(config_file)
    redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
    redis_urls = config_data.get('redis_urls', [])
    redis_url = redis_urls[redis_url_index]
    return redis.from_url(redis_url)

def configure_cache(app):
    with open('Database/caching.json') as config_file:
        config_data = json.load(config_file)
    redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
    redis_urls = config_data.get('redis_urls', [])    
    if redis_url_index >= len(redis_urls):
        raise ValueError("Invalid REDIS_URL_INDEX value")
    redis_url = redis_urls[redis_url_index]
    app.config['CACHE_TYPE'] = 'RedisCache'
    app.config['CACHE_REDIS_URL'] = redis_url
    app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # Set default timeout (e.g., 5 minutes)
    cache = Cache(app)
    return cache

def generate_session_signature(session_data):
    """Generate a HMAC signature for the session data."""
    return hmac.new(HMAC_SECRET.encode(), session_data.encode(), hashlib.sha256).hexdigest()

def push_session_data(redis_conn, session_id, session_data, timeout=1800, max_length=100):
    if max_length <= 0:
        logging.error("max_length must be greater than 0")
        return
    try:
        # Parse session_data if it is a JSON string
        if isinstance(session_data, str):
            session_data = json.loads(session_data)
        # Convert lockout_expiration to string if it is a datetime
        if 'lockout_expiration' in session_data and isinstance(session_data['lockout_expiration'], datetime):
            session_data['lockout_expiration'] = session_data['lockout_expiration'].strftime('%Y-%m-%d %H:%M:%S')
        session_data_json = json.dumps(session_data)
        session_signature = generate_session_signature(session_data_json)
        redis_conn.lpush(f'session:{session_id}', json.dumps({'data': session_data_json, 'signature': session_signature}))
        redis_conn.expire(f'session:{session_id}', timeout)
        redis_conn.ltrim(f'session:{session_id}', 0, max_length - 1)
    except Exception as e:
        logging.error(f"Error pushing session data with TTL: {e}")

def pop_data(redis_conn, key):
    key_type = redis_conn.type(key)
    if key_type == b'list':
        value = redis_conn.rpop(key)  # Pop the last element of the list
    else:
        value = redis_conn.get(key)   # Retrieve the value before deleting
        redis_conn.delete(key)        # Delete the key from Redis
    return value

redis_conn = get_redis_connection()

def get_redis_uri():
    with open('Database/caching.json') as config_file:
        config_data = json.load(config_file)
    redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
    redis_urls = config_data.get('redis_urls', [])
    if redis_url_index >= len(redis_urls):
        raise ValueError("Invalid REDIS_URL_INDEX value")
    return redis_urls[redis_url_index]

def get_request_count(user_ip):
    key = f'rate_limit:{user_ip}'
    current_time = datetime.now().timestamp()
    try:
        request_times = redis_conn.lrange(key, 0, -1)
        valid_requests = [float(t) for t in request_times if current_time - float(t) <= window_duration.total_seconds()]
        return len(valid_requests)
    except Exception as e:
        print(f"Error retrieving request count: {e}")
        raise

def dynamic_rate_limit():
    user_ip = get_remote_address()
    record_request_in_redis(user_ip)
    request_count = get_request_count(user_ip)
    if request_count > 5000:
        return "5 per minute"
    elif request_count > 2500:
        return "10 per minute"
    elif request_count > 1250:
        return "20 per minute"
    else:
        return "60 per minute"
    
def record_request_in_redis(user_ip):
    current_time = datetime.now().timestamp()
    key = f'rate_limit:{user_ip}'
    pipeline = redis_conn.pipeline()
    pipeline.lpush(key, current_time)
    pipeline.ltrim(key, 0, 2499) 
    pipeline.expire(key, window_duration.seconds) 
    pipeline.execute()