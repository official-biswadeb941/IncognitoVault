import json
import os
import redis
from flask_caching import Cache
import datetime
from datetime import timedelta
from flask_limiter.util import get_remote_address

# Rate limiting functions
window_duration = timedelta(minutes=1)

# Initialize Redis connection
def redis_conn():
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

def push_data_with_ttl(redis_conn, key, value, timeout, max_length=100):
    redis_conn.lpush(key, value)
    redis_conn.expire(key, timeout)
    redis_conn.ltrim(key, 0, max_length - 1)

def pop_data(redis_conn, key):
    key_type = redis_conn.type(key)
    if key_type == b'list':
        value = redis_conn.rpop(key)  # Pop the last element of the list
    else:
        value = redis_conn.get(key)   # Retrieve the value before deleting
        redis_conn.delete(key)        # Delete the key from Redis
    return value

def get_redis_uri():
    with open('Database/caching.json') as config_file:
        config_data = json.load(config_file)
    redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
    redis_urls = config_data.get('redis_urls', [])
    if redis_url_index >= len(redis_urls):
        raise ValueError("Invalid REDIS_URL_INDEX value")
    return redis_urls[redis_url_index]


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