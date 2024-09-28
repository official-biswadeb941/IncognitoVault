import json
import os
import redis
from flask_caching import Cache

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