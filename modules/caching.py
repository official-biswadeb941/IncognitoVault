import json
import os
import redis
from flask_caching import Cache

# Initialize Redis connection
def get_redis_connection():
    #print("Initializing Redis connection...")
    with open('Database/caching.json') as config_file:
        config_data = json.load(config_file)
    
    redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
    redis_urls = config_data.get('redis_urls', [])
    redis_url = redis_urls[redis_url_index]
    
    #print(f"Connecting to Redis at {redis_url}")
    return redis.from_url(redis_url)

# Configure and initialize Flask cache
def configure_cache(app):
    print("Configuring Flask cache...")
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
    #print(f"Cache configured with Redis URL: {redis_url}")
    return cache

# Push data to Redis List with TTL
def push_data_with_ttl(redis_conn, key, value, timeout, max_length=100):
    #print(f"Pushing data to Redis list: key={key}, value={value}, timeout={timeout}, max_length={max_length}")
    redis_conn.lpush(key, value)
    redis_conn.expire(key, timeout)
    redis_conn.ltrim(key, 0, max_length - 1)
    #print(f"Data pushed to list {key} with TTL {timeout} seconds")

# Pop data from Redis List
def pop_data(redis_conn, key):
    #print(f"Popping data from Redis list: key={key}")
    value = redis_conn.rpop(key)
    #print(f"Data popped from list {key}: {value}")
    return value

# Add this function to get the Redis URI
def get_redis_uri():
    with open('Database/caching.json') as config_file:
        config_data = json.load(config_file)

    redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
    redis_urls = config_data.get('redis_urls', [])
    
    if redis_url_index >= len(redis_urls):
        raise ValueError("Invalid REDIS_URL_INDEX value")
    
    return redis_urls[redis_url_index]