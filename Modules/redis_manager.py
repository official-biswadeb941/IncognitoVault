import json, os, redis, logging, hmac, hashlib
from redis import from_url
from flask_caching import Cache
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import secrets

class RedisManager:
    def __init__(self, config_path='Database/caching.json'):
        self.config_path = config_path
        self.HMAC_SECRET = self.generate_key()  # Now using the imported key
        self.window_duration = timedelta(minutes=1)
        self.redis_conn = self.get_redis_connection()

    def generate_key(self):
        salt = secrets.token_bytes(64)
        ikm = secrets.token_bytes(80)
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=128,
            salt=salt,
            info=b'key derivation',
            backend=default_backend()
        )
        derived_key = hkdf.derive(ikm)
        return derived_key.hex()
    
    def get_redis_connection(self):
        """Initialize Redis connection using the provided configuration file."""
        try:
            with open(self.config_path) as config_file:
                config_data = json.load(config_file)
            redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
            redis_urls = config_data.get('redis_urls', [])
            redis_url = redis_urls[redis_url_index]
            # Create a Redis connection object
            return from_url(redis_url)
        except Exception as e:
            logging.error(f"Error initializing Redis connection: {e}")
            raise

    def configure_cache(self, app):
        """Configure the caching mechanism with Redis."""
        try:
            with open(self.config_path) as config_file:
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
        except Exception as e:
            logging.error(f"Error configuring cache: {e}")
            raise

    def generate_session_signature(self, session_data):
        """Generate a HMAC signature for the session data."""
        return hmac.new(self.HMAC_SECRET.encode(), session_data.encode(), hashlib.sha256).hexdigest()

    def push_session_data(self, session_id, session_data, timeout=1800, max_length=100):
        """Push session data to Redis with a time-to-live (TTL)."""
        if max_length <= 0:
            logging.error("max_length must be greater than 0")
            return
        try:
            print(f"Pushing session data: {session_data}")  # Debug print
            # Validate session_data
            if isinstance(session_data, str):
                try:
                    session_data = json.loads(session_data)  # Attempt to parse if string
                except json.JSONDecodeError:
                    logging.error(f"Invalid JSON data: {session_data}")
                    return  # Skip processing if invalid

            # Check if session_data is a dictionary now
            if not isinstance(session_data, dict):
                logging.error(f"Session data is not a dictionary: {session_data}")
                return  # Skip if not a dict

            # Serialize to JSON
            session_data_json = json.dumps(session_data)

            self.redis_conn.lpush(f'session:{session_id}', session_data_json)
            self.redis_conn.expire(f'session:{session_id}', timeout)
            self.redis_conn.ltrim(f'session:{session_id}', 0, max_length - 1)
        except Exception as e:
            logging.error(f"Error pushing session data with TTL: {e}")

    def pop_data(self, key):
        """Pop data from Redis based on the key type."""
        try:
            key_type = self.redis_conn.type(key)
            if key_type == b'list':
                value = self.redis_conn.rpop(key)  # Pop the last element of the list
            else:
                value = self.redis_conn.get(key)   # Retrieve the value before deleting
                self.redis_conn.delete(key)        # Delete the key from Redis
            return value
        except Exception as e:
            logging.error(f"Error popping data from Redis: {e}")
            return None

    def get_redis_uri(self):
        """Retrieve the Redis URI from the configuration file."""
        try:
            with open(self.config_path) as config_file:
                config_data = json.load(config_file)
            redis_url_index = int(os.getenv('REDIS_URL_INDEX', 0))
            redis_urls = config_data.get('redis_urls', [])
            if redis_url_index >= len(redis_urls):
                raise ValueError("Invalid REDIS_URL_INDEX value")
            return redis_urls[redis_url_index]
        except Exception as e:
            logging.error(f"Error getting Redis URI: {e}")
            raise

    def get_request_count(self, user_ip):
        """Get the count of requests made by the user in the current window."""
        key = f'rate_limit:{user_ip}'
        current_time = datetime.now().timestamp()
        try:
            request_times = self.redis_conn.lrange(key, 0, -1)
            valid_requests = [float(t) for t in request_times if current_time - float(t) <= self.window_duration.total_seconds()]
            return len(valid_requests)
        except Exception as e:
            logging.error(f"Error retrieving request count: {e}")
            raise

    def dynamic_rate_limit(self):
        """Determine the rate limit dynamically based on user requests."""
        user_ip = get_remote_address()
        self.record_request_in_redis(user_ip)
        request_count = self.get_request_count(user_ip)
        if request_count > 5000:
            return "5 per minute"
        elif request_count > 2500:
            return "10 per minute"
        elif request_count > 1250:
            return "20 per minute"
        else:
            return "60 per minute"

    def record_request_in_redis(self, user_ip):
        """Record a user's request in Redis for rate limiting."""
        current_time = datetime.now().timestamp()
        key = f'rate_limit:{user_ip}'
        pipeline = self.redis_conn.pipeline()
        pipeline.lpush(key, current_time)
        pipeline.ltrim(key, 0, 2499) 
        pipeline.expire(key, self.window_duration.seconds) 
        pipeline.execute()


# Example usage:
redis = RedisManager()
#redis_manager.push_session_data('session_123', {'user': 'test', 'lockout_expiration': datetime.now()})
