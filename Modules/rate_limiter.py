import time
import redis
from flask import request, current_app, session
from functools import wraps
import psutil  # Importing psutil to monitor system load
from .redis_manager import *


class RateLimiter:
    def __init__(self, redis_connection, get_capacity, get_leak_rate):
        self.redis = redis_connection
        self.get_capacity = get_capacity  # Function for dynamic capacity
        self.get_leak_rate = get_leak_rate  # Function for dynamic leak rate
        self.leak_interval = 1  # Leak interval in seconds

    def _get_bucket_key(self):
        ip_address = request.remote_addr
        user_id = session.get('user_id')
        if user_id:
            return f"rate_limit:user:{user_id}"
        else:
            return f"rate_limit:ip:{ip_address}"

    def is_allowed(self):
        bucket_key = self._get_bucket_key()
        current_time = time.time()
        capacity = self.get_capacity()
        leak_rate = self.get_leak_rate()
        bucket = self.redis.get(bucket_key)
        if bucket is None:
            self.redis.set(bucket_key, 0, ex=self.leak_interval)
            return True
        current_count = int(bucket)
        leaked_tokens = int((current_time // self.leak_interval) * leak_rate)
        allowed_count = max(current_count - leaked_tokens, 0)
        if allowed_count >= capacity:
            return False
        self.redis.set(bucket_key, allowed_count + 1, ex=self.leak_interval)
        return True

def rate_limited(rate_limiter):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not rate_limiter.is_allowed():
                error_handler = current_app.config.get('error_handler')
                return error_handler.render_error_page(429)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_system_load():
    cpu_usage = psutil.cpu_percent(interval=1)  # CPU usage in the past second
    memory_info = psutil.virtual_memory()  # Memory stats
    memory_usage = memory_info.percent  # Memory usage percentage
    load_avg = psutil.getloadavg()[0]  # 1-minute load average
    return cpu_usage, memory_usage, load_avg

def get_dynamic_capacity():
    cpu_usage, memory_usage, load_avg = get_system_load()
    if cpu_usage > 90 or memory_usage > 90 or load_avg > psutil.cpu_count():
        return 10000
    elif cpu_usage > 80 or memory_usage > 80:
        return 20000
    elif cpu_usage > 70 or memory_usage > 70:
        return 40000
    elif cpu_usage > 60 or memory_usage > 60:
        return 80000
    elif cpu_usage > 50 or memory_usage > 50:
        return 160000
    else:
        return 200000

def get_dynamic_leak_rate():
    cpu_usage, memory_usage, load_avg = get_system_load()
    if cpu_usage > 90 or memory_usage > 90 or load_avg > psutil.cpu_count():
        return 1700
    elif cpu_usage > 80 or memory_usage > 80:
        return 3400
    elif cpu_usage > 70 or memory_usage > 70:
        return 6800
    elif cpu_usage > 60 or memory_usage > 60:
        return 13600
    elif cpu_usage > 50 or memory_usage > 50:
        return 27200
    else:
        return 40000

redis_connection = get_redis_connection()
rate_limiter = RateLimiter(redis_connection=redis_connection, get_capacity=get_dynamic_capacity, get_leak_rate=get_dynamic_leak_rate)
