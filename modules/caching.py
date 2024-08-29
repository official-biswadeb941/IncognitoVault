import json
import redis
import logging
import time
from urllib.parse import urlparse
from redis.exceptions import RedisError, ConnectionError, TimeoutError
from apscheduler.schedulers.background import BackgroundScheduler

def load_caching_servers():
    """Load caching server URLs from a JSON file."""
    with open('Database/caching.json') as f:
        data = json.load(f)
    return list(data.values())

class RoundRobinRedis:
    """A class to manage Redis connections using round-robin strategy."""
    def __init__(self, urls):
        self.urls = urls
        self.current = 0
        self.clients = [self._create_client(url) for url in urls]

    def _create_client(self, url):
        """Create a Redis client from a URL."""
        parsed_url = urlparse(url)
        return redis.StrictRedis(
            host=parsed_url.hostname,
            port=parsed_url.port,
            password=parsed_url.password,
            ssl=True
        )

    def _get_client(self):
        """Return a Redis client using round-robin strategy."""
        client = self.clients[self.current]
        self.current = (self.current + 1) % len(self.clients)
        return client

    def __getattr__(self, name):
        """Delegate attribute access to the current Redis client."""
        client = self._get_client()
        return getattr(client, name)

class RobustRoundRobinRedis(RoundRobinRedis):
    """A subclass of RoundRobinRedis that adds retry, timeout, and connection validation."""
    def __init__(self, urls, retries=3, timeout=5):
        super().__init__(urls)
        self.retries = retries
        self.timeout = timeout

    def _get_client(self):
        """Return a Redis client with retry and timeout configurations."""
        client = super()._get_client()
        return redis.StrictRedis(
            host=client.connection_pool.connection_kwargs['host'],
            port=client.connection_pool.connection_kwargs['port'],
            password=client.connection_pool.connection_kwargs.get('password'),
            ssl=True,
            socket_timeout=self.timeout,
            socket_connect_timeout=self.timeout
        )

    def _execute_with_retry(self, func, *args, **kwargs):
        """Execute a Redis command with retry and exponential backoff on failure."""
        for attempt in range(self.retries):
            try:
                return func(*args, **kwargs)
            except (RedisError, ConnectionError, TimeoutError) as e:
                logging.warning(f"Redis operation attempt {attempt + 1} failed: {e}")
                if attempt == self.retries - 1:
                    raise
                # Exponential backoff
                time.sleep(2 ** attempt)

    def get(self, key):
        """Get value from Redis with retry."""
        client = self._get_client()
        return self._execute_with_retry(client.get, key)

    def set(self, key, value, ex=None):
        """Set value in Redis with retry."""
        client = self._get_client()
        return self._execute_with_retry(client.set, key, value, ex=ex)

    def delete(self, key):
        """Delete a key from Redis with retry."""
        client = self._get_client()
        return self._execute_with_retry(client.delete, key)

    def flush_all(self):
        """Flush all keys from Redis with retry."""
        client = self._get_client()
        return self._execute_with_retry(client.flushall)

# Function to reset caching server once a month
def reset_caching_server():
    """Flush all caching servers once a month."""
    logging.info("Resetting caching servers...")
    redis_client = RobustRoundRobinRedis(load_caching_servers())
    redis_client.flush_all()
    logging.info("Caching servers reset.")

# Schedule the reset task
scheduler = BackgroundScheduler()
scheduler.add_job(reset_caching_server, 'cron', day=1, hour=0, minute=0)  # Runs at midnight on the first day of each month
scheduler.start()
