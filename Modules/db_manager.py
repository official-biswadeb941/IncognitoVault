import json
import os
import pymysql
import psutil
import logging
import re
from dbutils.pooled_db import PooledDB

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

class DatabaseManager:
    def __init__(self, config_path=None, db_section='1_DB'):
        self.config_path = config_path or os.getenv('DB_CONFIG_PATH', 'Database/DB.json')
        self.db_section = db_section
        self.pool = None
        self.ssl_config = None
        self._initialize_pool()

    def _load_db_config(self):
        """Load the database configuration from the specified JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                db_config = json.load(f).get(self.db_section, {})
                if not db_config:
                    raise ValueError(f"No configuration found for section '{self.db_section}' in '{self.config_path}'.")
                return db_config
        except FileNotFoundError:
            error_message = f"Database configuration file '{self.config_path}' not found."
            logging.error(error_message)
            raise Exception(error_message)
        except json.JSONDecodeError as e:
            error_message = f"Error decoding JSON from the configuration file '{self.config_path}': {e}."
            logging.error(error_message)
            raise Exception(error_message)
        except Exception as e:
            error_message = f"An unexpected error occurred while loading the database configuration: {e}."
            logging.error(error_message)
            raise Exception(error_message)

    def _validate_db_config(self, db_config):
        """Validate database configuration parameters."""
        required_fields = ['host', 'user', 'password', 'database', 'port']
        
        for field in required_fields:
            if field not in db_config:
                raise ValueError(f"Missing required database configuration field: '{field}'.")

        # Validate host (should be a valid hostname or IP)
        if not re.match(r'^[a-zA-Z0-9.-]+$', db_config['host']):
            raise ValueError(f"Invalid host name: '{db_config['host']}'. Must be a valid hostname or IP.")

        # Validate port (should be an integer within valid range)
        if not isinstance(db_config['port'], int) or not (1 <= db_config['port'] <= 65535):
            raise ValueError(f"Invalid port number: '{db_config['port']}'. Must be an integer between 1 and 65535.")

        # Validate user and database (alphanumeric with underscores)
        for field in ['user', 'database']:
            if not re.match(r'^\w+$', db_config[field]):
                raise ValueError(f"Invalid {field} name: '{db_config[field]}'. Must be alphanumeric with underscores.")

    def _calculate_pool_parameters(self):
        """Dynamically calculate pool parameters based on system resources."""
        total_memory = psutil.virtual_memory().total
        num_cpus = psutil.cpu_count()

        # Example formula for dynamic pool parameters
        max_connections = min(20, num_cpus * 2)
        min_cached = max(1, max_connections // 2)
        max_cached = max_connections
        max_shared = max_connections

        return max_connections, min_cached, max_cached, max_shared

    def _initialize_pool(self):
        """Initialize the connection pool based on the configuration."""
        try:
            db_config = self._load_db_config()
            self._validate_db_config(db_config)  # Validate the loaded config

            # Check SSL configuration
            self.ssl_config = db_config.get('ssl', {})
            ca_path = self.ssl_config.get('ca')
            if ca_path:
                self.ssl_config['ca'] = os.path.join('Database', ca_path)
                # Ensure that SSL mode is enforced
                self.ssl_config['check_hostname'] = True  # Enforce hostname checking
                self.ssl_config['ssl_disabled'] = False  # Ensure SSL is not disabled
            else:
                raise ValueError("SSL configuration missing 'ca' key.")

            # Calculate dynamic pool parameters
            self.max_connections, self.min_cached, self.max_cached, self.max_shared = self._calculate_pool_parameters()

            self.pool = PooledDB(
                creator=pymysql,
                maxconnections=self.max_connections,
                mincached=self.min_cached,
                maxcached=self.max_cached,
                maxshared=self.max_shared,
                blocking=True,
                host=db_config['host'],
                user=db_config['user'],
                password=db_config['password'],
                database=db_config['database'],
                port=int(db_config['port']),
                cursorclass=pymysql.cursors.DictCursor,
                ssl=self.ssl_config
            )
        except ValueError as ve:
            error_message = f"Configuration error: {ve}."
            logging.error(error_message)
            raise Exception(error_message)
        except Exception as e:
            error_message = f"Failed to initialize the database connection pool: {e}."
            logging.error(error_message)
            raise Exception(error_message)

    def get_connection(self):
        """Get a connection from the connection pool."""
        if self.pool is None:
            error_message = "Database connection pool is not initialized."
            logging.error(error_message)
            raise Exception(error_message)
        try:
            return self.pool.connection()
        except Exception as e:
            error_message = f"Failed to get a connection from the pool: {e}."
            logging.error(error_message)
            raise Exception(error_message)

    def close_pool(self):
        """Close the pool gracefully if needed."""
        if self.pool:
            self.pool.close()
            self.pool = None

# Instantiate a global DatabaseManager object to reuse across the app
db_manager = DatabaseManager()
