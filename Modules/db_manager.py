# db_manager.py

import json
import os
import pymysql
from dbutils.pooled_db import PooledDB

class DatabaseManager:
    def __init__(self, config_path='Database/DB.json', db_section='1_DB'):
        self.config_path = config_path
        self.db_section = db_section
        self.pool = None
        self.ssl_config = None
        self._initialize_pool()

    def _load_db_config(self):
        """Load the database configuration from the specified JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                db_config = json.load(f).get(self.db_section, {})
                return db_config
        except FileNotFoundError:
            raise Exception(f"Database configuration file '{self.config_path}' not found.")

    def _initialize_pool(self):
        """Initialize the connection pool based on the configuration."""
        db_config = self._load_db_config()
        self.ssl_config = db_config.get('ssl', {})
        self.ssl_config['ca'] = os.path.join('Database', self.ssl_config.get('ca', 'ca.pem'))

        self.pool = PooledDB(
            creator=pymysql,  # The database module to use
            maxconnections=20,  # The maximum number of connections allowed
            mincached=5,  # The minimum number of connections to be cached
            maxcached=10,  # The maximum number of connections to be cached
            maxshared=10,  # The maximum number of shared connections
            blocking=True,  # Whether to block if the pool is full
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password'],
            database=db_config['database'],
            port=int(db_config['port']),
            cursorclass=pymysql.cursors.DictCursor,
            ssl=self.ssl_config
        )

    def get_connection(self):
        """Get a connection from the connection pool."""
        if self.pool is None:
            raise Exception("Database connection pool is not initialized.")
        return self.pool.connection()

    def close_pool(self):
        """Close the pool gracefully if needed."""
        self.pool = None

# Instantiate a global DatabaseManager object to reuse across the app
db_manager = DatabaseManager()
