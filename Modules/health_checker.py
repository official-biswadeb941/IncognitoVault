import psutil
import json
import time
import socket
import platform
import speedtest
from flask import Flask, jsonify
from concurrent.futures import ThreadPoolExecutor
from Modules.redis_manager import redis_conn
from Modules.db_manager import db_manager

class ServerHealthChecker:
    @staticmethod
    def check_cpu_usage():
        return {"cpu_usage": f"{psutil.cpu_percent(interval=0.1)} %"}  # Faster CPU check

    @staticmethod
    def check_memory_usage():
        mem = psutil.virtual_memory()
        return {
            "total_memory": f"{mem.total / (1024**3):.2f} GB",
            "used_memory": f"{mem.used / (1024**3):.2f} GB",
            "memory_usage": f"{mem.percent} %"
        }

    @staticmethod
    def check_swap_usage():
        swap = psutil.swap_memory()
        return {
            "total_swap": f"{swap.total / (1024**3):.2f} GB",
            "used_swap": f"{swap.used / (1024**3):.2f} GB",
            "swap_usage": f"{swap.percent} %"
        }

    @staticmethod
    def check_network_speed():
        try:
            s = speedtest.Speedtest()
            s.get_best_server()
            ping_latency = s.results.ping  # Get ping first (faster)
            download_speed = s.download() / 1_000_000  # Convert to Mbps
            upload_speed = s.upload() / 1_000_000  # Convert to Mbps

            return {
                "ping_latency": f"{ping_latency:.2f} ms",
                "download_speed": f"{download_speed:.2f} Mbps",
                "upload_speed": f"{upload_speed:.2f} Mbps"
            }
        except Exception as e:
            return {"network_speed_error": str(e)}

    @staticmethod
    def check_redis_connection():
        try:
            redis_conn.ping()
            return {"redis_status": "Connected"}
        except Exception as e:
            return {"redis_status": f"Error: {str(e)}"}

    @staticmethod
    def check_mysql_connection():
        try:
            conn = db_manager.get_connection()
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
            conn.close()
            return {"mysql_status": "Connected"}
        except Exception as e:
            return {"mysql_status": f"Error: {str(e)}"}
    
    @staticmethod
    def check_disk_usage():
        disk = psutil.disk_usage('/')
        return {
            "total_disk": f"{disk.total / (1024**3):.2f} GB",
            "used_disk": f"{disk.used / (1024**3):.2f} GB",
            "disk_usage": f"{disk.percent} %"
        }
    
    @classmethod
    def health_check(cls):
        """ Runs all health checks in parallel for faster execution. """
        checks = {
            "cpu_usage": cls.check_cpu_usage,
            "memory_usage": cls.check_memory_usage,
            "swap_usage": cls.check_swap_usage,  # Added swap memory check
            "network_speed": cls.check_network_speed,
            "redis_status": cls.check_redis_connection,
            "mysql_status": cls.check_mysql_connection,
            "disk_usage": cls.check_disk_usage
        }

        results = {}
        with ThreadPoolExecutor(max_workers=7) as executor:  # Updated max_workers to 7
            futures = {executor.submit(func): key for key, func in checks.items()}
            for future in futures:
                results.update(future.result())

        return results

HealthChecker = ServerHealthChecker()

