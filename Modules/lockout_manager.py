from datetime import datetime, timedelta
import logging
from .db_manager import db_manager # Adjust import based on your db manager location

class LockoutManager:
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    LOCKOUT_INCREMENT = timedelta(minutes=5)

    @staticmethod
    def is_account_locked(user):
        lockout_expiration = user['lockout_expiration']
        if lockout_expiration is None:
            return False
        if isinstance(lockout_expiration, str):
            lockout_expiration = datetime.strptime(lockout_expiration, '%Y-%m-%d %H:%M:%S')
        if datetime.now() < lockout_expiration:
            return True
        else:
            return False

    @staticmethod
    def increase_lockout_time(user):
        new_lockout_time = datetime.now() + LockoutManager.LOCKOUT_INCREMENT
        try:
            conn = db_manager.get_connection()
            with conn.cursor() as cursor:
                cursor.execute("UPDATE super_admin SET lockout_expiration = %s WHERE id = %s", 
                               (new_lockout_time, user['id']))
                conn.commit()
        except Exception as e:
            logging.error(f"Error increasing lockout time: {e}")
        finally:
            conn.close()

    @staticmethod
    def reset_failed_attempts(user):
        try:
            conn = db_manager.get_connection()
            with conn.cursor() as cursor:
                cursor.execute("UPDATE super_admin SET failed_attempts = 0, lockout_expiration = NULL WHERE id = %s", 
                               (user['id'],))
                conn.commit()
        except Exception as e:
            logging.error(f"Error resetting failed attempts: {e}")
        finally:
            conn.close()

    @staticmethod
    def increment_failed_attempts(user):
        try:
            conn = db_manager.get_connection()
            with conn.cursor() as cursor:
                new_failed_attempts = user['failed_attempts'] + 1
                if new_failed_attempts >= LockoutManager.MAX_FAILED_ATTEMPTS:
                    lockout_time = datetime.now() + LockoutManager.LOCKOUT_DURATION
                    cursor.execute("UPDATE super_admin SET failed_attempts = %s, lockout_expiration = %s WHERE id = %s", 
                                   (new_failed_attempts, lockout_time, user['id']))
                else:
                    cursor.execute("UPDATE super_admin SET failed_attempts = %s WHERE id = %s", 
                                   (new_failed_attempts, user['id']))
                conn.commit()
        except Exception as e:
            logging.error(f"Error incrementing failed attempts: {e}")
        finally:
            conn.close()
