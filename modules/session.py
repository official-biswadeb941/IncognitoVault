import hashlib
import os
import binascii

def session():
    # Generate a larger random secret key (128 bytes for added strength)
    secret_key = os.urandom(512)
    
    # Use PBKDF2-HMAC with Whirlpool and many iterations for extra security
    salt = os.urandom(128)  # Use a longer salt (64 bytes)
    iterations = 200000    # Increase the number of iterations for added security
    
    # Use Whirlpool instead of SHA512
    hashed_key = hashlib.pbkdf2_hmac('whirlpool', secret_key, salt, iterations)
    
    # Convert the binary hashed key to a hexadecimal string
    hashed_key = binascii.hexlify(hashed_key).decode('utf-8')

    return hashed_key