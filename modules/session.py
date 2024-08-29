import hashlib
import os

def session():
    # Generate a random secret key
    secret_key = os.urandom(64)
    
    # Create a Whirlpool hashed secret key
    hashed_key = hashlib.new('whirlpool', secret_key).hexdigest()
    
    return hashed_key
