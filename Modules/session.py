from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import secrets

def generate_key():
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

def generate_session_key(length: int = 128) -> str:
    salt = secrets.token_bytes(128)
    ikm = secrets.token_bytes(128)
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=b'key derivation',
        backend=default_backend()
    )
    derived_key = hkdf.derive(ikm)
    return derived_key.hex()
