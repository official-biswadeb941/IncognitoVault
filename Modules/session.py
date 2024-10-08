from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import secrets

class KeyGenerator:
    def __init__(self, hash_algorithm=hashes.SHA512(), default_length=128, backend=default_backend()):
        self.hash_algorithm = hash_algorithm
        self.default_length = default_length
        self.backend = backend

    def generate_key(self) -> str:
        """Generates a derived key using HKDF."""
        salt = secrets.token_bytes(64)
        ikm = secrets.token_bytes(80)
        hkdf = HKDF(
            algorithm=self.hash_algorithm,
            length=self.default_length,
            salt=salt,
            info=b'key derivation',
            backend=self.backend
        )
        derived_key = hkdf.derive(ikm)
        return derived_key.hex()

    def generate_session_key(self, length: int = None) -> str:
        """Generates a session key of specified length using HKDF."""
        if length is None:
            length = self.default_length
        salt = secrets.token_bytes(128)
        ikm = secrets.token_bytes(128)
        hkdf = HKDF(
            algorithm=self.hash_algorithm,
            length=length,
            salt=salt,
            info=b'key derivation',
            backend=self.backend
        )
        derived_key = hkdf.derive(ikm)
        return derived_key.hex()

key_gen = KeyGenerator()