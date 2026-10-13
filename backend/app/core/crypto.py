"""
Encryption and Secret Protection Utility
Provides symmetric Fernet encryption for sensitive credentials and channel secrets.
"""
import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet
from .config import settings

def _get_fernet_key() -> bytes:
    raw_key = settings.ENCRYPTION_KEY
    if raw_key and len(raw_key.strip()) >= 32:
        clean = raw_key.strip()
        try:
            # Check if it's already a valid Fernet 32-byte urlsafe base64 key
            Fernet(clean.encode())
            return clean.encode()
        except Exception:
            # Hash to 32 bytes and base64-encode
            hashed = hashlib.sha256(clean.encode()).digest()
            return base64.urlsafe_b64encode(hashed)
    
    # Deterministic fallback key derived from project name
    fallback_seed = f"auditor-secret-key-{settings.PROJECT_NAME}".encode()
    hashed = hashlib.sha256(fallback_seed).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_secret(plain_text: str) -> str:
    """
    Encrypts sensitive plain text string into a base64 ciphertext token.
    """
    if not plain_text:
        return ""
    key = _get_fernet_key()
    fernet = Fernet(key)
    return fernet.encrypt(plain_text.encode()).decode()

def decrypt_secret(cipher_text: str) -> str:
    """
    Decrypts encrypted token back into plain text string.
    """
    if not cipher_text:
        return ""
    try:
        key = _get_fernet_key()
        fernet = Fernet(key)
        return fernet.decrypt(cipher_text.encode()).decode()
    except Exception:
        # Return as-is if not encrypted
        return cipher_text
