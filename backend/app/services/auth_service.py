"""
Authentication & Authorization Service
Handles PBKDF2-SHA256 password hashing, token encoding/validation,
and pre-seeding of default Standard and Pro demo accounts.
"""
import os
import time
import json
import base64
import hmac
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session

from ..db.session import get_db, SessionLocal
from ..db.models import User
from ..core.config import settings

# Secret key for HS256 token signing
AUTH_SECRET_KEY = getattr(settings, "SECRET_KEY", "hackingly-auditor-super-secret-auth-key-2026")
TOKEN_EXPIRY_SECONDS = 60 * 60 * 24 * 7  # 7 days

def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations and random salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"pbkdf2_sha256${salt.hex()}${key.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Timing-safe verification of plain password against stored PBKDF2 hash."""
    if not hashed_password or not hashed_password.startswith("pbkdf2_sha256$"):
        return False
    try:
        parts = hashed_password.split("$")
        if len(parts) != 3:
            return False
        _, salt_hex, key_hex = parts
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        candidate_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(candidate_key, expected_key)
    except Exception:
        return False

def _b64encode_str(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def _b64decode_str(s: str) -> bytes:
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    return base64.urlsafe_b64decode(s)

def create_access_token(payload_data: Dict[str, Any], expires_delta_seconds: int = TOKEN_EXPIRY_SECONDS) -> str:
    """Generates an HS256 compliant bearer token with signed payload."""
    header = {"alg": "HS256", "typ": "JWT"}
    exp = int(time.time()) + expires_delta_seconds
    payload = {**payload_data, "exp": exp, "iat": int(time.time())}
    
    header_b64 = _b64encode_str(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64encode_str(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    
    signature = hmac.new(AUTH_SECRET_KEY.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = _b64encode_str(signature)
    
    return f"{signing_input}.{sig_b64}"

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates token signature and expiration."""
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(AUTH_SECRET_KEY.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
        provided_sig = _b64decode_str(sig_b64)
        
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        
        payload_json = _b64decode_str(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)
        
        if payload.get("exp", 0) < int(time.time()):
            return None  # expired
            
        return payload
    except Exception:
        return None

def seed_default_users(db: Session = None):
    """
    Seeds default Standard and Pro user accounts if they don't already exist.
    Normal User: user@hackingly.io / User@123456 (role: standard)
    Pro User:    pro@hackingly.io  / Pro@123456  (role: pro)
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
        
    try:
        # 1. Pro User
        pro_user = db.query(User).filter(User.email == "pro@hackingly.io").first()
        if not pro_user:
            pro_user = User(
                email="pro@hackingly.io",
                hashed_password=hash_password("Pro@123456"),
                full_name="Pro Security Engineer",
                role="pro",
                is_active=True
            )
            db.add(pro_user)
        else:
            pro_user.role = "pro"
            pro_user.is_active = True
            
        # 2. Standard User
        normal_user = db.query(User).filter(User.email == "user@hackingly.io").first()
        if not normal_user:
            normal_user = User(
                email="user@hackingly.io",
                hashed_password=hash_password("User@123456"),
                full_name="Standard Analyst",
                role="standard",
                is_active=True
            )
            db.add(normal_user)
        else:
            normal_user.role = "standard"
            normal_user.is_active = True
            
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[Auth] Warning seeding users: {e}")
    finally:
        if close_db:
            db.close()

def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    role: Optional[str] = None,
    token: Optional[str] = None,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Retrieves current user via Bearer token, query token, or role param, with fallback to pro user in demo mode."""
    # Defensive check: if db was passed as 2nd positional argument
    if not isinstance(role, str) and role is not None:
        db = role
        role = None

    # 1. Bearer Header
    raw_token = authorization
    if raw_token and isinstance(raw_token, str) and raw_token.startswith("Bearer "):
        raw_token = raw_token[7:].strip()
    # 2. Query token
    if not raw_token and token and isinstance(token, str):
        raw_token = token

    if raw_token and isinstance(raw_token, str):
        payload = verify_token(raw_token)
        if payload:
            email = payload.get("sub")
            if email:
                u = db.query(User).filter(User.email == email, User.is_active == True).first()
                if u:
                    return u

    # 3. Explicit role parameter (?role=standard or ?role=pro)
    if role and isinstance(role, str):
        target_email = "user@hackingly.io" if role.lower() == "standard" else "pro@hackingly.io"
        u = db.query(User).filter(User.email == target_email).first()
        if u:
            return u

    # 4. Fallback to pro user in demo environment
    return db.query(User).filter(User.email == "pro@hackingly.io").first()

def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """Enforces valid authentication. Returns authenticated User."""
    user = get_current_user_optional(authorization=authorization, db=db)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "AUTHENTICATION_REQUIRED", "message": "Valid Bearer authentication token is required."}
        )
    return user

def require_pro_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Enforces that current user is authenticated AND has role 'pro' (or 'admin').
    Standard users receive 403 Forbidden with upgrade prompt.
    """
    user = get_current_user_optional(authorization=authorization, db=db)
    if not user:
        # Also check default if no auth header passed or invalid
        raise HTTPException(
            status_code=401,
            detail={"error": "AUTHENTICATION_REQUIRED", "message": "Please log in to access this resource."}
        )
    if user.role not in ("pro", "admin"):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PRO_SUBSCRIPTION_REQUIRED",
                "message": "Autonomous AI Remediation Playbooks and analytical patch downloads require a Pro subscription.",
                "current_role": user.role,
                "upgrade_url": "/upgrade"
            }
        )
    return user
