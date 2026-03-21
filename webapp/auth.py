"""Authentication: register, login, sessions, API key validation."""
import time
import uuid
import jwt
import os
import logging
import threading
from typing import Optional
from fastapi import Request, HTTPException
from passlib.hash import bcrypt
from slowapi import Limiter
from slowapi.util import get_remote_address
from database import get_db, generate_api_key, hash_api_key

log = logging.getLogger("ardyn.auth")

# Rate limiter: 5 requests per 15 minutes per IP for auth endpoints
limiter = Limiter(key_func=get_remote_address)

# JWT secret from environment (NEVER hardcode in production)
SECRET = os.environ.get("ADS_JWT_SECRET")
if not SECRET:
    raise RuntimeError("FATAL: ADS_JWT_SECRET not set. Generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\"")
ALGO = "HS256"
TOKEN_EXPIRE = 86400 * 7  # 7 days

def create_user(email: str, password: str) -> dict:
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, "Email already registered")
    user_id = uuid.uuid4().hex
    pw_hash = bcrypt.hash(password)
    conn.execute("INSERT INTO users (id, email, password_hash, created_at) VALUES (?,?,?,?)",
                 (user_id, email, pw_hash, time.time()))
    # Auto-generate API key
    raw_key = generate_api_key()
    key_id = uuid.uuid4().hex[:12]
    conn.execute("INSERT INTO api_keys (key_id, user_id, key_hash, key_prefix, created_at) VALUES (?,?,?,?,?)",
                 (key_id, user_id, hash_api_key(raw_key), raw_key[:12], time.time()))
    conn.commit()
    conn.close()
    # Fire-and-forget drip email schedule
    try:
        from drip_emails import schedule_drip
        threading.Thread(target=schedule_drip, args=(email, raw_key), daemon=True).start()
    except Exception as e:
        log.warning(f"Drip schedule failed: {e}")
    return {"user_id": user_id, "email": email, "api_key": raw_key}

def authenticate(email: str, password: str) -> dict:
    conn = get_db()
    row = conn.execute("SELECT id, email, password_hash, role, org_id, vertical, jurisdiction FROM users WHERE LOWER(email)=LOWER(?) AND is_active=1", (email,)).fetchone()
    conn.close()
    if not row or not bcrypt.verify(password, row["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    # Convert row to dict for easier access
    user = dict(row)
    return {
        "user_id": user["id"],
        "email": user["email"],
        "role": user.get("role", "user"),
        "org_id": user.get("org_id", user["id"]),
        "vertical": user.get("vertical", "general"),
        "jurisdiction": user.get("jurisdiction", "us")
    }

def create_token(user_id: str, email: str, role: str = "user", org_id: str = None,
                 vertical: str = "general", jurisdiction: str = "us") -> str:
    # CRIT-005: Include org context in JWT
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "org_id": org_id or user_id,
        "vertical": vertical,
        "jurisdiction": jurisdiction,
        "exp": time.time() + TOKEN_EXPIRE
    }
    token = jwt.encode(payload, SECRET, ALGO)
    return token if isinstance(token, str) else token.decode("utf-8")

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO], options={"verify_exp": True})
        # CRIT-005: Ensure all claims are present
        return {
            "sub": payload.get("sub"),
            "email": payload.get("email"),
            "role": payload.get("role", "user"),
            "org_id": payload.get("org_id", payload.get("sub")),
            "vertical": payload.get("vertical", "general"),
            "jurisdiction": payload.get("jurisdiction", "us"),
            "exp": payload.get("exp")
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

async def get_current_user(request: Request) -> dict:
    # Try cookie first
    token = request.cookies.get("ads_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        # Try API key
        api_key = request.headers.get("X-API-Key", "")
        if api_key:
            return await get_user_by_api_key(api_key)
        raise HTTPException(401, "Not authenticated")

    user = decode_token(token)
    # Add admin status
    user = add_user_admin_status(user)
    return user

def add_user_admin_status(user: dict) -> dict:
    """Add is_admin flag to user dict from database."""
    try:
        conn = get_db()
        row = conn.execute("SELECT is_admin FROM users WHERE id=?", (user.get("sub"),)).fetchone()
        conn.close()
        user["is_admin"] = bool(row["is_admin"]) if row and row["is_admin"] else False
    except Exception:
        # Column may not exist yet
        user["is_admin"] = False
    return user

async def get_admin_user(request: Request) -> dict:
    """Get user and verify admin status for portal access. Returns 403 for non-admins."""
    user = await get_current_user(request)
    if not user.get("is_admin"):
        log.warning(f"BLOCKED: Non-admin user {user.get('email')} attempted admin portal access")
        raise HTTPException(403, "Admin access required")
    return user

async def get_user_by_api_key(key: str) -> dict:
    conn = get_db()
    kh = hash_api_key(key)
    row = conn.execute("""
        SELECT ak.user_id, u.email, u.is_admin FROM api_keys ak
        JOIN users u ON u.id = ak.user_id
        WHERE ak.key_hash=? AND ak.is_active=1 AND u.is_active=1
    """, (kh,)).fetchone()
    if row:
        conn.execute("UPDATE api_keys SET last_used=? WHERE key_hash=?", (time.time(), kh))
        conn.commit()
    conn.close()
    if not row:
        raise HTTPException(401, "Invalid API key")
    return {"sub": row["user_id"], "email": row["email"], "is_admin": bool(row["is_admin"]) if row["is_admin"] else False}

def regenerate_api_key(user_id: str) -> str:
    conn = get_db()
    conn.execute("UPDATE api_keys SET is_active=0 WHERE user_id=?", (user_id,))
    raw_key = generate_api_key()
    key_id = uuid.uuid4().hex[:12]
    conn.execute("INSERT INTO api_keys (key_id, user_id, key_hash, key_prefix, created_at) VALUES (?,?,?,?,?)",
                 (key_id, user_id, hash_api_key(raw_key), raw_key[:12], time.time()))
    conn.commit()
    conn.close()
    return raw_key

def get_user_api_key(user_id: str) -> Optional[str]:
    conn = get_db()
    row = conn.execute("SELECT key_prefix FROM api_keys WHERE user_id=? AND is_active=1 ORDER BY created_at DESC LIMIT 1",
                       (user_id,)).fetchone()
    conn.close()
    return row["key_prefix"] + "..." if row else None
