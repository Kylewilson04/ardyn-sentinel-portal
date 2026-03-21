"""
Ardyn Billing — FastAPI Auth Middleware
========================================
API key validation with Redis caching and rate limiting.

Usage:
    from enterprise.billing.middleware import require_api_key

    @app.post("/v1/process")
    async def process(request: Request, auth=Depends(require_api_key)):
        org_id = auth["organization_id"]
        tier = auth["tier"]
"""

import os
import time
import json
import hashlib
import logging
import threading
from typing import Optional, Dict, Any

from fastapi import Request, HTTPException

logger = logging.getLogger("ardyn.billing.middleware")

# ---------------------------------------------------------------------------
# Redis (optional — graceful fallback to DB-only)
# ---------------------------------------------------------------------------

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL = 60  # seconds

_redis = None

def _get_redis():
    """Lazy Redis connection — returns None if unavailable."""
    global _redis
    if _redis is not None:
        return _redis
    try:
        import redis
        _redis = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=0.1)
        _redis.ping()
        logger.info("Redis connected for API key caching")
        return _redis
    except Exception:
        logger.warning("Redis unavailable — falling back to DB-only auth (slower)")
        _redis = False  # Don't retry every request
        return None


def _cache_get(key_hash: str) -> Optional[Dict]:
    """Get cached auth result by key hash."""
    r = _get_redis()
    if not r:
        return None
    try:
        data = r.get(f"ardyn:auth:{key_hash}")
        return json.loads(data) if data else None
    except Exception:
        return None


def _cache_set(key_hash: str, auth_data: Dict):
    """Cache auth result with TTL."""
    r = _get_redis()
    if not r:
        return
    try:
        r.setex(f"ardyn:auth:{key_hash}", CACHE_TTL, json.dumps(auth_data))
    except Exception:
        pass


def _cache_delete(key_hash: str):
    """Invalidate cached auth (call on key revocation)."""
    r = _get_redis()
    if not r:
        return
    try:
        r.delete(f"ardyn:auth:{key_hash}")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Rate Limiting (Redis-based, per org)
# ---------------------------------------------------------------------------

RATE_LIMITS = {
    "individual": 100,    # req/min
    "enterprise": 10000,  # req/min
}

# In-memory fallback rate limiter (used when Redis is unavailable)
_memory_rate: Dict[str, list] = {}
_memory_rate_lock = threading.Lock()


def _check_rate_limit_memory(org_id: str, tier: str) -> bool:
    """Sliding-window rate limit using in-memory dict. Fallback when Redis is down."""
    limit = RATE_LIMITS.get(tier, 100)
    now = time.time()
    window_start = now - 60

    with _memory_rate_lock:
        timestamps = _memory_rate.get(org_id, [])
        # Prune old entries
        timestamps = [t for t in timestamps if t > window_start]
        if len(timestamps) >= limit:
            _memory_rate[org_id] = timestamps
            return False
        timestamps.append(now)
        _memory_rate[org_id] = timestamps
        return True


def _check_rate_limit(org_id: str, tier: str) -> bool:
    """
    Check rate limit using Redis sliding window.
    Returns True if allowed, False if rate limited.
    Falls back to allowing all requests if Redis is down.
    """
    r = _get_redis()
    if not r:
        return _check_rate_limit_memory(org_id, tier)

    limit = RATE_LIMITS.get(tier, 100)
    window_key = f"ardyn:rate:{org_id}"

    try:
        pipe = r.pipeline()
        now = time.time()
        window_start = now - 60

        # Remove old entries, add current, count
        pipe.zremrangebyscore(window_key, 0, window_start)
        pipe.zadd(window_key, {f"{now}:{id(pipe)}": now})
        pipe.zcard(window_key)
        pipe.expire(window_key, 120)
        results = pipe.execute()

        current_count = results[2]
        return current_count <= limit
    except Exception:
        return True  # Fail open


# ---------------------------------------------------------------------------
# FastAPI Dependency
# ---------------------------------------------------------------------------

def _extract_key(request: Request) -> Optional[str]:
    """Extract API key from Authorization header or X-API-Key."""
    # Check Authorization: Bearer <key>
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    # Check X-API-Key header
    api_key = request.headers.get("x-api-key", "")
    if api_key:
        return api_key.strip()

    return None


async def require_api_key(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency for API key authentication.

    Extracts key from headers, validates via cache/DB, enforces rate limits.
    Injects auth context into request.state for downstream use.

    Usage:
        @app.post("/v1/process")
        async def process(request: Request, auth=Depends(require_api_key)):
            org_id = auth["organization_id"]
    """
    raw_key = _extract_key(request)
    if not raw_key:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "API Key missing or invalid. Get your key at: https://platform.ardyn.ai/signup"
            },
        )

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    # 1. Check Redis cache first (sub-ms)
    auth_data = _cache_get(key_hash)

    # 2. Fall back to DB
    if auth_data is None:
        from enterprise.billing.models import validate_api_key
        auth_data = validate_api_key(raw_key)

        if auth_data is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "API Key missing or invalid. Get your key at: https://platform.ardyn.ai/signup"
                },
            )

        # Cache for next time
        _cache_set(key_hash, auth_data)

    # 3. Check billing status
    if auth_data.get("billing_status") != "active":
        raise HTTPException(
            status_code=403,
            detail={"error": "Account suspended. Contact compliance@ardyn.ai"},
        )

    # 4. Rate limit check
    if not _check_rate_limit(auth_data["organization_id"], auth_data["tier"]):
        limit = RATE_LIMITS.get(auth_data["tier"], 100)
        raise HTTPException(
            status_code=429,
            detail={
                "error": f"Rate limit exceeded ({limit} req/min for {auth_data['tier']} tier)",
                "retry_after": 60,
            },
        )

    # 5. Inject into request state for downstream handlers
    request.state.organization_id = auth_data["organization_id"]
    request.state.tier = auth_data["tier"]
    request.state.api_key_id = auth_data["api_key_id"]

    return auth_data
