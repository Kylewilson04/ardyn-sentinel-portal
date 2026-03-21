"""API Rate Limiting - HIGH-004
Rate limiting for inference and document endpoints
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

# General API rate limiter: 100 requests per minute per IP
api_limiter = Limiter(key_func=get_remote_address)

# Stricter limiter for inference: 20 requests per minute
inference_limiter = Limiter(key_func=get_remote_address)
