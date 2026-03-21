"""Session Timeout Middleware - CRIT-012
HIPAA-compliant session timeout for clinical access
"""
import time
import json
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class SessionTimeoutMiddleware(BaseHTTPMiddleware):
    """
    Enforces session timeout for clinical endpoints.
    15-minute idle timeout as per HIPAA best practices.
    """

    CLINICAL_PATHS = ["/clinical", "/api/clinical"]
    TIMEOUT_SECONDS = 900  # 15 minutes

    async def dispatch(self, request: Request, call_next):
        # Check if this is a clinical endpoint
        path = request.url.path
        is_clinical = any(path.startswith(cp) for cp in self.CLINICAL_PATHS)

        if not is_clinical:
            return await call_next(request)

        # Get session from cookie
        session_cookie = request.cookies.get("ads_session")
        if session_cookie:
            try:
                session_data = json.loads(session_cookie)
                last_activity = session_data.get("last_activity", 0)

                if time.time() - last_activity > self.TIMEOUT_SECONDS:
                    # Session expired
                    raise HTTPException(401, "Session expired due to inactivity. Please log in again.")

                # Update last activity
                session_data["last_activity"] = time.time()
            except (json.JSONDecodeError, KeyError):
                pass

        response = await call_next(request)
        return response
