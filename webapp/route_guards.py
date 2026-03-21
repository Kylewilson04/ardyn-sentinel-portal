"""
Vertical Route Guards Middleware

Prevents cross-vertical access:
- Users can only access routes matching their organization's vertical.
- Supports: healthcare, legal, finance, cybersecurity, general.
"""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

# Vertical → route prefix mapping
VERTICAL_ROUTE_PREFIXES = {
    "healthcare": ["/health/", "/clinical", "/health-us", "/health-ca"],
    "legal": ["/legal/", "/counsel", "/matters", "/legal-us", "/legal-ca"],
    "finance": ["/finance/"],
    "cybersecurity": ["/security/"],
}


class VerticalRouteGuardMiddleware(BaseHTTPMiddleware):
    """Enforce vertical-based route access control."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip for public routes
        public_routes = ["/", "/login", "/register", "/logout", "/health", "/v1/health"]
        if path in public_routes or path.startswith("/static/") or path.startswith("/enterprise/"):
            return await call_next(request)

        # Also skip vertical landing pages
        for vid in VERTICAL_ROUTE_PREFIXES:
            if path == f"/{vid}":
                return await call_next(request)

        # Get user from session
        try:
            user = request.session.get("user")
            if not user:
                return await call_next(request)
        except AssertionError:
            return await call_next(request)

        user_vertical = user.get("vertical", "general")

        # Check if user is accessing a different vertical's routes
        for vertical, prefixes in VERTICAL_ROUTE_PREFIXES.items():
            if vertical == user_vertical:
                continue
            if any(path.startswith(r) for r in prefixes):
                return RedirectResponse(
                    url=f"/dashboard?error=This area is for {vertical.title()} organizations only",
                    status_code=302
                )

        return await call_next(request)


def get_allowed_personas(vertical: str) -> list:
    """Get personas allowed for a given vertical."""
    common = ["default", "ardyn", "operations", "analyst"]

    # Load vertical-specific personas from registry
    try:
        from vertical_registry import vertical_registry
        cfg = vertical_registry.get(vertical)
        if cfg:
            return common + [p["id"] for p in cfg.personas]
    except Exception:
        pass

    return common


def get_system_prompt(persona: str, vertical: str) -> str:
    """Get the appropriate system prompt for persona and vertical."""
    try:
        from vertical_registry import vertical_registry
        cfg = vertical_registry.get(vertical)
        if cfg:
            for p in cfg.personas:
                if p["id"] == persona:
                    return p.get("system_prompt", "")
            # If persona not found in vertical, return vertical template
            return cfg.system_prompt_template
    except Exception:
        pass

    return "You are a helpful AI assistant operating in a sovereignty-secured environment."
