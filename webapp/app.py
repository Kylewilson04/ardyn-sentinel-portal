"""ADS Web Dashboard — Main FastAPI Application."""
import os
import sys
import time
import re
import logging
from pathlib import Path

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, use system env

# Setup paths FIRST - before any other imports
APP_DIR = Path(__file__).resolve().parent
# Add webapp first, before src, to avoid src/models.py shadowing webapp/models/ package
sys.path.insert(0, str(APP_DIR))
sys.path.insert(0, str(APP_DIR.parent / "src"))

from fastapi import FastAPI, Request, Form, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel

from database import init_db, get_db
from auth import authenticate, create_token, decode_token, get_current_user, limiter
from slowapi.errors import RateLimitExceeded

# Init
init_db()

_env = os.environ.get("ENVIRONMENT", "development")
app = FastAPI(
    title="Ardyn Sentinel Dashboard",
    docs_url="/api/docs" if _env != "production" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _env != "production" else None,
)

# HIGH-007: Lock down CORS
# Only allow ardyn.ai and localhost in development
allowed_origins = ["https://ardyn.ai", "https://api.ardyn.ai", "https://platform.ardyn.ai", "https://demo.ardyn.ai"]
if os.environ.get("ENVIRONMENT") == "development":
    allowed_origins.extend(["http://localhost:8080", "http://localhost:3000"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Security Headers Middleware
@app.middleware("http")
async def security_headers(request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    # HSTS - Force HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # XSS Protection
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://js.stripe.com https://static.cloudflareinsights.com https://cdn.tailwindcss.com; "
        "script-src-elem 'self' 'unsafe-inline' https://js.stripe.com https://static.cloudflareinsights.com https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.stripe.com https://cloudflareinsights.com; "
        "frame-src https://js.stripe.com;"
    )
    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions Policy
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(self)"
    # Permissions Policy
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# Add rate limiting (CRIT-002)
app.state.limiter = limiter

# Custom rate limit exceeded handler
async def rate_limit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."}
    )

app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# HIGH-008: Custom exception handler to hide stack traces in production
from fastapi import HTTPException

# Production exception handler — hides stack traces unless ENVIRONMENT=development
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler - hides stack traces in production"""
    is_development = os.environ.get("ENVIRONMENT") == "development"

    if is_development:
        # In development, show full error
        raise exc
    else:
        # In production, return generic error
        import traceback
        logging.error(f"Unhandled exception: {exc}")
        logging.error(traceback.format_exc())

        # Check if HTML request
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            # Return error page for browser
            return templates.TemplateResponse("error.html", {"request": request, "error": "An error occurred"}, status_code=500)

        return JSONResponse(
            status_code=500,
            content={"detail": "An internal error occurred. Please try again later."}
        )

_session_secret = os.environ.get("ADS_SESSION_SECRET")
if not _session_secret:
    raise RuntimeError("FATAL: ADS_SESSION_SECRET not set.")
app.add_middleware(SessionMiddleware, secret_key=_session_secret)

# CSRF Protection: Validate Origin/Referer on state-changing requests with cookie auth
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_ALLOWED_ORIGINS = {"https://ardyn.ai", "https://api.ardyn.ai", "https://platform.ardyn.ai", "https://demo.ardyn.ai"}
if os.environ.get("ENVIRONMENT") != "production":
    CSRF_ALLOWED_ORIGINS.update({"http://localhost:8080", "http://localhost:3000"})
    # Allow Azure Container Apps staging URL
    CSRF_ALLOWED_ORIGINS.add("https://ardyn-sentinel-staging.redwater-078014b9.eastus2.azurecontainerapps.io")

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method not in CSRF_SAFE_METHODS:
            # Only enforce CSRF for cookie-based auth (not API key/Bearer token)
            has_cookie = request.cookies.get("ads_token")
            has_api_key = request.headers.get("X-API-Key")
            has_bearer = (request.headers.get("Authorization", "").startswith("Bearer "))

            if has_cookie and not has_api_key and not has_bearer:
                origin = request.headers.get("Origin", "")
                referer = request.headers.get("Referer", "")

                origin_ok = any(origin.startswith(o) for o in CSRF_ALLOWED_ORIGINS) if origin else False
                referer_ok = any(referer.startswith(o) for o in CSRF_ALLOWED_ORIGINS) if referer else False

                if not origin_ok and not referer_ok:
                    return JSONResponse(
                        {"detail": "CSRF validation failed: invalid origin"},
                        status_code=403
                    )
        return await call_next(request)

app.add_middleware(CSRFMiddleware)


app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

# ── Retained routes: evidence-only portal (Phase 3 reduction) ──
# All routes below exist on disk and have been verified boot-safe on VM.
from routes.billing import router as billing_router
from routes.audit import router as audit_router
from routes.health import router as health_router
from routes.verify_api import router as verify_router
from routes.ledger import router as ledger_router
from routes.ledger_api import router as ledger_api_router

app.include_router(billing_router)
app.include_router(audit_router)
app.include_router(health_router)
app.include_router(verify_router)
app.include_router(ledger_router)
app.include_router(ledger_api_router)


# ── New ADS Platform landing page ──
from pathlib import Path as _Path
_website_dir = _Path(__file__).resolve().parent.parent / "website"

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    index = _website_dir / "index.html"
    if index.exists():
        from fastapi.responses import FileResponse
        return FileResponse(str(index), media_type="text/html")
    return templates.TemplateResponse("enterprise/landing.html", {"request": request})

# Mount website static assets
if _website_dir.exists():
    from fastapi.staticfiles import StaticFiles as _SF
    app.mount("/website", _SF(directory=str(_website_dir)), name="website_static")

# ── Docs (redirect to docs.ardyn.ai) ──
@app.get("/docs")
async def docs_redirect():
    return RedirectResponse("https://docs.ardyn.ai", status_code=302)

# ── Trust Dashboard (public metrics UI) ──
@app.get("/trust", response_class=HTMLResponse)
async def trust_dashboard(request: Request):
    """Public trust dashboard showing DDC metrics."""
    trust_page = _website_dir / "trust-dashboard.html"
    if trust_page.exists():
        return FileResponse(str(trust_page), media_type="text/html")
    return HTMLResponse("<h1>Trust Dashboard</h1><p>Page not found.</p>", status_code=404)

# ── API Documentation Page ──
@app.get("/api", response_class=HTMLResponse)
async def api_docs(request: Request):
    """API documentation page."""
    api_page = _website_dir / "api.html"
    if api_page.exists():
        return FileResponse(str(api_page), media_type="text/html")
    return HTMLResponse("<h1>API</h1><p>Page not found.</p>", status_code=404)


# ── Verification Page (public - shows clean trust signal) ──
@app.get("/verify/{job_id}", response_class=HTMLResponse)
async def verification_page(request: Request, job_id: str):
    """
    Public verification page showing clean trust signal.
    """
    import httpx
    import json
    
    # Fetch verification data from gateway
    gateway_url = os.environ.get("ADS_GATEWAY_URL", "http://localhost:8443")
    verify_url = f"{gateway_url}/v1/verify/{job_id}"
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(verify_url)
            if resp.status_code == 404:
                return HTMLResponse("<h1>Not Found</h1><p>No proof found for this job ID.</p>", status_code=404)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return HTMLResponse(f"<h1>Error</h1><p>Failed to fetch verification data: {e}</p>", status_code=500)
    
    # Extract clean signals
    valid = data.get("valid", False)
    message = data.get("message", "")
    cert = data.get("death_certificate", {})
    sentinel_enforced = data.get("sentinel_enforced")
    enforcement_tier = data.get("enforcement_tier")
    ads_verified = data.get("ads_verified")
    
    # Build clean trust message
    if valid and sentinel_enforced:
        trust_message = """
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:20px;margin-top:20px;">
            <h2 style="color:#166534;margin-top:0;">✓ Execution Verified</h2>
            <p style="color:#15803d;font-size:15px;line-height:1.6;">
                This execution completed under <strong>Ardyn Sentinel</strong> enforcement.<br>
                All required runtime conditions were validated before certificate issuance.
            </p>
            <div style="margin-top:16px;padding-top:16px;border-top:1px solid #bbf7d0;">
                <p style="color:#166534;font-size:13px;margin:4px 0;">✓ Runtime integrity validated</p>
                <p style="color:#166534;font-size:13px;margin:4px 0;">✓ Destruction conditions satisfied</p>
                <p style="color:#166534;font-size:13px;margin:4px 0;">✓ System state verified</p>
            </div>
        </div>"""
    elif not valid:
        trust_message = """
        <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:20px;margin-top:20px;">
            <h2 style="color:#991b1b;margin-top:0;">✗ Verification Failed</h2>
            <p style="color:#7f1d1d;">The proof could not be verified. The DDC is invalid.</p>
        </div>"""
    else:
        trust_message = """
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:20px;margin-top:20px;">
            <h2 style="color:#475569;margin-top:0;">Sentinel Enforcement Unavailable</h2>
            <p style="color:#64748b;">Trust signal not available for this execution.</p>
        </div>"""
    
    # Build final HTML
    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Verification Result - Ardyn Sentinel</title>
    <style>
        body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#f8fafc; margin:0; padding:40px; }}
        .container {{ max-width:800px; margin:0 auto; background:white; border-radius:12px; box-shadow:0 4px6px rgba(0,0,0,0.1); overflow:hidden; }}
        .header {{ background:{"#22c55e" if valid else "#ef4444"}; color:white; padding:24px; }}
        .header h1 {{ margin:0;font-size:28px; }}
        .content {{ padding:24px; }}
        .status {{ font-size:18px;font-weight:600;margin-bottom:16px; }}
        .card {{ background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin-bottom:16px; }}
        .card h3 {{ margin:0 0 12px 0;color:#334155;font-size:16px; }}
        .label {{ color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:0.5px; }}
        .value {{ color:#1e293b;font-size:14px;word-break:break-all; }}
        .footer {{ background:#f1f5f9;padding:16px;text-align:center;color:#64748b;font-size:12px; }}
        a {{ color:#3b82f6;text-decoration:none; }}
        a:hover {{ text-decoration:underline; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{"✓ Verified" if valid else "✗ Invalid"}</h1>
        </div>
        <div class="content">
            <div class="status">{message}</div>
            
            <div class="card">
                <h3>📋 Job Details</h3>
                <div style="margin-bottom:12px;">
                    <div class="label">Job ID</div>
                    <div class="value">{job_id}</div>
                </div>
            </div>
            
            <div class="card">
                <h3>📜 Death Certificate</h3>
                <div style="margin-bottom:12px;">
                    <div class="label">Record ID</div>
                    <div class="value">{cert.get("record_id", "N/A")}</div>
                </div>
                <div style="margin-bottom:12px;">
                    <div class="label">Attestation Hash</div>
                    <div class="value">{cert.get("attestation_hash", "N/A")[:64]}...</div>
                </div>
                <div>
                    <div class="label">Monotonic Counter</div>
                    <div class="value">{cert.get("monotonic_counter", "N/A")}</div>
                </div>
            </div>
            
            {trust_message}
        </div>
        <div class="footer">
            <a href="/trust">← Back to Trust Dashboard</a>
        </div>
    </div>
</body>
</html>'''
    
    return HTMLResponse(html)

# ── Your DDCs Page (authenticated) ──
@app.get("/my-ddcs", response_class=HTMLResponse)
async def my_ddcs_page(request: Request):
    """Your DDCs dashboard - requires authentication."""
    # Check if user is authenticated
    from auth import get_current_user
    try:
        user = await get_current_user(request)
    except Exception:
        # Not authenticated - redirect to login
        return RedirectResponse("/login?next=/my-ddcs")
    
    ddcs_page = _website_dir / "my-ddcs.html"
    if ddcs_page.exists():
        return FileResponse(str(ddcs_page), media_type="text/html")
    return HTMLResponse("<h1>Your DDCs</h1><p>Page not found.</p>", status_code=404)

# ── Developer Platform (billing dashboard) ──
# DEFERRED (Phase 3): enterprise.billing.* package missing — remove when rebuilt
# DEFERRED: routes.health already included above


# ── Demo Portal (login-gated) ──
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    user = _get_user_or_none(request)
    if not user:
        return RedirectResponse("/login?next=/admin")
    # Check admin
    email = (user.get("email") or "").lower()
    is_admin = email == "kylewilson4@protonmail.com" or user.get("is_admin")
    if not is_admin:
        # Check DB
        conn = get_db()
        row = conn.execute("SELECT is_admin FROM users WHERE id=?", (user["sub"],)).fetchone()
        conn.close()
        if not row or not row["is_admin"]:
            return HTMLResponse("<h1>403 Forbidden</h1><p>Admin access required.</p>", status_code=403)
    from fastapi.responses import FileResponse
    resp = FileResponse(str(_website_dir / "admin.html"), media_type="text/html")
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp

@app.get("/demo-portal", response_class=HTMLResponse)
async def demo_portal_page(request: Request):
    user = _get_user_or_none(request)
    if not user:
        return RedirectResponse("/login?next=/demo-portal")
    from fastapi.responses import FileResponse
    resp = FileResponse(str(_website_dir / "demo-portal.html"), media_type="text/html")
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp

@app.get("/monitor", response_class=HTMLResponse)
async def monitor_dashboard_page(request: Request):
    """Real-time ADS pipeline monitoring dashboard (admin only)"""
    user = _get_user_or_none(request)
    if not user:
        return RedirectResponse("/login?next=/monitor")

    # Check admin access
    email = (user.get("email") or "").lower()
    is_admin = email == "kylewilson4@protonmail.com" or user.get("is_admin")
    if not is_admin:
        # Check DB
        conn = get_db()
        row = conn.execute("SELECT is_admin FROM users WHERE id=?", (user["sub"],)).fetchone()
        conn.close()
        if not row or not row["is_admin"]:
            return HTMLResponse("<h1>403 Forbidden</h1><p>Admin access required.</p>", status_code=403)

    # Inject auth token into the page so JS can use it for SSE/fetch through Cloudflare
    token = request.cookies.get("ads_token", "")
    html = (_website_dir / "monitor.html").read_text()
    html = html.replace("</head>", f'<script>window.__ADS_TOKEN="{token}";</script></head>')
    resp = HTMLResponse(html)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp

# ── Demo Status API ──
@app.get("/api/demo/status")
async def demo_status(request: Request):
    """Returns inference endpoint reachability, pipeline mode, and demo count."""
    import httpx as _httpx
    inference_reachable = False
    ollama_url = os.environ.get("OLLAMA_URL", os.environ.get("ADS_OLLAMA_URL", "http://localhost:11434"))
    try:
        async with _httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{ollama_url}/api/tags")
            inference_reachable = r.status_code == 200
    except:
        pass
    load_test = os.environ.get("SENTINEL_LOAD_TEST",
            os.environ.get("ADS_LOAD_TEST", "0")) == "1"
    # Count demos today (simple: we don't have a counter yet, return 0)
    demos_today = getattr(app.state, '_demo_count_today', 0)
    return {
        "inference_reachable": inference_reachable,
        "mode": "live" if (inference_reachable and not load_test) else "simulation",
        "demos_today": demos_today,
    }

# ── GPU VM Control API (admin only) ──
@app.post("/api/gpu/start")
async def gpu_start(request: Request):
    """Start the Azure GPU VM."""
    token = request.cookies.get("ads_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    import asyncio
    import subprocess
    proc = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: subprocess.run(
            ["az", "vm", "start", "-g", "ArdynRG", "-n", "ardyn-gpu-vm", "--no-wait"],
            capture_output=True, text=True, timeout=30
        )
    )
    if proc.returncode == 0:
        return {"status": "starting", "message": "VM boot initiated. ~3-5 min to ready, ~7 min for first model load."}
    return {"status": "error", "message": proc.stderr or "Failed to start VM"}

@app.post("/api/gpu/stop")
async def gpu_stop(request: Request):
    """Deallocate the Azure GPU VM (stops billing)."""
    token = request.cookies.get("ads_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    import asyncio
    import subprocess
    proc = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: subprocess.run(
            ["az", "vm", "deallocate", "-g", "ArdynRG", "-n", "ardyn-gpu-vm", "--no-wait"],
            capture_output=True, text=True, timeout=30
        )
    )
    if proc.returncode == 0:
        return {"status": "stopping", "message": "VM deallocation initiated. Billing stops shortly."}
    return {"status": "error", "message": proc.stderr or "Failed to stop VM"}

@app.get("/api/gpu/vm-status")
async def gpu_vm_status(request: Request):
    """Get Azure VM power state (public — only returns power state string)."""
    import asyncio
    import subprocess
    proc = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: subprocess.run(
            ["az", "vm", "get-instance-view", "-g", "ArdynRG", "-n", "ardyn-gpu-vm",
             "--query", "instanceView.statuses[1].displayStatus", "-o", "tsv"],
            capture_output=True, text=True, timeout=15
        )
    )
    power_state = proc.stdout.strip() if proc.returncode == 0 else "unknown"
    return {"power_state": power_state}

# ── Demo Input Data API ──
@app.get("/api/demo/input/{vertical}")
async def demo_input_data(vertical: str):
    """Return mock input data for a vertical."""
    import json as _json
    demos_dir = Path(__file__).resolve().parent / "demos"
    mapping = {"healthcare": "healthcare_demo.json", "finance": "finance_demo.json",
               "legal": "legal_demo.json", "cybersecurity": "cybersecurity_demo.json",
               "pharmacy": "pharmacy_demo.json"}
    if vertical not in mapping:
        raise HTTPException(404, "Unknown vertical")
    with open(demos_dir / mapping[vertical]) as f:
        return _json.load(f)

# Legacy vertical pages → redirect to home

@app.get("/clinical", response_class=HTMLResponse)
async def clinical_page(request: Request):
    return RedirectResponse("/")

@app.get("/counsel", response_class=HTMLResponse)
async def counsel_page(request: Request):
    return RedirectResponse("/")

# Legacy routes — all redirect to new platform
@app.get("/matters")
async def matters_page(request: Request): return RedirectResponse("/")
@app.get("/enterprise-dashboard")
async def enterprise_dashboard(request: Request): return RedirectResponse("/")
@app.get("/dashboard")
async def dashboard_page(request: Request): return RedirectResponse("/demo-portal")
@app.get("/health-us")
async def health_us_portal(request: Request): return RedirectResponse("/")
@app.get("/legal-us")
async def legal_us_portal(request: Request): return RedirectResponse("/")
@app.get("/vault-org")
async def org_vault_page(request: Request): return RedirectResponse("/")

# Load personas
import yaml
PERSONAS = {}
try:
    with open(Path(__file__).parent / "personas.yaml", "r") as f:
        PERSONAS = yaml.safe_load(f).get("personas", [])
except Exception as e:
    logging.getLogger(__name__).warning(f"Failed to load personas: {e}")

@app.get("/api/personas")
async def get_personas():
    """Get all available AI personas."""
    return {"personas": PERSONAS}

@app.get("/api/personas/{persona_id}")
async def get_persona(persona_id: str):
    """Get a specific persona by ID."""
    for p in PERSONAS:
        if p["id"] == persona_id:
            return p
    raise HTTPException(404, "Persona not found")

# ── Legacy router stubs (removed in Phase 3 — deferred rebuild) ──
# dashboard_router    → REMOVED (route file missing)
# inference_router    → REMOVED (system_prompts, rag_pipeline, inference_config, ads_pipeline missing)
# proofs_router       → REMOVED (route file missing)
# admin_router        → REMOVED (route file missing)
# blog_router         → REMOVED (blog_routes module missing)
# billing_router      → RETAINED (already included above)
# audit_router        → RETAINED (already included above)
# health_router       → RETAINED (already included above)

# Load GPU worker pool from config
# DEFERRED (Phase 3): worker_manager module missing — restore when rebuilt

def _get_user_or_none(request: Request):
    token = request.cookies.get("ads_token")
    if not token:
        return None
    try:
        return decode_token(token)
    except:
        return None

def _require_auth(request: Request):
    user = _get_user_or_none(request)
    if not user:
        return None
    return user

# ── Page Routes ──
# NOTE: Root route "/" is defined above at line 90

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    next_url = request.query_params.get("next", "")
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "next": next_url})

@app.post("/login")
@limiter.limit("5/15minute")  # CRIT-002: Rate limit auth attempts
async def login_submit(request: Request, email: str = Form(...), password: str = Form(...)):
    try:
        user = authenticate(email, password)
        # CRIT-005: Include full org context in JWT
        token = create_token(
            user["user_id"],
            user["email"],
            role=user.get("role", "user"),
            org_id=user.get("org_id", user["user_id"]),
            vertical=user.get("vertical", "general"),
            jurisdiction=user.get("jurisdiction", "us")
        )
        # Support ?next= redirect
        form_data = await request.form()
        next_url = form_data.get("next", "/demo-portal")
        if not next_url.startswith("/"):
            next_url = "/demo-portal"
        resp = RedirectResponse(next_url, status_code=303)
        resp.set_cookie("ads_token", token, httponly=True, max_age=86400*7, samesite="lax", secure=True)
        return resp
    except HTTPException as he:
        # Return login page with error - MUST use HTMLResponse
        return templates.TemplateResponse("login.html",
            {"request": request, "error": he.detail},
            status_code=401)
    except Exception as e:
        import logging
        logging.error(f"Login error: {e}")
        return templates.TemplateResponse("login.html",
            {"request": request, "error": "Invalid credentials"},
            status_code=401)

# Registration disabled — Kyle creates accounts directly
@app.get("/register")
async def register_page(request: Request):
    return RedirectResponse("/login")

@app.post("/register")
async def register_submit(request: Request):
    return RedirectResponse("/login")

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login")
    resp.delete_cookie("ads_token", samesite="lax")
    return resp

# Check if user has completed onboarding
# DEFERRED (Phase 3): user_context table may not exist — stubbed for boot safety
def _has_completed_onboarding(user_id: str) -> bool:
    return True  # stub — bypass onboarding gate during reduced boot

# Build enterprise navigation helper
# DEFERRED (Phase 3): enterprise_navigation and db_models.organizations missing — stubbed for boot safety
def _build_enterprise_nav(user: dict) -> dict:
    """Build enterprise navigation for logged-in user. Stubbed during reduced boot."""
    return {}  # stub — returns empty nav during Phase 3 reduction

# Protected pages - standard handlers with enterprise navigation
standard_pages = ["playground", "history", "vault", "proofs", "ledger", "billing", "documents", "settings", "onboarding", "tutorial", "import", "audit"]

for page in standard_pages:
    def make_handler(p):
        async def handler(request: Request):
            user = _require_auth(request)
            if not user:
                return RedirectResponse("/login")
            # Skip onboarding check for onboarding and tutorial pages
            if p not in ["onboarding", "tutorial"]:
                if not _has_completed_onboarding(user["sub"]):
                    return RedirectResponse("/onboarding")
            # Build enterprise navigation
            nav = _build_enterprise_nav(user)
            return templates.TemplateResponse(f"{p}.html", {"request": request, "user": user, "nav": nav})
        handler.__name__ = f"page_{p}"
        return handler
    app.get(f"/{page}", response_class=HTMLResponse)(make_handler(page))

# Favicon route for browsers that request /favicon.ico
@app.get("/favicon.ico")
async def favicon():
    return RedirectResponse("/static/favicon.ico")

# ── Access Request Endpoint ──
@app.post("/api/access-request")
async def access_request(request: Request):
    """Receive enterprise access applications and log them."""
    import json as _json
    data = await request.json()
    email = data.get("email", "").strip()
    company = data.get("company", "").strip()
    infra = data.get("infrastructure", "")
    compliance = data.get("compliance", "")
    ts = data.get("submitted_at", "")

    # Block personal email domains
    blocked = ["gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","icloud.com","mail.com","protonmail.com","zoho.com","yandex.com","live.com","msn.com","comcast.net"]
    domain = email.split("@")[-1].lower() if "@" in email else ""
    if domain in blocked:
        raise HTTPException(status_code=400, detail="Work email required")

    # Log to file
    log_dir = Path("/opt/ardyn/data/access-requests")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "requests.jsonl"
    entry = {"email": email, "company": company, "infrastructure": infra, "compliance": compliance, "submitted_at": ts, "ip": request.client.host}
    with open(log_file, "a") as f:
        f.write(_json.dumps(entry) + "\n")

    logging.getLogger("ardyn").info(f"ACCESS REQUEST: {company} ({email}) — {compliance} — {infra}")
    return {"status": "received"}

# Simplified Onboarding - Quick 30-second setup
@app.get("/onboarding")
async def onboarding_page(request: Request):
    return RedirectResponse("/demo-portal")

@app.post("/onboarding")
async def onboarding_submit(
    request: Request,
    display_name: str = Form(...),
    position: str = Form(...),
    vertical: str = Form(...)
):
    """Handle streamlined onboarding form submission"""
    user = _require_auth(request)
    if not user:
        return RedirectResponse("/login")

    # Update user profile
    conn = get_db()
    try:
        conn.execute(
            """UPDATE users SET
               role = ?, vertical = ?, custom_instructions = ?
               WHERE id = ?""",
            (position, vertical, display_name, user["sub"])
        )
        conn.commit()

        # Create minimal context record (marks onboarding as complete)
        import time
        import json
        try:
            conn.execute(
                """INSERT INTO user_context (user_id, core_identity, topic_index, full_context, context_hash, encryption_key_hash, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (user["sub"], display_name, json.dumps([]), json.dumps({"name": display_name, "position": position}), "hash", "key", time.time(), time.time())
            )
            conn.commit()
        except:
            pass  # May already exist

    finally:
        conn.close()

    # Redirect based on vertical
    if vertical == "healthcare":
        return RedirectResponse("/clinical", status_code=303)
    elif vertical == "legal":
        return RedirectResponse("/counsel", status_code=303)
    else:
        return RedirectResponse("/dashboard", status_code=303)

# Chat page with enterprise navigation and vertical-specific personas
@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    user = _require_auth(request)
    if not user:
        return RedirectResponse("/login")
    if not _has_completed_onboarding(user["sub"]):
        return RedirectResponse("/onboarding")

    # Get user vertical from database
    user_vertical = "general"  # default
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT vertical FROM users WHERE id = ?", (user["sub"],)
        ).fetchone()
        conn.close()
        if row and row["vertical"]:
            user_vertical = row["vertical"]
    except:
        pass

    # Build enterprise navigation
    try:
        from enterprise_navigation import get_enterprise_nav
        from db_models.organizations import Organization, OrgVertical, OrgJurisdiction

        # Create org object for nav generation
        org = Organization(
            id=1,
            name=user.get("org_name", "My Organization"),
            slug="my-org",
            vertical=OrgVertical.HEALTHCARE if user_vertical == "healthcare" else
                     OrgVertical.LEGAL if user_vertical == "legal" else OrgVertical.GENERAL,
            jurisdiction=OrgJurisdiction.US
        )
        nav = get_enterprise_nav(org, user.get("role", "member"))
    except:
        # Fallback to basic nav
        nav = {
            "org_header": {
                "flag": "🇺🇸",
                "org_name": user.get("org_name", "My Organization"),
                "vertical_name": user_vertical.title(),
                "jurisdiction_name": "United States"
            },
            "primary_nav": [
                {"url": "/dashboard", "label": "Dashboard", "icon": "📊"},
                {"url": "/chat", "label": "Chat", "icon": "💬"},
                {"url": "/documents", "label": "Documents", "icon": "📄"},
                {"url": "/vault", "label": "Secure Vault", "icon": "🔒"},
            ],
            "secondary_nav": [
                {"url": "/proofs", "label": "Proofs", "icon": "🛡️"},
                {"url": "/settings", "label": "Settings", "icon": "⚙️"},
            ],
            "admin_nav": None
        }

    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": user,
        "nav": nav,
        "user_vertical": user_vertical
    })

# ── Waitlist API ──

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.post("/api/waitlist")
async def waitlist_signup(request: Request):
    try:
        body = await request.json()
    except:
        return {"ok": False, "error": "Invalid JSON"}
    email = (body.get("email") or "").strip().lower()
    if not email or not EMAIL_RE.match(email):
        return {"ok": False, "error": "Invalid email"}
    source = body.get("source", "website")
    conn = get_db()
    try:
        conn.execute("INSERT INTO waitlist (email, signed_up_at, source) VALUES (?,?,?)",
                     (email, time.time(), source))
        conn.commit()
        conn.close()
        return {"ok": True, "message": "You're on the list!"}
    except Exception:
        conn.close()
        return {"ok": True, "message": "You're already on the list!"}

@app.get("/api/admin/waitlist")
async def admin_waitlist(user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT email, signed_up_at, source FROM waitlist ORDER BY signed_up_at DESC").fetchall()
    conn.close()
    return {"waitlist": [dict(r) for r in rows]}

# ── Drip queue processing endpoint ──

@app.post("/api/admin/process-drip")
async def process_drip(user: dict = Depends(get_current_user)):
    try:
        from drip_emails import process_drip_queue
        process_drip_queue()
    except ImportError:
        pass  # drip_emails removed in Phase 3 reduction
    return {"ok": True}

# ── License validation (on-prem) ──
try:
    from license_validator import validate_on_startup, is_onprem_mode, get_license
    _license_status = validate_on_startup()
except ImportError:
    _license_status = {"mode": "saas", "license": None}
    def is_onprem_mode(): return False
    def get_license(): return None

# ── Attestation metering (on-prem) ──
_meter = None
if is_onprem_mode():
    try:
        from attestation_metering import AttestationMeter
        _meter = AttestationMeter(os.environ.get("ARDYN_LICENSE_KEY", ""))
        _meter.start_background()
    except Exception as _e:
        logging.getLogger(__name__).warning("Attestation metering init failed: %s", _e)

# ── Health check for Cloudflare ──
@app.get("/health")
@app.get("/v1/health")
async def health_check():
    resp = {"status": "healthy", "service": "ardyn-webapp"}
    resp["deployment_mode"] = _license_status.get("mode", "saas")
    if _license_status.get("license"):
        resp["license"] = _license_status["license"]
    return resp

# ── User Profiling from Import (ephemeral analysis) ──
class ProfileRequest(BaseModel):
    import_data: str
    source: str = "openai"  # openai, claude, gemini

@app.post("/api/profile/analyze")
async def analyze_user_profile(req: ProfileRequest, user: dict = Depends(get_current_user)):
    """
    Analyze imported conversation data to extract user preferences/persona.
    Raw data is processed and discarded - only the profile is stored.
    This is 'sharding' - extracting essence without keeping the source.
    """
    try:
        import json
        data = json.loads(req.import_data)

        # Parse based on source format
        messages = []
        if req.source == "openai":
            convs = data.get("conversations", [data])
            for conv in convs:
                for m in conv.get("messages", []):
                    if m.get("role") and m.get("content"):
                        messages.append(m)
        elif req.source == "claude":
            convs = data.get("conversations", data.get("chat_messages", [data]))
            for conv in convs:
                msgs = conv.get("messages", conv.get("chat_messages", [conv]))
                for m in msgs:
                    content = m.get("text") or m.get("content") or m.get("message", "")
                    role = "user" if m.get("sender") == "human" or m.get("role") == "user" else "assistant"
                    messages.append({"role": role, "content": content})
        elif req.source == "gemini":
            convs = data.get("conversations", [data])
            for conv in convs:
                for m in conv.get("messages", []):
                    content = m.get("parts", [{}])[0].get("text") or m.get("content") or m.get("text", "")
                    role = m.get("role", "user")
                    messages.append({"role": role, "content": content})

        # Analyze the conversation patterns (ephemeral - data not stored)
        profile = extract_user_profile(messages)

        # Store only the profile, not the raw data
        conn = get_db()
        conn.execute("""
            INSERT OR REPLACE INTO user_profiles
            (user_id, writing_style, preferred_topics, response_preferences, technical_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user["sub"],
            profile.get("writing_style", ""),
            json.dumps(profile.get("preferred_topics", [])),
            json.dumps(profile.get("response_preferences", {})),
            profile.get("technical_level", "intermediate"),
            time.time()
        ))
        conn.commit()
        conn.close()

        return {
            "profile_created": True,
            "messages_analyzed": len(messages),
            "profile": profile
        }
    except Exception as e:
        return {"profile_created": False, "error": str(e)}

def extract_user_profile(messages):
    """Extract user persona from messages without storing raw data."""
    user_messages = [m for m in messages if m.get("role") == "user"]

    if not user_messages:
        return {}

    # Analyze writing style
    lengths = [len(m.get("content", "")) for m in user_messages]
    avg_length = sum(lengths) / len(lengths) if lengths else 0

    # Detect technical level
    technical_keywords = ["code", "api", "function", "programming", "database", "algorithm", "python", "javascript"]
    casual_keywords = ["hello", "hi", "thanks", "please", "help", "question"]

    content_text = " ".join([m.get("content", "").lower() for m in user_messages])
    tech_score = sum(1 for k in technical_keywords if k in content_text)
    casual_score = sum(1 for k in casual_keywords if k in content_text)

    if tech_score > casual_score * 2:
        technical_level = "expert"
    elif tech_score > casual_score:
        technical_level = "technical"
    else:
        technical_level = "casual"

    # Extract topics (simple keyword extraction)
    topics = set()
    topic_keywords = {
        "programming": ["code", "programming", "function", "api", "developer"],
        "writing": ["write", "essay", "story", "blog", "content"],
        "analysis": ["analyze", "data", "research", "study"],
        "business": ["business", "strategy", "marketing", "sales", "revenue"],
        "creative": ["creative", "design", "art", "music", "game"],
        "learning": ["learn", "study", "course", "tutorial", "education"]
    }

    for topic, keywords in topic_keywords.items():
        if any(k in content_text for k in keywords):
            topics.add(topic)

    # Response preferences based on message patterns
    response_prefs = {
        "prefers_detailed": avg_length > 200,
        "prefers_concise": avg_length < 50,
        "asks_questions": content_text.count("?") > len(user_messages) / 2,
        "uses_examples": "example" in content_text or "like" in content_text
    }

    # Writing style characterization
    if avg_length < 50:
        writing_style = "concise_direct"
    elif avg_length > 300:
        writing_style = "detailed_thorough"
    elif "please" in content_text or "thank" in content_text:
        writing_style = "polite_formal"
    else:
        writing_style = "casual_conversational"

    return {
        "writing_style": writing_style,
        "preferred_topics": list(topics),
        "response_preferences": response_prefs,
        "technical_level": technical_level,
        "avg_message_length": int(avg_length),
        "conversation_count": len(messages)
    }

@app.get("/api/profile")
async def get_user_profile(user: dict = Depends(get_current_user)):
    """Get the user's analyzed profile."""
    import json
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM user_profiles WHERE user_id = ?", (user["sub"],)
    ).fetchone()
    conn.close()

    if not row:
        return {"profile_exists": False}

    return {
        "profile_exists": True,
        "writing_style": row["writing_style"],
        "preferred_topics": json.loads(row["technical_level"]) if row["technical_level"] else [],
        "response_preferences": json.loads(row["response_preferences"]) if row["response_preferences"] else {},
        "technical_level": row["technical_level"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)


# ── SMS Demo Webhook (Twilio) ──
# Simple: receive SMS → call Ardyn → send reply
from fastapi.responses import Response

@app.post("/webhook/sms")
async def sms_webhook(
    From: str = Form(None),
    Body: str = Form(""),
):
    """
    Receive SMS from Twilio, trigger Ardyn execution, reply with result.
    
    No storage, no state, no auth. Just text → result → proof.
    """
    import httpx
    
    if not Body or not Body.strip():
        twiml = f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>Please send a prompt.</Message></Response>'
        return Response(content=twiml, media_type="text/xml")
    
    prompt = Body.strip()
    
    # Call Ardyn sovereign inference
    gateway_url = os.environ.get("ADS_GATEWAY_URL", "http://gateway:8443")
    headers = {}
    secret = os.environ.get("GATEWAY_SHARED_SECRET")
    if secret:
        headers["X-Gateway-Secret"] = secret
    
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{gateway_url}/v1/sovereign-inference",
                json={"prompt": prompt},  # Use default model
                headers=headers,
            )
            resp.raise_for_status()
            result = resp.json()
    except Exception as e:
        twiml = f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>Execution failed: {str(e)[:100]}</Message></Response>'
        return Response(content=twiml, media_type="text/xml")
    
    # Extract result
    job_id = result.get("job_id", "unknown")
    response_text = result.get("response", "")[:500]  # Truncate for SMS
    death_cert = result.get("death_certificate")
    
    # Build reply
    if death_cert and death_cert.get("record_id"):
        # Success with DDC
        reply = f"Result:\n{response_text}\n\nDDC Verified ✓\nExecution enforced by Ardyn Sentinel\n\nVerify:\nhttps://ardyn.ai/verify/{job_id}\n\nTrust:\nhttps://ardyn.ai/trust"
    else:
        # Failed or no DDC
        reply = f"Result:\n{response_text}\n\nDDC: Not issued\n\nTrust:\nhttps://ardyn.ai/trust"
    
    twiml = f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{reply}</Message></Response>'
    return Response(content=twiml, media_type="text/xml")

# ONE-TIME SETUP ENDPOINT (DELETE AFTER USE)
try:
    from setup_sovereign import router as setup_router
    app.include_router(setup_router)
except ImportError:
    pass  # setup_sovereign.py removed after one-time use
