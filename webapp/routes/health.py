"""
Ardyn Health Check & Status Endpoints
=======================================
Deep health checks for load balancers, monitoring, and the public status page.

GET /health       — Quick health check (200/503)
GET /health/deep  — Deep check with component status
GET /status       — Public status page
"""

import logging
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse

logger = logging.getLogger("ardyn.health")

router = APIRouter(tags=["health"])

_START_TIME = time.time()


def _check_postgres_billing():
    """Check billing PostgreSQL connectivity."""
    try:
        from enterprise.billing.models import SessionLocal
        from sqlalchemy import text
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            return {"status": "healthy", "type": "postgresql"}
        finally:
            db.close()
    except Exception as e:
        return {"status": "unhealthy", "error": str(e), "type": "postgresql"}


def _check_main_db():
    """Check main webapp database."""
    try:
        from database import get_db
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        db_type = "postgresql" if os.environ.get("ADS_DATABASE_URL", "").startswith("postgresql") else "sqlite"
        return {"status": "healthy", "type": db_type}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


def _check_gpu():
    """Check NVIDIA GPU availability (NVML or CUDA driver)."""
    import ctypes
    import ctypes.util

    # Try NVML first (desktop/server GPUs)
    for lib in ["libnvidia-ml.so.1", "/usr/lib/aarch64-linux-gnu/libnvidia-ml.so.1"]:
        try:
            nvml = ctypes.CDLL(lib)
            nvml.nvmlInit_v2()
            count = ctypes.c_uint()
            nvml.nvmlDeviceGetCount_v2(ctypes.byref(count))
            nvml.nvmlShutdown()
            return {"status": "healthy", "gpu_count": count.value, "driver": "nvml"}
        except OSError:
            continue
        except Exception:
            break

    # Fallback: CUDA driver (Jetson / embedded)
    for lib in [ctypes.util.find_library("cuda"), "libcuda.so.1",
                "/usr/lib/aarch64-linux-gnu/libcuda.so.1",
                "/usr/local/cuda/lib64/libcuda.so.1"]:
        if not lib:
            continue
        try:
            cuda = ctypes.CDLL(lib)
            if cuda.cuInit(0) == 0:
                count = ctypes.c_int()
                cuda.cuDeviceGet(ctypes.byref(count), 0)
                return {"status": "healthy", "driver": "cuda", "note": "Jetson/embedded GPU"}
        except OSError:
            continue
        except Exception:
            break

    # Last resort: check if /dev/nvhost exists (Jetson)
    if os.path.exists("/dev/nvhost-ctrl-gpu"):
        return {"status": "healthy", "driver": "tegra", "note": "Jetson GPU detected via /dev/nvhost"}

    return {"status": "unavailable", "note": "No NVIDIA GPU detected"}


def _check_hsm():
    """Check Azure Key Vault HSM connectivity."""
    if os.environ.get("ARDYN_USE_KEY_VAULT") != "1":
        return {"status": "disabled", "note": "HSM not enabled (ARDYN_USE_KEY_VAULT!=1)"}
    try:
        from certificate_authority import ArdynCA
        ca = ArdynCA()
        backend = ca.get_signing_backend()
        return {"status": "healthy", "backend": backend}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


def _check_redis():
    """Check Redis availability."""
    try:
        import redis
        r = redis.Redis.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            socket_timeout=1,
        )
        r.ping()
        return {"status": "healthy"}
    except Exception:
        return {"status": "unavailable", "note": "Redis not running (caching disabled, rate limiting disabled)"}


@router.get("/health")
async def health_quick():
    """Quick health check for load balancers. Returns 200 or 503."""
    try:
        db_ok = _check_main_db()["status"] == "healthy"
        if db_ok:
            return JSONResponse({"status": "healthy", "uptime_seconds": int(time.time() - _START_TIME)})
        return JSONResponse({"status": "degraded"}, status_code=503)
    except Exception:
        return JSONResponse({"status": "unhealthy"}, status_code=503)


@router.get("/health/deep")
async def health_deep():
    """
    Deep health check — status only.
    No internal topology, component names, or version info exposed.
    """
    checks = {
        "main_database": _check_main_db(),
        "billing_database": _check_postgres_billing(),
        "gpu": _check_gpu(),
        "hsm": _check_hsm(),
        "redis": _check_redis(),
    }

    overall = "healthy"
    degraded_count = 0
    for name, check in checks.items():
        if check["status"] == "unhealthy":
            overall = "unhealthy"
            break
        if check["status"] in ("unavailable", "degraded", "disabled"):
            degraded_count += 1
            if overall == "healthy":
                overall = "degraded"

    return {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/status", response_class=HTMLResponse)
async def status_page():
    """Public status page at status.ardyn.ai."""
    return HTMLResponse("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ardyn Status</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
  * { font-family: 'JetBrains Mono', monospace; }
  body { background: #0a0a0f; color: #e0e0e0; }
  .healthy { color: #00ff88; }
  .degraded { color: #ff8800; }
  .unhealthy { color: #ff4444; }
  .unavailable { color: #666; }
  .disabled { color: #666; }
  .card { background: #111118; border: 1px solid #1a1a2e; border-radius: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 8px; }
  .dot-healthy { background: #00ff88; }
  .dot-degraded { background: #ff8800; }
  .dot-unhealthy { background: #ff4444; }
  .dot-unavailable, .dot-disabled { background: #444; }
</style>
</head>
<body class="min-h-screen p-8">
<div class="max-w-2xl mx-auto">
  <h1 class="text-2xl font-bold mb-2" style="color:#00cccc">ARDYN SYSTEM STATUS</h1>
  <p class="text-gray-500 text-sm mb-8">Real-time infrastructure health</p>

  <div id="overall" class="card p-6 mb-6 text-center">
    <p class="text-sm text-gray-500 mb-2">OVERALL STATUS</p>
    <p id="overall-text" class="text-3xl font-bold">Loading...</p>
    <p id="uptime" class="text-gray-600 text-xs mt-2"></p>
  </div>

  <div id="components" class="space-y-3"></div>

  <p class="text-gray-700 text-xs text-center mt-8">Auto-refreshes every 30 seconds</p>
</div>
<script>
const LABELS = {
  main_database: "Main Database",
  billing_database: "Billing Database",
  gpu: "GPU Compute",
  hsm: "HSM Root CA",
  redis: "Redis Cache",
};

async function refresh() {
  try {
    const res = await fetch('/health/deep');
    const data = await res.json();

    const el = document.getElementById('overall-text');
    el.textContent = data.status.toUpperCase();
    el.className = 'text-3xl font-bold ' + data.status;

    const days = Math.floor(data.uptime_seconds / 86400);
    const hrs = Math.floor((data.uptime_seconds % 86400) / 3600);
    document.getElementById('uptime').textContent = `Uptime: ${days}d ${hrs}h`;

    const container = document.getElementById('components');
    container.innerHTML = Object.entries(data.components).map(([key, comp]) => {
      const label = LABELS[key] || key;
      const extra = comp.type ? ` (${comp.type})` : comp.backend ? ` (${comp.backend})` : comp.note ? ` — ${comp.note}` : '';
      return `<div class="card p-4 flex items-center justify-between">
        <div class="flex items-center">
          <span class="dot dot-${comp.status}"></span>
          <span>${label}${extra}</span>
        </div>
        <span class="${comp.status} text-sm font-bold">${comp.status.toUpperCase()}</span>
      </div>`;
    }).join('');
  } catch(e) {
    document.getElementById('overall-text').textContent = 'UNREACHABLE';
    document.getElementById('overall-text').className = 'text-3xl font-bold unhealthy';
  }
}
refresh();
setInterval(refresh, 30000);
</script>
</body>
</html>""")
