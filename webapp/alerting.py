"""Alerting module — checks system health conditions and stores alert history."""
import os
import time
import shutil
import uuid
import logging
import httpx
from database import get_db, DB_PATH

log = logging.getLogger("ardyn.alerting")

ADS_INFERENCE_ENDPOINT = os.environ.get("ADS_OLLAMA_URL", os.environ.get("ADS_OLLAMA_URL", "http://localhost:11434"))


def _make_alert(level: str, check_name: str, message: str) -> dict:
    return {
        "level": level,
        "check_name": check_name,
        "message": message,
        "timestamp": time.time(),
    }


async def check_alerts() -> list[dict]:
    """Run all alert checks and return active alerts. Also persists to DB."""
    alerts = []

    # 1. inference endpoint check
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{ADS_INFERENCE_ENDPOINT}/api/tags")
            if resp.status_code != 200:
                alerts.append(_make_alert("critical", "inference_endpoint", f"Inference returned HTTP {resp.status_code}"))
    except (httpx.TimeoutException, httpx.ConnectError):
        alerts.append(_make_alert("info", "tee_vm_deallocated", "VM appears deallocated (Ollama unreachable — expected when not in use)"))
    except Exception as e:
        alerts.append(_make_alert("critical", "inference_endpoint", f"inference endpoint error: {e}"))

    # 2. Database check
    if not DB_PATH.exists():
        alerts.append(_make_alert("critical", "database_missing", f"Database file missing: {DB_PATH}"))
    else:
        try:
            conn = get_db()
            conn.execute("SELECT 1 FROM users LIMIT 1")
            conn.close()
        except Exception as e:
            alerts.append(_make_alert("critical", "database_corrupt", f"Database error: {e}"))

    # 3. Disk space
    disk = shutil.disk_usage("/")
    pct = disk.used / disk.total * 100
    if pct > 85:
        alerts.append(_make_alert("warning", "disk_space", f"Disk usage at {pct:.1f}%"))

    # 4. Error rate last hour
    try:
        conn = get_db()
        hour_ago = time.time() - 3600
        total = conn.execute("SELECT COUNT(*) as c FROM jobs WHERE created_at >= ?", (hour_ago,)).fetchone()["c"]
        failed = conn.execute("SELECT COUNT(*) as c FROM jobs WHERE status='failed' AND created_at >= ?", (hour_ago,)).fetchone()["c"]
        if total > 0 and (failed / total) > 0.10:
            alerts.append(_make_alert("warning", "error_rate", f"Error rate {failed}/{total} ({failed/total*100:.0f}%) in last hour"))
        conn.close()
    except Exception:
        pass

    # 5. No inference in 24h
    try:
        conn = get_db()
        day_ago = time.time() - 86400
        recent = conn.execute("SELECT COUNT(*) as c FROM jobs WHERE status='completed' AND completed_at >= ?", (day_ago,)).fetchone()["c"]
        if recent == 0:
            alerts.append(_make_alert("warning", "no_inference", "No successful inference in last 24 hours"))
        conn.close()
    except Exception:
        pass

    # Persist alerts to DB
    _store_alerts(alerts)

    return alerts


def _store_alerts(alerts: list[dict]):
    """Store alerts in the alerts table."""
    try:
        conn = get_db()
        for a in alerts:
            conn.execute(
                "INSERT INTO alerts (id, level, check_name, message, created_at) VALUES (?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, a["level"], a["check_name"], a["message"], a["timestamp"]),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Failed to store alerts: {e}")
