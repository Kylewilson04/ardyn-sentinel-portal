"""
Ledger API — Azure Immutable Blob Storage endpoints for death certificates.
"""
from __future__ import annotations
import logging
from fastapi import APIRouter, Depends, HTTPException
from auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ledger", tags=["ledger-api"])


def _get_ledger():
    from immutable_ledger import get_immutable_ledger
    return get_immutable_ledger()


@router.get("/certificate/{job_id}")
async def get_certificate(job_id: str, user: dict = Depends(get_current_user)):
    """Fetch a death certificate from Azure immutable storage."""
    ledger = _get_ledger()
    cert = ledger.get_certificate(job_id)
    if cert is None:
        # Fall back to local archive
        try:
            from certificate_archive import get_certificate as local_get
            cert = local_get(job_id)
            if cert:
                return {"source": "local", "certificate": cert}
        except Exception:
            pass
        raise HTTPException(404, f"Certificate {job_id} not found")
    return {"source": "azure", "certificate": cert}


@router.get("/verify/{job_id}")
async def verify_certificate(job_id: str, user: dict = Depends(get_current_user)):
    """Verify a specific certificate's hash chain integrity."""
    ledger = _get_ledger()
    result = ledger.verify_certificate(job_id)
    return result


@router.get("/chain/status")
async def chain_status(user: dict = Depends(get_current_user)):
    """Get chain statistics: total certs, last anchor, validity."""
    ledger = _get_ledger()
    status = ledger.get_chain_status()
    # Include local archive stats too
    try:
        from certificate_archive import get_stats
        status["local_archive"] = get_stats()
    except Exception:
        pass
    return status


@router.post("/chain/anchor")
async def trigger_anchor(user: dict = Depends(get_current_user)):
    """Trigger a manual chain anchor (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    ledger = _get_ledger()
    anchor_hash = ledger.anchor_chain()
    if not anchor_hash:
        raise HTTPException(500, "Chain anchor failed — Azure may be unavailable")
    return {"anchor_hash": anchor_hash, "status": "anchored"}
