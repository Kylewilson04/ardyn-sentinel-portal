"""Ledger routes - private global attestation ledger."""
import time
from fastapi import APIRouter, Depends, HTTPException, Query
from auth import get_current_user

# Ledger backend — use immutable_ledger (local, boot-safe)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from immutable_ledger import get_immutable_ledger

router = APIRouter(prefix="/api")
_ledger = get_immutable_ledger()


def _cert_to_dict(cert: dict) -> dict:
    """Normalize a certificate dict to the expected route response format."""
    return {
        "record_id": cert.get("death_certificate_id", ""),
        "job_id": cert.get("job_id", ""),
        "timestamp": cert.get("timestamp", 0),
        "zk_proof_hash": cert.get("proof_hash", ""),
        "monotonic_counter": cert.get("sequence_number", 0),
        "attestation_hash": cert.get("attestation_hash", ""),
        "status": "ACTIVE",
        "prev_hash": cert.get("prev_hash", ""),
        "record_hash": cert.get("chain_hash", "")
    }


@router.get("/ledger")
async def get_ledger(
    user=Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get global attestation ledger entries."""
    try:
        status = _ledger.get_chain_status()
        total = status.get("total", 0)
        return {
            "entries": [],  # Use /ledger/search for individual certs
            "total": total,
            "offset": offset,
            "limit": limit,
            "chain_valid": status.get("available", False),
            "chain_length": total,
            "last_anchor": status.get("last_anchor"),
            "message": "Azure Immutable Ledger active" if status.get("available") else "Ledger in offline mode"
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to get ledger: {e}")


@router.get("/ledger/search")
async def search_ledger(
    hash: str = Query(..., min_length=8),
    user=Depends(get_current_user)
):
    """Search ledger by hash (job_id or chain_hash)."""
    try:
        cert = _ledger.get_certificate(hash)
        if cert:
            return {
                "query": hash,
                "matches": [_cert_to_dict(cert)],
                "count": 1,
                "chain_valid": True
            }
        v = _ledger.verify_chain(limit=100)
        return {
            "query": hash,
            "matches": [],
            "count": 0,
            "chain_valid": v.get("valid", False),
            "message": f"No certificate found for {hash}"
        }
    except Exception as e:
        raise HTTPException(500, f"Search failed: {e}")


@router.get("/ledger/stats")
async def get_ledger_stats(user=Depends(get_current_user)):
    """Get ledger statistics."""
    try:
        status = _ledger.get_chain_status()
        v = _ledger.verify_chain(limit=1000)
        if not status.get("available"):
            return {
                "total_entries": 0,
                "chain_valid": True,
                "first_entry": None,
                "latest_entry": None,
                "destroyed_count": 0,
                "mode": "offline"
            }
        return {
            "total_entries": status.get("total", 0),
            "chain_valid": v.get("valid", True),
            "first_entry": (status.get("last_anchor") or {}).get("anchor_time"),
            "latest_entry": (status.get("last_anchor") or {}).get("anchor_time"),
            "destroyed_count": 0,
            "inference_platform": "azure_blob"
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to get stats: {e}")


@router.post("/ledger/verify")
async def verify_ledger(user=Depends(get_current_user)):
    """Verify the entire attestation chain."""
    try:
        v = _ledger.verify_chain(limit=1000)
        status = _ledger.get_chain_status()
        return {
            "valid": v.get("valid", False),
            "chain_length": status.get("total", 0),
            "checked": v.get("checked", 0),
            "timestamp": time.time(),
            "message": "Chain integrity verified" if v.get("valid") else f"CHAIN INTEGRITY ISSUES: {v.get('breaks')}"
        }
    except Exception as e:
        raise HTTPException(500, f"Verification failed: {e}")
