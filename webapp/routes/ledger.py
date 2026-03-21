"""Ledger routes - private global attestation ledger."""
import time
from fastapi import APIRouter, Depends, HTTPException, Query
from auth import get_current_user

# Import the ledger from ADS core
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from attestation_ledger import AttestationLedger

router = APIRouter(prefix="/api")
ledger = AttestationLedger()

@router.get("/ledger")
async def get_ledger(
    user=Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get global attestation ledger entries."""
    try:
        all_certs = ledger.get_all()
        total = len(all_certs)

        # Paginate
        certs = all_certs[offset:offset + limit]

        results = []
        for cert in certs:
            results.append({
                "record_id": cert.record_id,
                "job_id": cert.job_id,
                "timestamp": cert.timestamp,
                "zk_proof_hash": cert.zk_proof_hash,
                "monotonic_counter": cert.monotonic_counter,
                "attestation_hash": cert.attestation_hash,
                "status": cert.status,
                "prev_hash": cert.prev_hash,
                "record_hash": cert.record_hash
            })

        return {
            "entries": results,
            "total": total,
            "offset": offset,
            "limit": limit,
            "chain_valid": ledger.verify_chain(),
            "chain_length": ledger.chain_length
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to get ledger: {e}")

@router.get("/ledger/search")
async def search_ledger(
    hash: str = Query(..., min_length=8),
    user=Depends(get_current_user)
):
    """Search ledger by hash (proof_hash, attestation_hash, record_hash, or job_id)."""
    try:
        all_certs = ledger.get_all()
        hash_lower = hash.lower()

        matches = []
        for cert in all_certs:
            # Search across all hash fields
            if (
                hash_lower in cert.zk_proof_hash.lower() or
                hash_lower in cert.attestation_hash.lower() or
                hash_lower in cert.record_hash.lower() or
                hash_lower in cert.prev_hash.lower() or
                hash_lower in cert.job_id.lower() or
                hash_lower in cert.record_id.lower()
            ):
                matches.append({
                    "record_id": cert.record_id,
                    "job_id": cert.job_id,
                    "timestamp": cert.timestamp,
                    "zk_proof_hash": cert.zk_proof_hash,
                    "monotonic_counter": cert.monotonic_counter,
                    "attestation_hash": cert.attestation_hash,
                    "status": cert.status,
                    "prev_hash": cert.prev_hash,
                    "record_hash": cert.record_hash
                })

        return {
            "query": hash,
            "matches": matches,
            "count": len(matches),
            "chain_valid": ledger.verify_chain()
        }
    except Exception as e:
        raise HTTPException(500, f"Search failed: {e}")

@router.get("/ledger/stats")
async def get_ledger_stats(user=Depends(get_current_user)):
    """Get ledger statistics."""
    try:
        all_certs = ledger.get_all()

        if not all_certs:
            return {
                "total_entries": 0,
                "chain_valid": True,
                "first_entry": None,
                "latest_entry": None,
                "destroyed_count": 0
            }

        destroyed = sum(1 for c in all_certs if c.status == "DESTROYED")

        return {
            "total_entries": len(all_certs),
            "chain_valid": ledger.verify_chain(),
            "first_entry": all_certs[0].timestamp if all_certs else None,
            "latest_entry": all_certs[-1].timestamp if all_certs else None,
            "destroyed_count": destroyed,
            "inference_platform": all_certs[-1].inference_platform if all_certs else None
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to get stats: {e}")

@router.post("/ledger/verify")
async def verify_ledger(user=Depends(get_current_user)):
    """Verify the entire attestation chain."""
    try:
        is_valid = ledger.verify_chain()
        return {
            "valid": is_valid,
            "chain_length": ledger.chain_length,
            "timestamp": time.time(),
            "message": "Chain integrity verified" if is_valid else "CHAIN INTEGRITY COMPROMISED"
        }
    except Exception as e:
        raise HTTPException(500, f"Verification failed: {e}")
