"""Billing routes — org account display only. No inference data."""
from fastapi import APIRouter, Depends, Request, HTTPException
from auth import get_current_user

router = APIRouter()

# Lazy import to avoid hard dependency on billing service
_billing_service = None
def _get_billing_service():
    global _billing_service
    if _billing_service is None:
        from billing import billing_service as _bs
        _billing_service = _bs
    return _billing_service


@router.get("/api/billing/usage")
async def billing_usage(user=Depends(get_current_user)):
    """Return org billing usage — stubbed for evidence portal."""
    bs = _get_billing_service()
    usage = bs.get_usage(user["sub"])
    usage["total_inferences"] = 0
    usage["total_tokens"] = 0
    usage["inference_cost"] = 0.0
    return usage


@router.get("/api/billing/history")
async def billing_history(user=Depends(get_current_user)):
    """Return billing event history — stubbed."""
    bs = _get_billing_service()
    return {"events": bs.get_history(user["sub"])}


@router.get("/api/billing")
async def billing_summary(user=Depends(get_current_user)):
    """Return billing summary for org."""
    return {
        "total_inferences": 0,
        "total_tokens": 0,
        "total_cost": 0.0,
        "daily": [],
        "usage_tokens": [],
    }
