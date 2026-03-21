"""Backward-compat shim — real module moved to shared.volume_tracker

This shim ensures existing imports continue to work during
the Sentinel consolidation. Remove after all import paths
are updated to use the new module location.
"""
from shared.volume_tracker import *  # noqa: F401,F403

# Legacy function - migrate to tier_resolver
def get_customer_tier(customer_id: str) -> tuple[str, float]:
    """Get customer tier and volume. Returns (tier, scu)."""
    from shared.tier_resolver import resolve_tier
    tier, rate = resolve_tier("general", 0)
    return tier, 0
