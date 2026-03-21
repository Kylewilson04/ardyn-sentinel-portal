"""Backward-compat shim — real module moved to shared.tier_resolver

This shim ensures existing imports continue to work during
the Sentinel consolidation. Remove after all import paths
are updated to use the new module location.
"""
from shared.tier_resolver import *  # noqa: F401,F403
