"""Backward-compat shim — real module moved to ads.certificate_authority

This shim ensures existing imports continue to work during
the Sentinel consolidation. Remove after all import paths
are updated to use the new module location.
"""
from ads.certificate_authority import *  # noqa: F401,F403
