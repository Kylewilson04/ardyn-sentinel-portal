"""Billing service stub for portal — SCU pricing stubs only.

Real SCU pricing is in src/shared/tier_resolver.py (runtime dependency).
Portal billing display is stubbed here to avoid hard coupling.
"""
import os
import time
import logging
from database import get_db

log = logging.getLogger(__name__)

# Stub SCU pricing — matches src/shared/tier_resolver.py defaults
SCU_PRICING = {
    "developer":  {"scu_rate": 0.00, "ddc_rate": 0.00, "monthly_quota": 50},
    "production": {"scu_rate": 0.03, "ddc_rate": 0.00, "monthly_quota": None},
    "enterprise": {"scu_rate": 0.05, "ddc_rate": 0.02, "monthly_quota": None},
}

STRIPE_AVAILABLE = False
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")

class BillingService:
    """Stub billing service for portal evidence display."""
    FREE_TIER_EVENTS = 100

    def get_usage(self, user_id: str) -> dict:
        """Return stub usage — real usage comes from runtime metering."""
        conn = get_db()
        row = conn.execute(
            "SELECT COUNT(*) as events FROM billing WHERE user_id=?",
            (user_id,)
        ).fetchone()
        conn.close()
        return {
            "user_id": user_id,
            "tier": "developer",
            "events_this_period": row["events"] if row else 0,
            "monthly_quota": 50,
            "scu_rate": 0.00,
        }

    def get_history(self, user_id: str) -> list:
        return []

    def create_customer(self, email: str, user_id: str) -> str:
        return ""

billing_service = BillingService()
