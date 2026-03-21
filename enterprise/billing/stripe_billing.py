"""
Ardyn Billing — Stripe Metered Billing
========================================
Handles Stripe customer creation, metered usage reporting, and webhooks.

Stripe metered billing for SCU usage tracking.
Enterprise tier: Prepaid certificate balance, no Stripe — manual invoicing.

Env vars:
    STRIPE_SECRET_KEY       — Stripe API secret key
    STRIPE_WEBHOOK_SECRET   — Stripe webhook signing secret
    STRIPE_PRICE_ID         — Price ID for metered WORM certificates
"""

import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("ardyn.billing.stripe")

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")  # Metered price for SCU billing

# Lazy Stripe import — won't crash if stripe isn't installed
_stripe = None

def _get_stripe():
    global _stripe
    if _stripe is not None:
        return _stripe
    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY
        _stripe = stripe
        return stripe
    except ImportError:
        logger.error("stripe package not installed — run: pip install stripe")
        return None


# ---------------------------------------------------------------------------
# Customer & Subscription Management
# ---------------------------------------------------------------------------

def create_customer(org_id: str, email: str, name: str) -> Optional[Dict[str, str]]:
    """
    Create a Stripe customer with a metered subscription.
    Returns {"customer_id": ..., "subscription_id": ...} or None on failure.

    Call this when an individual-tier org signs up.
    """
    stripe = _get_stripe()
    if not stripe or not STRIPE_SECRET_KEY:
        logger.warning("Stripe not configured — skipping customer creation")
        return None

    try:
        # Create customer
        customer = stripe.Customer.create(
            email=email,
            name=name,
            metadata={"ardyn_org_id": org_id},
        )

        # Create metered subscription (usage-based, billed monthly)
        subscription = stripe.Subscription.create(
            customer=customer.id,
            items=[{"price": STRIPE_PRICE_ID}],
            # Metered billing — charge based on reported usage
            payment_behavior="default_incomplete",
            metadata={"ardyn_org_id": org_id},
        )

        # Update org in DB
        from enterprise.billing.models import SessionLocal, Organization
        db = SessionLocal()
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            if org:
                org.stripe_customer_id = customer.id
                org.stripe_subscription_id = subscription.id
                db.commit()
        finally:
            db.close()

        logger.info(f"Stripe customer created: {customer.id} for org {org_id}")
        return {
            "customer_id": customer.id,
            "subscription_id": subscription.id,
        }

    except Exception as e:
        logger.error(f"Stripe customer creation failed: {e}")
        return None


def report_usage(org_id: str, worm_cert_hash: str) -> bool:
    """
    Report one WORM certificate to Stripe metered billing.

    Reports 1 SCU to Stripe metered billing.
    For enterprise tier: decrements prepaid balance.

    Idempotent: same worm_cert_hash is never billed twice (checked in UsageLog + Stripe idempotency key).
    Returns True if successfully reported.
    """
    from enterprise.billing.models import SessionLocal, Organization, UsageLog

    db = SessionLocal()
    try:
        # Check if already reported
        existing = (
            db.query(UsageLog)
            .filter(UsageLog.worm_certificate_hash == worm_cert_hash)
            .first()
        )
        if existing and existing.stripe_reported:
            return True  # Already done — idempotent

        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            logger.error(f"Org not found: {org_id}")
            return False

        if org.tier == "enterprise":
            return _report_enterprise(db, org, worm_cert_hash)
        else:
            return _report_individual(db, org, worm_cert_hash)

    finally:
        db.close()


def _report_individual(db, org, worm_cert_hash: str) -> bool:
    """Report usage to Stripe for individual tier."""
    stripe = _get_stripe()
    if not stripe or not org.stripe_subscription_id:
        logger.warning(f"Stripe not configured for org {org.id} — usage logged but not billed")
        return False

    try:
        # Get the subscription item ID (needed for usage reporting)
        subscription = stripe.Subscription.retrieve(org.stripe_subscription_id)
        si_id = subscription["items"]["data"][0]["id"]

        # Report 1 unit with idempotency key
        stripe.SubscriptionItem.create_usage_record(
            si_id,
            quantity=1,
            action="increment",
            idempotency_key=f"worm_{worm_cert_hash}",
        )

        # Mark as reported in DB
        from enterprise.billing.models import UsageLog
        usage = (
            db.query(UsageLog)
            .filter(UsageLog.worm_certificate_hash == worm_cert_hash)
            .first()
        )
        if usage:
            usage.stripe_reported = True
            db.commit()

        logger.info(f"Stripe usage reported for org {org.id}: {worm_cert_hash[:16]}...")
        return True

    except Exception as e:
        logger.error(f"Stripe usage reporting failed: {e}")
        return False


def _report_enterprise(db, org, worm_cert_hash: str) -> bool:
    """Decrement enterprise prepaid balance."""
    from enterprise.billing.models import UsageLog

    if org.enterprise_cert_balance is not None and org.enterprise_cert_balance > 0:
        org.enterprise_cert_balance -= 1
        db.commit()

        # Alert at 80% consumed
        if org.enterprise_cert_total and org.enterprise_cert_total > 0:
            used_pct = 1 - (org.enterprise_cert_balance / org.enterprise_cert_total)
            if used_pct >= 0.8:
                logger.warning(
                    f"⚠️ Enterprise org {org.name} at {used_pct:.0%} cert usage "
                    f"({org.enterprise_cert_balance} remaining of {org.enterprise_cert_total})"
                )

        # Mark as reported
        usage = (
            db.query(UsageLog)
            .filter(UsageLog.worm_certificate_hash == worm_cert_hash)
            .first()
        )
        if usage:
            usage.stripe_reported = True
            db.commit()

        return True
    else:
        logger.error(f"Enterprise org {org.name} has exhausted cert balance!")
        return False


def get_current_usage(org_id: str) -> Dict[str, Any]:
    """
    Get current billing period usage and estimated cost.
    """
    from enterprise.billing.models import get_usage_stats
    stats = get_usage_stats(org_id, days=30)

    if stats["tier"] == "individual":
        stats["scu_rate"] = 0.15
        stats["estimated_bill"] = round(stats["total_certificates"] * 0.15, 2)
    elif stats["tier"] == "enterprise":
        stats["billing_model"] = "prepaid"

    return stats


def create_billing_portal_session(org_id: str) -> Optional[str]:
    """
    Create a Stripe Billing Portal session for payment method management.
    Returns the portal URL or None.
    """
    stripe = _get_stripe()
    if not stripe:
        return None

    from enterprise.billing.models import SessionLocal, Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org or not org.stripe_customer_id:
            return None

        session = stripe.billing_portal.Session.create(
            customer=org.stripe_customer_id,
            return_url="https://platform.ardyn.ai/platform",
        )
        return session.url
    except Exception as e:
        logger.error(f"Billing portal session failed: {e}")
        return None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Webhook Handler
# ---------------------------------------------------------------------------

def handle_webhook(payload: bytes, sig_header: str) -> Dict[str, Any]:
    """
    Handle Stripe webhook events.

    Supported events:
      - invoice.paid: Mark subscription as healthy
      - invoice.payment_failed: Suspend org billing
      - customer.subscription.deleted: Cancel org

    Returns {"status": "ok"} or {"error": ...}
    """
    stripe = _get_stripe()
    if not stripe or not STRIPE_WEBHOOK_SECRET:
        return {"error": "Stripe webhooks not configured"}

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        return {"error": f"Webhook verification failed: {e}"}

    event_type = event["type"]
    data = event["data"]["object"]

    from enterprise.billing.models import SessionLocal, Organization
    db = SessionLocal()

    try:
        if event_type == "invoice.paid":
            customer_id = data.get("customer")
            org = db.query(Organization).filter(Organization.stripe_customer_id == customer_id).first()
            if org and org.billing_status == "suspended":
                org.billing_status = "active"
                db.commit()
                logger.info(f"Org {org.name} reactivated after payment")

        elif event_type == "invoice.payment_failed":
            customer_id = data.get("customer")
            org = db.query(Organization).filter(Organization.stripe_customer_id == customer_id).first()
            if org:
                org.billing_status = "suspended"
                db.commit()
                logger.warning(f"⚠️ Org {org.name} suspended — payment failed")

        elif event_type == "customer.subscription.deleted":
            customer_id = data.get("customer")
            org = db.query(Organization).filter(Organization.stripe_customer_id == customer_id).first()
            if org:
                org.billing_status = "cancelled"
                db.commit()
                logger.warning(f"Org {org.name} cancelled")

        return {"status": "ok", "event_type": event_type}

    finally:
        db.close()
