"""
Ardyn Billing — Database Models & CRUD
========================================
SQLAlchemy models for organizations, API keys, and usage logs.
Works with SQLite (dev) and PostgreSQL (prod).

Usage:
    from enterprise.billing.models import create_all, create_org, create_api_key
    create_all()  # Initialize tables
"""

import json
import logging
import os
import hashlib
import secrets
import datetime

logger = logging.getLogger(__name__)
from typing import Optional, Tuple, Dict, Any, List

from sqlalchemy import (
    create_engine, Column, String, BigInteger, Boolean,
    DateTime, ForeignKey, Index, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# Engine & Session
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "BILLING_DATABASE_URL",
    "sqlite:////tmp/billing.db"  # Safe default; set BILLING_DATABASE_URL in prod
)

# SQLite needs special args for thread safety
_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args = {
        "check_same_thread": False,
        "timeout": 30.0  # 30 second timeout for lock acquisition
    }

_engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = _connect_args
    _engine_kwargs["connect_args"]["isolation_level"] = None  # Enable autocommit for WAL
    if ":memory:" in DATABASE_URL:
        _engine_kwargs["poolclass"] = StaticPool

engine = create_engine(DATABASE_URL, **_engine_kwargs)

# Enable WAL mode for SQLite (better concurrency)
if DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")  # 30 seconds
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_session():
    """Yield a DB session — use in FastAPI Depends or context manager."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Organization(Base):
    """A billing entity — either an individual dev or an enterprise."""
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_hex(16))
    name = Column(String(255), nullable=False)
    tier = Column(String(20), nullable=False, default="individual")  # individual | enterprise
    email = Column(String(255), nullable=True, unique=True)

    # Auth
    password_hash = Column(String(255), nullable=True)  # bcrypt hash
    email_verified = Column(Boolean, default=False)
    verification_token = Column(String(64), nullable=True)

    # Stripe (individual tier)
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)

    # Enterprise prepaid balance
    enterprise_cert_balance = Column(BigInteger, nullable=True, default=None)
    enterprise_cert_total = Column(BigInteger, nullable=True, default=None)  # original purchase

    # SSO config (JSON string — OIDC or SAML settings)
    sso_config = Column(String(4096), nullable=True)

    # Data residency — which region this org's data must stay in
    data_region = Column(String(20), nullable=True, default="us-east")  # us-east | eu-west | ap-south | any

    billing_status = Column(String(20), nullable=False, default="active")  # active | suspended | cancelled

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    api_keys = relationship("ApiKey", back_populates="organization")
    usage_logs = relationship("UsageLog", back_populates="organization")


class ApiKey(Base):
    """
    API key for authenticating requests.
    Raw key shown ONCE at creation — only SHA-256 hash stored.
    Key format: sk_live_<32 hex chars> (40 chars total with prefix)
    """
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_hex(16))
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)

    key_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 hex
    key_prefix = Column(String(16), nullable=False)  # e.g. sk_live_a1b2c3d4

    name = Column(String(255), nullable=True)  # user label
    status = Column(String(20), nullable=False, default="active")  # active | revoked

    signing_secret = Column(String(64), nullable=True)  # HMAC signing secret for webhook verification
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="api_keys")
    usage_logs = relationship("UsageLog", back_populates="api_key")

    __table_args__ = (
        Index("ix_api_keys_hash_status", "key_hash", "status"),
    )


class UsageLog(Base):
    """
    One row per WORM certificate issued.
    worm_certificate_hash is unique to prevent double-billing.
    """
    __tablename__ = "usage_logs"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_hex(16))
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    api_key_id = Column(String(36), ForeignKey("api_keys.id"), nullable=True)

    worm_certificate_hash = Column(String(128), nullable=False, unique=True)  # prevents double-billing
    event_type = Column(String(50), nullable=False, default="shred.certified")

    # Stripe reporting
    stripe_reported = Column(Boolean, default=False)
    stripe_idempotency_key = Column(String(128), nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="usage_logs")
    api_key = relationship("ApiKey", back_populates="usage_logs")

    __table_args__ = (
        Index("ix_usage_org_created", "organization_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# Table Creation
# ---------------------------------------------------------------------------

class ComplianceEvent(Base):
    """Immutable compliance event log for SIEM integration."""
    __tablename__ = "compliance_events"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_hex(16))
    timestamp = Column(String(64), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)
    organization_id = Column(String(36), nullable=True, index=True)
    severity = Column(String(20), nullable=False, default="info")
    details = Column(String(8192), nullable=True)

    __table_args__ = (
        Index("ix_compliance_ts_org", "timestamp", "organization_id"),
    )


class SentinelEvent(Base):
    """
    Sentinel Live Telemetry — Real-time agent health and probe results.

    Streams events from Sentinel agents to the platform for monitoring:
    - Probe results (memory, platform, behavior integrity)
    - Agent health (heartbeats, errors, warnings)
    - Remediation actions (tier escalation, halts, refusals)
    """
    __tablename__ = "sentinel_events"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_hex(16))
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    agent_id = Column(String(255), nullable=False)
    node_id = Column(String(255), nullable=True)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # DEBUG, INFO, WARNING, CRITICAL, FATAL
    message = Column(String(2048), nullable=False)
    evidence = Column(String(8192), nullable=True)  # JSON blob with probe details
    timestamp = Column(String(64), nullable=False)  # ISO 8601 timestamp from agent
    platform_tier = Column(String(50), nullable=True)  # T1, T2, T3, etc.
    behavior_hash = Column(String(128), nullable=True)  # Hash of behavior signature
    cert_id = Column(String(128), nullable=True)  # Link to WORM certificate if applicable
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization")

    __table_args__ = (
        Index("ix_sentinel_org_ts", "organization_id", "timestamp"),
        Index("ix_sentinel_severity", "severity"),
        Index("ix_sentinel_agent", "agent_id"),
        Index("ix_sentinel_cert", "cert_id"),
        Index("ix_sentinel_event_type", "event_type"),
    )


class AuditLog(Base):
    """
    Audit log for security-sensitive administrative actions.

    Tracks:
    - API key creation/revocation
    - Organization changes
    - Webhook registration/updates
    - Login attempts
    - Permission changes

    Immutable: Records are never updated or deleted (compliance requirement).
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_hex(16))
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)

    # Action details
    action = Column(String(64), nullable=False)  # e.g., "api_key.created", "api_key.revoked"
    actor = Column(String(255), nullable=True)  # Email or API key that performed action
    target = Column(String(255), nullable=True)  # Resource affected (e.g., API key ID)

    # Context
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent = Column(String(512), nullable=True)
    context = Column(String(2048), nullable=True)  # JSON blob with additional context (renamed from metadata to avoid SQLAlchemy reserved word)

    # Result
    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(String(512), nullable=True)

    # Timestamp
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)

    organization = relationship("Organization")

    __table_args__ = (
        Index("ix_audit_org_created", "organization_id", "created_at"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_actor", "actor"),
    )


def create_all():
    """Create all tables. Safe to call multiple times."""
    Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
# CRUD Helpers
# ---------------------------------------------------------------------------

def create_org(
    name: str,
    tier: str = "individual",
    email: Optional[str] = None,
    enterprise_cert_balance: Optional[int] = None,
) -> Organization:
    """Create an organization. Returns the new org."""
    db = SessionLocal()
    try:
        org = Organization(
            name=name,
            tier=tier,
            email=email,
            enterprise_cert_balance=enterprise_cert_balance,
            enterprise_cert_total=enterprise_cert_balance,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        return org
    finally:
        db.close()


def create_api_key(
    organization_id: str,
    name: Optional[str] = None,
    actor: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Tuple[str, ApiKey]:
    """
    Generate a new API key for an organization.
    Returns (raw_key, ApiKey object).
    ⚠️ The raw key is returned ONCE — it cannot be recovered.

    Args:
        organization_id: Organization ID
        name: Human-readable key name
        actor: Email/user creating the key (for audit log)
        ip_address: Client IP (for audit log)
    """
    # Generate: sk_live_ + 32 random hex chars
    raw_key = f"sk_live_{secrets.token_hex(16)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:16]  # sk_live_a1b2c3d4

    db = SessionLocal()
    try:
        api_key = ApiKey(
            organization_id=organization_id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=name or "Default",
            signing_secret=secrets.token_hex(32),
        )
        db.add(api_key)
        db.commit()
        db.refresh(api_key)

        # Audit log: API key created
        log_audit_event(
            organization_id=organization_id,
            action="api_key.created",
            actor=actor,
            target=api_key.id,
            ip_address=ip_address,
            context=json.dumps({"key_name": name or "Default", "key_prefix": key_prefix})
        )

        return raw_key, api_key
    finally:
        db.close()


def validate_api_key(raw_key: str) -> Optional[Dict[str, Any]]:
    """
    Validate a raw API key. Returns dict with org info or None if invalid.
    This is the DB-only path — middleware adds Redis caching on top.
    """
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    db = SessionLocal()
    try:
        api_key = (
            db.query(ApiKey)
            .filter(ApiKey.key_hash == key_hash, ApiKey.status == "active")
            .first()
        )
        if not api_key:
            return None

        org = db.query(Organization).filter(Organization.id == api_key.organization_id).first()
        if not org or org.billing_status != "active":
            return None

        # Update last_used timestamp
        api_key.last_used_at = datetime.datetime.utcnow()
        db.commit()

        return {
            "organization_id": org.id,
            "org_name": org.name,
            "tier": org.tier,
            "api_key_id": api_key.id,
            "billing_status": org.billing_status,
        }
    finally:
        db.close()


def revoke_api_key(
    key_id: str,
    actor: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> bool:
    """
    Revoke an API key by ID. Returns True if found and revoked.

    Args:
        key_id: API key ID to revoke
        actor: Email/user revoking the key (for audit log)
        ip_address: Client IP (for audit log)
    """
    db = SessionLocal()
    try:
        api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
        if not api_key:
            return False

        api_key.status = "revoked"
        api_key.revoked_at = datetime.datetime.utcnow()
        db.commit()

        # Audit log: API key revoked
        log_audit_event(
            organization_id=api_key.organization_id,
            action="api_key.revoked",
            actor=actor,
            target=key_id,
            ip_address=ip_address,
            context=json.dumps({"key_name": api_key.name, "key_prefix": api_key.key_prefix})
        )

        return True
    finally:
        db.close()


def log_usage(
    organization_id: str,
    api_key_id: str,
    worm_certificate_hash: str,
    event_type: str = "shred.certified",
) -> Optional[UsageLog]:
    """
    Log a usage event. Returns None if duplicate (already billed).
    The unique constraint on worm_certificate_hash prevents double-billing.
    """
    db = SessionLocal()
    try:
        # Check for duplicate
        existing = (
            db.query(UsageLog)
            .filter(UsageLog.worm_certificate_hash == worm_certificate_hash)
            .first()
        )
        if existing:
            return None  # Already logged — not an error, just idempotent

        log = UsageLog(
            organization_id=organization_id,
            api_key_id=api_key_id,
            worm_certificate_hash=worm_certificate_hash,
            event_type=event_type,
            stripe_idempotency_key=f"worm_{worm_certificate_hash}",
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log
    finally:
        db.close()


def get_usage_stats(
    organization_id: str,
    days: int = 30,
) -> Dict[str, Any]:
    """Get usage statistics for an organization over the last N days."""
    db = SessionLocal()
    try:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)

        total = (
            db.query(func.count(UsageLog.id))
            .filter(
                UsageLog.organization_id == organization_id,
                UsageLog.created_at >= cutoff,
            )
            .scalar()
        ) or 0

        # Daily breakdown
        daily = (
            db.query(
                func.date(UsageLog.created_at).label("day"),
                func.count(UsageLog.id).label("count"),
            )
            .filter(
                UsageLog.organization_id == organization_id,
                UsageLog.created_at >= cutoff,
            )
            .group_by(func.date(UsageLog.created_at))
            .order_by(func.date(UsageLog.created_at))
            .all()
        )

        org = db.query(Organization).filter(Organization.id == organization_id).first()

        result = {
            "total_certificates": total,
            "period_days": days,
            "daily": [{"date": str(d.day), "count": d.count} for d in daily],
            "tier": org.tier if org else "unknown",
        }

        if org and org.tier == "individual":
            result["estimated_bill"] = round(total * 0.05, 2)  # Enterprise SCU rate
        elif org and org.tier == "enterprise":
            result["cert_balance_remaining"] = org.enterprise_cert_balance
            result["cert_balance_total"] = org.enterprise_cert_total

        return result
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Sentinel Event CRUD
# ---------------------------------------------------------------------------

def create_sentinel_event(
    organization_id: str,
    agent_id: str,
    event_type: str,
    severity: str,
    message: str,
    timestamp: str,
    *,
    node_id: Optional[str] = None,
    evidence: Optional[str] = None,
    platform_tier: Optional[str] = None,
    behavior_hash: Optional[str] = None,
    cert_id: Optional[str] = None,
) -> SentinelEvent:
    """
    Create a Sentinel telemetry event.

    Args:
        organization_id: Tenant/org UUID
        agent_id: Unique agent identifier
        event_type: Event type (e.g., "probe.memory", "agent.start")
        severity: DEBUG, INFO, WARNING, CRITICAL, or FATAL
        message: Human-readable event message
        timestamp: ISO 8601 timestamp from agent
        node_id: Optional node identifier
        evidence: Optional JSON evidence blob
        platform_tier: Optional platform tier (T1, T2, T3)
        behavior_hash: Optional behavior signature hash
        cert_id: Optional WORM certificate ID for cross-reference

    Returns:
        SentinelEvent instance
    """
    db = SessionLocal()
    try:
        event = SentinelEvent(
            organization_id=organization_id,
            agent_id=agent_id,
            node_id=node_id,
            event_type=event_type,
            severity=severity,
            message=message,
            evidence=evidence,
            timestamp=timestamp,
            platform_tier=platform_tier,
            behavior_hash=behavior_hash,
            cert_id=cert_id,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    finally:
        db.close()


def list_sentinel_events(
    organization_id: str,
    *,
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Tuple[List[SentinelEvent], int]:
    """
    List Sentinel events with optional filters.

    Returns (events, total_count) tuple.
    """
    db = SessionLocal()
    try:
        query = db.query(SentinelEvent).filter(
            SentinelEvent.organization_id == organization_id
        )

        if severity:
            query = query.filter(SentinelEvent.severity == severity)
        if agent_id:
            query = query.filter(SentinelEvent.agent_id == agent_id)
        if event_type:
            query = query.filter(SentinelEvent.event_type == event_type)

        total = query.count()

        events = (
            query.order_by(SentinelEvent.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return events, total
    finally:
        db.close()


def get_sentinel_agents(
    organization_id: str,
) -> List[Dict[str, Any]]:
    """
    Get summary of all Sentinel agents for an organization.

    Returns list of dicts with agent_id, last_seen, event_count.
    """
    db = SessionLocal()
    try:
        agents = (
            db.query(
                SentinelEvent.agent_id,
                func.max(SentinelEvent.timestamp).label("last_seen"),
                func.count(SentinelEvent.id).label("event_count"),
            )
            .filter(SentinelEvent.organization_id == organization_id)
            .group_by(SentinelEvent.agent_id)
            .all()
        )

        return [
            {
                "agent_id": a.agent_id,
                "last_seen": a.last_seen,
                "event_count": a.event_count,
            }
            for a in agents
        ]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# CSV Export with Security Sanitization
# ---------------------------------------------------------------------------

def sanitize_for_csv(value: Optional[str]) -> str:
    """
    Sanitize value for CSV export to prevent formula injection.

    Formula injection occurs when CSV programs (Excel, LibreOffice) execute
    formulas that start with: = + - @ \t \r

    We escape these by prefixing with a single quote.

    Args:
        value: String value to sanitize

    Returns:
        Sanitized string safe for CSV export
    """
    if value is None:
        return ""

    # Formula injection prefixes
    dangerous_prefixes = ['=', '+', '-', '@', '\t', '\r']

    # Escape if starts with dangerous character
    if any(value.startswith(prefix) for prefix in dangerous_prefixes):
        return "'" + value  # Prefix with single quote to neutralize

    # Escape double quotes for CSV
    return value.replace('"', '""')


def verify_sentinel_event_ownership(
    event_id: str,
    organization_id: str,
) -> SentinelEvent:
    """
    Verify that a Sentinel event belongs to the specified organization.

    This prevents IDOR (Insecure Direct Object Reference) attacks where
    one organization could access another's events by guessing event IDs.

    Args:
        event_id: Event ID to verify
        organization_id: Organization ID that should own the event

    Returns:
        SentinelEvent object if owned by organization

    Raises:
        HTTPException: 404 if event not found or access denied
    """
    from fastapi import HTTPException

    db = SessionLocal()
    try:
        event = db.query(SentinelEvent).filter(
            SentinelEvent.id == event_id,
            SentinelEvent.organization_id == organization_id  # ✓ ORG CHECK
        ).first()

        if not event:
            raise HTTPException(
                status_code=404,
                detail="Event not found or access denied"
            )

        return event

    finally:
        db.close()


def export_sentinel_events_csv(
    organization_id: str,
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 1000,
) -> str:
    """
    Export Sentinel events as CSV with proper sanitization.

    Security:
    - Sanitizes all fields to prevent formula injection
    - Limits export to 1000 events by default
    - Organization-scoped (prevents cross-tenant data leakage)

    Args:
        organization_id: Organization ID (required)
        severity: Filter by severity (optional)
        agent_id: Filter by agent ID (optional)
        event_type: Filter by event type (optional)
        limit: Max events to export (default 1000)

    Returns:
        CSV string with headers and sanitized data
    """
    import csv
    import io

    # Fetch events
    events, _ = list_sentinel_events(
        organization_id=organization_id,
        severity=severity,
        agent_id=agent_id,
        event_type=event_type,
        limit=limit,
        offset=0,
    )

    # Build CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Timestamp",
        "Agent ID",
        "Node ID",
        "Event Type",
        "Severity",
        "Message",
        "Evidence",
        "Platform Tier",
        "Behavior Hash",
        "Cert ID",
        "Created At"
    ])

    # Data rows (sanitized)
    for event in events:
        writer.writerow([
            event.timestamp.isoformat() if event.timestamp else "",
            sanitize_for_csv(event.agent_id),
            sanitize_for_csv(event.node_id),
            sanitize_for_csv(event.event_type),
            event.severity,  # Enum, no sanitization needed
            sanitize_for_csv(event.message),
            sanitize_for_csv(event.evidence),
            sanitize_for_csv(event.platform_tier),
            sanitize_for_csv(event.behavior_hash),
            sanitize_for_csv(event.cert_id),
            event.created_at.isoformat() if event.created_at else "",
        ])

    return output.getvalue()


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

def log_audit_event(
    organization_id: str,
    action: str,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    context: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None,
):
    """
    Log a security-sensitive administrative action.

    Args:
        organization_id: Organization ID
        action: Action performed (e.g., "api_key.created", "api_key.revoked")
        actor: Email or API key that performed action
        target: Resource affected (e.g., API key ID)
        ip_address: Client IP address
        user_agent: Client user agent
        metadata: JSON blob with additional context
        success: Whether action succeeded
        error_message: Error message if action failed

    Examples:
        # API key creation
        log_audit_event(
            organization_id="org-123",
            action="api_key.created",
            actor="user@example.com",
            target="key-abc",
            ip_address="203.0.113.1",
            metadata='{"key_name": "Production API Key"}'
        )

        # API key revocation
        log_audit_event(
            organization_id="org-123",
            action="api_key.revoked",
            actor="user@example.com",
            target="key-abc",
            ip_address="203.0.113.1"
        )

        # Failed login attempt
        log_audit_event(
            organization_id="org-123",
            action="auth.login_failed",
            actor="user@example.com",
            ip_address="203.0.113.1",
            success=False,
            error_message="Invalid password"
        )
    """
    db = SessionLocal()
    try:
        audit_log = AuditLog(
            organization_id=organization_id,
            action=action,
            actor=actor,
            target=target,
            ip_address=ip_address,
            user_agent=user_agent,
            context=context,
            success=success,
            error_message=error_message,
        )
        db.add(audit_log)
        db.commit()

        logger.info(
            "Audit: %s by %s on %s (org=%s, success=%s)",
            action, actor or "unknown", target or "N/A", organization_id, success
        )

    except Exception as e:
        logger.error("Failed to log audit event: %s", e)
        # Don't raise - audit logging should never break the main flow

    finally:
        db.close()


def list_audit_logs(
    organization_id: str,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Tuple[List[AuditLog], int]:
    """
    List audit logs for an organization.

    Args:
        organization_id: Organization ID
        action: Filter by action type (optional)
        actor: Filter by actor (optional)
        limit: Max results (default 100)
        offset: Pagination offset (default 0)

    Returns:
        Tuple of (audit_logs, total_count)
    """
    db = SessionLocal()
    try:
        query = db.query(AuditLog).filter(
            AuditLog.organization_id == organization_id
        )

        if action:
            query = query.filter(AuditLog.action == action)
        if actor:
            query = query.filter(AuditLog.actor == actor)

        total = query.count()

        audit_logs = (
            query.order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return audit_logs, total

    finally:
        db.close()
