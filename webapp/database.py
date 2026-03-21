"""
Ardyn Main Database — PostgreSQL (prod) / SQLite (dev fallback)
================================================================
All webapp tables: users, jobs, billing, PHI, matters, audit logs, etc.
"""
import os
import uuid
import hashlib
import logging
from pathlib import Path

logger = logging.getLogger("ardyn.database")

# ---------------------------------------------------------------------------
# Connection config
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("ADS_DATABASE_URL", "")
DB_PATH = Path(os.environ.get("ADS_DB_PATH", "/opt/ardyn/data/ads.db"))

USE_POSTGRES = DATABASE_URL.startswith("postgresql")

if not USE_POSTGRES:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_db():
    """Return a database connection (PostgreSQL or SQLite)."""
    if USE_POSTGRES:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        # Return a cursor factory that gives dict-like rows
        return PostgresConnection(conn)
    else:
        import sqlite3
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn


class PostgresConnection:
    """
    Wrapper around psycopg2 connection that mimics sqlite3 interface.
    Provides .execute(), .executescript(), .commit(), .close(), .fetchone(), .fetchall()
    with Row-like dict access so existing code works unchanged.
    """
    def __init__(self, conn):
        self._conn = conn
        self._cursor = None

    def execute(self, sql, params=None):
        # Convert SQLite ? placeholders to PostgreSQL %s
        sql = sql.replace("?", "%s")
        # Convert SQLite-specific syntax
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        sql = sql.replace("AUTOINCREMENT", "")
        sql = sql.replace("REAL", "DOUBLE PRECISION")
        sql = sql.replace("strftime('%s','now')", "EXTRACT(EPOCH FROM NOW())")
        # Remove SQLite PRAGMAs
        if sql.strip().upper().startswith("PRAGMA"):
            return self
        # Remove CREATE TRIGGER (SQLite syntax differs)
        if "CREATE TRIGGER" in sql.upper():
            return self
        cur = self._conn.cursor(cursor_factory=_dict_cursor_factory())
        try:
            cur.execute(sql, params or ())
        except Exception as e:
            # Ignore duplicate column/table errors (migration-safe)
            err = str(e)
            if "already exists" in err or "duplicate" in err.lower():
                self._conn.rollback()
                return self
            raise
        self._cursor = cur
        return self

    def executescript(self, sql):
        """Execute multiple statements (PostgreSQL compatible)."""
        # Split on semicolons, handle each statement
        import re
        # Remove SQLite-specific triggers
        sql = re.sub(r'CREATE TRIGGER.*?END;', '', sql, flags=re.DOTALL | re.IGNORECASE)

        statements = [s.strip() for s in sql.split(';') if s.strip()]
        for stmt in statements:
            if not stmt or stmt.upper().startswith('--'):
                continue
            try:
                self.execute(stmt)
            except Exception as e:
                err = str(e)
                if "already exists" in err or "duplicate" in err.lower():
                    self._conn.rollback()
                    continue
                logger.warning(f"Migration statement failed (non-fatal): {e}")
                self._conn.rollback()

    def fetchone(self):
        return self._cursor.fetchone() if self._cursor else None

    def fetchall(self):
        return self._cursor.fetchall() if self._cursor else []

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _dict_cursor_factory():
    """Return psycopg2 DictCursor or RealDictCursor."""
    import psycopg2.extras
    return psycopg2.extras.RealDictCursor


# ---------------------------------------------------------------------------
# Schema initialization
# ---------------------------------------------------------------------------

def init_db():
    conn = get_db()

    if not USE_POSTGRES:
        import sqlite3
        # SQLite migrations
        for alter in [
            "ALTER TABLE users ADD COLUMN jurisdiction TEXT DEFAULT 'us'",
            "ALTER TABLE users ADD COLUMN vertical TEXT DEFAULT 'general'",
            "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'",
            "ALTER TABLE users ADD COLUMN org_id TEXT",
            "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0",
            "ALTER TABLE jobs ADD COLUMN matter_id TEXT",
            "ALTER TABLE phi_access_log ADD COLUMN request_id TEXT",
            "ALTER TABLE phi_access_log ADD COLUMN session_id TEXT",
            "ALTER TABLE users ADD COLUMN custom_instructions TEXT",
        ]:
            try:
                conn.execute(alter)
            except sqlite3.OperationalError:
                pass

    # Create core tables
    conn.executescript(_SCHEMA_SQL)

    # Alerts table (used by monitoring)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            level TEXT NOT NULL,
            check_name TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL,
            resolved_at DOUBLE PRECISION
        )
    """)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized ({'PostgreSQL' if USE_POSTGRES else 'SQLite'})")


_SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        is_active INTEGER DEFAULT 1,
        jurisdiction TEXT DEFAULT 'us',
        vertical TEXT DEFAULT 'general',
        role TEXT DEFAULT 'user',
        org_id TEXT,
        is_admin INTEGER DEFAULT 0,
        custom_instructions TEXT
    );

    CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        key_hash TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        last_used DOUBLE PRECISION,
        is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        prompt TEXT,
        system_prompt TEXT,
        model TEXT,
        status TEXT DEFAULT 'pending',
        response_text TEXT,
        encrypted_result TEXT,
        proof_json TEXT,
        certificate_json TEXT,
        usage_token_json TEXT,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        cost_usd DOUBLE PRECISION DEFAULT 0.0,
        created_at DOUBLE PRECISION NOT NULL,
        completed_at DOUBLE PRECISION,
        error TEXT,
        matter_id TEXT
    );

    CREATE TABLE IF NOT EXISTS waitlist (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        signed_up_at DOUBLE PRECISION,
        source TEXT DEFAULT 'website'
    );

    CREATE TABLE IF NOT EXISTS billing (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        stripe_customer_id TEXT,
        payment_method_added INTEGER DEFAULT 0,
        current_period_start DOUBLE PRECISION,
        current_period_events INTEGER DEFAULT 0,
        total_events INTEGER DEFAULT 0,
        total_billed DOUBLE PRECISION DEFAULT 0.0
    );

    CREATE TABLE IF NOT EXISTS usage_events (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        job_id TEXT NOT NULL,
        event_type TEXT DEFAULT 'sovereignty_event',
        amount DOUBLE PRECISION DEFAULT 0.04,
        created_at DOUBLE PRECISION,
        billed INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        encrypted_messages TEXT NOT NULL,
        message_count INTEGER DEFAULT 0,
        created_at DOUBLE PRECISION NOT NULL,
        updated_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_profiles (
        user_id TEXT PRIMARY KEY,
        writing_style TEXT,
        preferred_topics TEXT,
        response_preferences TEXT,
        technical_level TEXT DEFAULT 'intermediate',
        created_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_context (
        user_id TEXT PRIMARY KEY,
        core_identity TEXT NOT NULL,
        topic_index TEXT NOT NULL,
        full_context TEXT NOT NULL,
        context_hash TEXT NOT NULL,
        encryption_key_hash TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        updated_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS patient_vaults (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        patient_mrn TEXT NOT NULL,
        encrypted_data TEXT NOT NULL,
        encryption_key_id TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        updated_at DOUBLE PRECISION NOT NULL,
        is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS patient_cases (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        case_number TEXT NOT NULL,
        presenting_complaint TEXT,
        symptoms TEXT,
        labs TEXT,
        vitals TEXT,
        differential_diagnosis TEXT,
        confidence_score DOUBLE PRECISION,
        cited_sources TEXT,
        created_at DOUBLE PRECISION NOT NULL,
        destroyed_at DOUBLE PRECISION,
        destruction_proof TEXT
    );

    CREATE TABLE IF NOT EXISTS phi_access_log (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        patient_id TEXT,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        request_id TEXT,
        session_id TEXT,
        details TEXT,
        success INTEGER DEFAULT 1,
        timestamp DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS case_access_log (
        id SERIAL PRIMARY KEY,
        case_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action TEXT NOT NULL,
        accessed_at DOUBLE PRECISION NOT NULL,
        ip_address TEXT,
        session_id TEXT
    );

    CREATE TABLE IF NOT EXISTS matters (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        client_name TEXT NOT NULL,
        matter_name TEXT NOT NULL,
        matter_type TEXT DEFAULT 'other',
        case_number TEXT,
        description TEXT,
        jurisdiction TEXT,
        status TEXT DEFAULT 'active',
        created_by TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        updated_at DOUBLE PRECISION,
        is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS matter_parties (
        id SERIAL PRIMARY KEY,
        matter_id TEXT NOT NULL,
        party_name TEXT NOT NULL,
        party_role TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        matter_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        mime_type TEXT,
        size INTEGER,
        checksum TEXT,
        uploaded_by TEXT NOT NULL,
        uploaded_at DOUBLE PRECISION NOT NULL,
        is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS baa_agreements (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        covered_entity_name TEXT NOT NULL,
        covered_entity_address TEXT,
        status TEXT DEFAULT 'pending',
        created_at DOUBLE PRECISION NOT NULL,
        signed_at DOUBLE PRECISION,
        expires_at DOUBLE PRECISION,
        signed_by TEXT,
        document_url TEXT
    );

    CREATE TABLE IF NOT EXISTS reminders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        due_date DOUBLE PRECISION,
        priority TEXT DEFAULT 'normal',
        status TEXT DEFAULT 'pending',
        created_at DOUBLE PRECISION NOT NULL,
        ios_url TEXT
    );

    CREATE TABLE IF NOT EXISTS saved_responses (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        conversation_id TEXT,
        message_content TEXT NOT NULL,
        model TEXT,
        prompt TEXT,
        created_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS drip_queue (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        template_id TEXT NOT NULL,
        send_at DOUBLE PRECISION NOT NULL,
        sent INTEGER DEFAULT 0,
        created_at DOUBLE PRECISION
    );
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_api_key():
    raw = uuid.uuid4().hex + uuid.uuid4().hex
    return f"ads_{raw}"

def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()
