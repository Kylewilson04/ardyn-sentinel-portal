"""
Immutable Certificate Archive — Append-only, hash-chained archive for destruction certificates.

Algorithm:
  - Each entry is a JSON line in /opt/ardyn/data/certificates.jsonl
  - Entry includes: job_id, timestamp, proof_hash, merkle_root, death_certificate_id,
    billing_signature, usage_token_summary, prev_hash, chain_hash
  - chain_hash = SHA256(prev_hash + canonical_json(entry_without_chain_hash))
  - First entry uses prev_hash = "GENESIS"
  - The file is APPEND-ONLY. Never modify or delete existing entries.
"""
from __future__ import annotations
import hashlib
import json
import os
import time
import fcntl
from pathlib import Path

ARCHIVE_PATH = Path("/opt/ardyn/data/certificates.jsonl")


def _canonical(entry: dict) -> str:
    """Deterministic JSON for hashing (sorted keys, no whitespace)."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _compute_chain_hash(prev_hash: str, entry: dict) -> str:
    """SHA256(prev_hash + canonical_json(entry))"""
    payload = prev_hash + _canonical(entry)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _last_chain_hash() -> str:
    """Read the last chain_hash from the archive, or 'GENESIS' if empty."""
    if not ARCHIVE_PATH.exists() or ARCHIVE_PATH.stat().st_size == 0:
        return "GENESIS"
    # Read last non-empty line
    with open(ARCHIVE_PATH, "r") as f:
        last = ""
        for line in f:
            if line.strip():
                last = line
        if not last:
            return "GENESIS"
        return json.loads(last)["chain_hash"]


def archive_certificate(proof_data: dict) -> str:
    """
    Append a destruction certificate to the archive.

    proof_data should contain keys from the pipeline result:
      job_id, proof (with proof_hash, merkle_root), death_certificate (with record_id),
      usage_token (with billing_signature, token_id, cost_usd, saas_tier)

    Returns the chain_hash of the new entry.
    """
    ARCHIVE_PATH.parent.mkdir(parents=True, exist_ok=True)

    proof = proof_data.get("proof", {})
    death_cert = proof_data.get("death_certificate", {})
    usage = proof_data.get("usage_token", {})

    entry = {
        "job_id": proof_data.get("job_id", ""),
        "timestamp": time.time(),
        "proof_hash": proof.get("zk_proof_hash", ""),
        "merkle_root": proof.get("merkle_root", ""),
        "death_certificate_id": death_cert.get("record_id", ""),
        "attestation_hash": death_cert.get("attestation_hash", ""),
        "billing_signature": usage.get("billing_signature", ""),
        "usage_token_summary": {
            "token_id": usage.get("token_id", ""),
            "cost_usd": usage.get("cost_usd", 0),
            "saas_tier": usage.get("saas_tier", ""),
        },
    }

    # Atomic append with file lock
    with open(ARCHIVE_PATH, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            prev_hash = _last_chain_hash()
            entry["prev_hash"] = prev_hash
            chain_hash = _compute_chain_hash(prev_hash, entry)
            entry["chain_hash"] = chain_hash
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)

    return chain_hash


def verify_chain() -> dict:
    """
    Walk the archive and verify the hash chain.
    Returns {valid: bool, entries: int, breaks: [line_numbers_with_breaks]}
    """
    if not ARCHIVE_PATH.exists() or ARCHIVE_PATH.stat().st_size == 0:
        return {"valid": True, "entries": 0, "breaks": []}

    breaks = []
    prev_hash = "GENESIS"
    count = 0

    with open(ARCHIVE_PATH, "r") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            count += 1
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                breaks.append(i)
                continue

            stored_chain_hash = entry.pop("chain_hash", "")
            stored_prev = entry.get("prev_hash", "")

            if stored_prev != prev_hash:
                breaks.append(i)
                prev_hash = stored_chain_hash
                continue

            expected = _compute_chain_hash(prev_hash, entry)
            if expected != stored_chain_hash:
                breaks.append(i)

            prev_hash = stored_chain_hash

    return {"valid": len(breaks) == 0, "entries": count, "breaks": breaks}


def get_certificate(job_id: str) -> dict | None:
    """Lookup a certificate by job_id. Returns the entry dict or None."""
    if not ARCHIVE_PATH.exists():
        return None

    with open(ARCHIVE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("job_id") == job_id:
                    return entry
            except json.JSONDecodeError:
                continue
    return None


def get_stats() -> dict:
    """Return archive statistics."""
    if not ARCHIVE_PATH.exists() or ARCHIVE_PATH.stat().st_size == 0:
        return {"total": 0, "chain_valid": True, "first_timestamp": None, "last_timestamp": None}

    first_ts = None
    last_ts = None
    count = 0

    with open(ARCHIVE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                count += 1
                ts = entry.get("timestamp")
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
            except json.JSONDecodeError:
                count += 1

    chain_result = verify_chain()
    return {
        "total": count,
        "chain_valid": chain_result["valid"],
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
    }
