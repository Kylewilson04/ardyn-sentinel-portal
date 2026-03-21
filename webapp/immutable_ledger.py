"""
Immutable Ledger — Azure Immutable Blob Storage backed death certificate ledger.

Every death certificate is written as an individual blob with:
- Blob name: {job_id}.json
- Content: full certificate + proof + usage token
- Metadata: chain_hash, previous_hash, sequence_number
- Legal hold: enabled (cannot be deleted)

Periodic chain anchors written to chain-anchors container.

Falls back gracefully if Azure is unreachable — local JSONL archive remains primary.
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Azure connection — loaded lazily
_CONN_STR_PATH = Path("/opt/ardyn/secrets/azure_storage.key")
_CERT_CONTAINER = "death-certificates"
_ANCHOR_CONTAINER = "chain-anchors"


def _get_connection_string() -> Optional[str]:
    """Load Azure connection string from secrets file or env."""
    cs = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if cs:
        return cs.strip()
    if _CONN_STR_PATH.exists():
        return _CONN_STR_PATH.read_text().strip()
    return None


def _canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


class ImmutableLedger:
    """
    Azure Immutable Blob Storage backed death certificate ledger.

    Compatible with the local certificate_archive.py hash chain format.
    """

    def __init__(self, connection_string: Optional[str] = None):
        self._conn_str = connection_string or _get_connection_string()
        self._blob_service = None
        self._cert_client = None
        self._anchor_client = None
        self._available = False
        self._init_clients()

    def _init_clients(self):
        if not self._conn_str:
            logger.warning("ImmutableLedger: No Azure connection string — operating in offline mode")
            return
        try:
            from azure.storage.blob import BlobServiceClient
            self._blob_service = BlobServiceClient.from_connection_string(self._conn_str)
            self._cert_client = self._blob_service.get_container_client(_CERT_CONTAINER)
            self._anchor_client = self._blob_service.get_container_client(_ANCHOR_CONTAINER)
            self._available = True
            logger.info("ImmutableLedger: Connected to Azure Immutable Blob Storage")
        except Exception as e:
            logger.error(f"ImmutableLedger: Failed to connect to Azure: {e}")
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    # ── Hash chain helpers (compatible with certificate_archive.py) ──

    def _compute_chain_hash(self, prev_hash: str, entry: dict) -> str:
        payload = prev_hash + _canonical(entry)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _get_last_chain_info(self) -> tuple[str, int]:
        """Get (last_chain_hash, sequence_number) from Azure blobs."""
        if not self._available:
            return "GENESIS", 0
        try:
            blobs = list(self._cert_client.list_blobs(include=["metadata"]))
            if not blobs:
                return "GENESIS", 0
            # Sort by sequence number in metadata
            sequenced = []
            for b in blobs:
                meta = b.metadata or {}
                seq = int(meta.get("sequence_number", 0))
                sequenced.append((seq, meta.get("chain_hash", "GENESIS")))
            sequenced.sort(key=lambda x: x[0])
            last_seq, last_hash = sequenced[-1]
            return last_hash, last_seq
        except Exception as e:
            logger.error(f"ImmutableLedger: Failed to read last chain info: {e}")
            return "GENESIS", 0

    # ── Public API ──

    def record_certificate(
        self,
        job_id: str,
        proof: dict,
        death_cert: dict,
        usage_token: dict,
    ) -> dict:
        """
        Write a death certificate to Azure Immutable Blob Storage with legal hold.

        Returns dict with blob_name, chain_hash, sequence_number, and azure_written flag.
        """
        if not self._available:
            return {"azure_written": False, "error": "Azure not available"}

        try:
            prev_hash, last_seq = self._get_last_chain_info()
            seq = last_seq + 1

            entry = {
                "job_id": job_id,
                "timestamp": time.time(),
                "proof_hash": proof.get("zk_proof_hash", ""),
                "merkle_root": proof.get("merkle_root", ""),
                "death_certificate_id": death_cert.get("record_id", ""),
                "attestation_hash": death_cert.get("attestation_hash", ""),
                "billing_signature": usage_token.get("billing_signature", ""),
                "usage_token_summary": {
                    "token_id": usage_token.get("token_id", ""),
                    "cost_usd": usage_token.get("cost_usd", 0),
                    "saas_tier": usage_token.get("saas_tier", ""),
                },
                "prev_hash": prev_hash,
            }

            chain_hash = self._compute_chain_hash(prev_hash, entry)
            entry["chain_hash"] = chain_hash

            blob_name = f"{job_id}.json"
            blob_client = self._cert_client.get_blob_client(blob_name)

            metadata = {
                "chain_hash": chain_hash,
                "previous_hash": prev_hash,
                "sequence_number": str(seq),
                "job_id": job_id,
            }

            from azure.storage.blob import ContentSettings
            blob_client.upload_blob(
                json.dumps(entry, indent=2),
                overwrite=False,
                metadata=metadata,
                content_settings=ContentSettings(content_type="application/json"),
            )

            # Set legal hold on the blob
            try:
                blob_client.set_legal_hold(True)
            except Exception as lh_err:
                logger.warning(f"ImmutableLedger: Legal hold set failed (may need container-level policy): {lh_err}")

            logger.info(f"ImmutableLedger: Recorded certificate {job_id} (seq={seq})")
            return {
                "azure_written": True,
                "blob_name": blob_name,
                "chain_hash": chain_hash,
                "sequence_number": seq,
            }

        except Exception as e:
            logger.error(f"ImmutableLedger: Failed to record certificate {job_id}: {e}")
            return {"azure_written": False, "error": str(e)}

    def get_certificate(self, job_id: str) -> Optional[dict]:
        """Fetch a specific certificate from Azure."""
        if not self._available:
            return None
        try:
            blob_client = self._cert_client.get_blob_client(f"{job_id}.json")
            data = blob_client.download_blob().readall()
            return json.loads(data)
        except Exception as e:
            logger.debug(f"ImmutableLedger: Certificate {job_id} not found in Azure: {e}")
            return None

    def verify_certificate(self, job_id: str) -> dict:
        """Fetch a certificate from Azure and verify its hash chain integrity."""
        cert = self.get_certificate(job_id)
        if not cert:
            return {"valid": False, "error": "Certificate not found in Azure", "job_id": job_id}

        stored_hash = cert.pop("chain_hash", "")
        prev_hash = cert.get("prev_hash", "GENESIS")
        expected_hash = self._compute_chain_hash(prev_hash, cert)
        cert["chain_hash"] = stored_hash  # restore

        valid = expected_hash == stored_hash
        return {
            "valid": valid,
            "job_id": job_id,
            "chain_hash": stored_hash,
            "expected_hash": expected_hash,
            "prev_hash": prev_hash,
            "timestamp": cert.get("timestamp"),
        }

    def anchor_chain(self) -> str:
        """Compute current chain state hash, write anchor blob, return anchor hash."""
        if not self._available:
            return ""
        try:
            last_hash, last_seq = self._get_last_chain_info()
            anchor = {
                "anchor_time": time.time(),
                "last_chain_hash": last_hash,
                "last_sequence": last_seq,
                "anchor_hash": hashlib.sha256(
                    f"{last_hash}:{last_seq}:{time.time()}".encode()
                ).hexdigest(),
            }
            blob_name = f"anchor-{int(time.time())}-seq{last_seq}.json"
            blob_client = self._anchor_client.get_blob_client(blob_name)
            from azure.storage.blob import ContentSettings as _CS
            blob_client.upload_blob(
                json.dumps(anchor, indent=2),
                metadata={"anchor_hash": anchor["anchor_hash"], "sequence": str(last_seq)},
                content_settings=_CS(content_type="application/json"),
            )
            logger.info(f"ImmutableLedger: Chain anchor written at seq={last_seq}")
            return anchor["anchor_hash"]
        except Exception as e:
            logger.error(f"ImmutableLedger: Chain anchor failed: {e}")
            return ""

    def verify_chain(self, limit: int = 100) -> dict:
        """Verify hash chain integrity across blobs."""
        if not self._available:
            return {"valid": False, "error": "Azure not available", "checked": 0}
        try:
            blobs = list(self._cert_client.list_blobs(include=["metadata"]))
            # Sort by sequence_number
            sorted_blobs = sorted(
                blobs,
                key=lambda b: int((b.metadata or {}).get("sequence_number", 0)),
            )[:limit]

            prev_hash = "GENESIS"
            breaks = []
            for i, blob in enumerate(sorted_blobs):
                blob_client = self._cert_client.get_blob_client(blob.name)
                data = json.loads(blob_client.download_blob().readall())
                stored_hash = data.pop("chain_hash", "")
                stored_prev = data.get("prev_hash", "")

                if stored_prev != prev_hash:
                    breaks.append({"blob": blob.name, "issue": "prev_hash mismatch"})
                    prev_hash = stored_hash
                    continue

                expected = self._compute_chain_hash(prev_hash, data)
                if expected != stored_hash:
                    breaks.append({"blob": blob.name, "issue": "chain_hash mismatch"})
                prev_hash = stored_hash

            return {
                "valid": len(breaks) == 0,
                "checked": len(sorted_blobs),
                "breaks": breaks,
            }
        except Exception as e:
            logger.error(f"ImmutableLedger: Chain verification failed: {e}")
            return {"valid": False, "error": str(e), "checked": 0}

    def get_chain_status(self) -> dict:
        """Return chain statistics: total certs, last anchor, validity."""
        if not self._available:
            return {"available": False, "total": 0}
        try:
            certs = list(self._cert_client.list_blobs())
            total = len(certs)

            # Get last anchor
            anchors = list(self._anchor_client.list_blobs(include=["metadata"]))
            last_anchor = None
            if anchors:
                anchors.sort(key=lambda b: b.name)
                last_blob = anchors[-1]
                anchor_client = self._anchor_client.get_blob_client(last_blob.name)
                last_anchor = json.loads(anchor_client.download_blob().readall())

            return {
                "available": True,
                "total": total,
                "last_anchor": last_anchor,
                "last_chain_hash": self._get_last_chain_info()[0],
            }
        except Exception as e:
            logger.error(f"ImmutableLedger: Status check failed: {e}")
            return {"available": False, "error": str(e), "total": 0}


# Singleton
_ledger_instance: Optional[ImmutableLedger] = None


def get_immutable_ledger() -> ImmutableLedger:
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = ImmutableLedger()
    return _ledger_instance
