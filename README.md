# Ardyn Sentinel Portal

Evidence portal — marketing, org login, DDC verification, ledger viewing, billing display. No hosted inference.

## Evidence Routes

- `GET /verify/{job_id}` — Public DDC verification (no auth)
- `GET /ledger` — Local attestation ledger (auth required)
- `GET /api/ledger` — Ledger API (auth required)
- `GET /api/billing/usage` — Billing usage (auth required)
- `GET /api/audit/stats` — Audit statistics (auth required)
- `GET /health` — Health endpoint

## Not Included

This repo does NOT contain the Sentinel runtime. See [ardyn-sentinel-runtime](https://github.com/Kylewilson04/ardyn-sentinel-runtime) for the runtime.

## Architecture

- `webapp/app.py` — Evidence portal FastAPI app (reduced from full webapp)
- `webapp/routes/` — Evidence-only routes (verify, ledger, billing, audit, health)
- `webapp/certificate_archive.py` — DDC storage/retrieval
- `webapp/immutable_ledger.py` — Azure immutable blob storage backend
- `webapp/enterprise_navigation.py` — Org navigation (inline org models, no DB)
- `website/` — Marketing pages + trust-dashboard

## Source

Production VM: `/home/ardyn/ardyn-sentinel/` (20.119.179.146)
# trigger
retest
retest2
