# Phase C/D/E Report — Portal Reduction, Runtime Verification, GitHub Push

**Date:** 2026-03-21
**Source:** Production VM `/home/ardyn/ardyn-sentinel/` (20.119.179.146)

---

## Phase C — Portal Evidence-Only Audit and Fixes

### Issue Found: billing.py imported runtime SCU pricing

`webapp/billing.py` had `sys.path.insert(0, .../src)` and imported `tier_resolver` and `volume_tracker` from `src/` — hard coupling to the runtime.

**Fix:** Replaced `billing.py` with a self-contained stub that has SCU pricing constants inline. Portal billing display now shows only what can be audited from the portal's own DB — no inference token pricing.

### Issue Found: routes/billing.py queried jobs table for inference tokens

`routes/billing.py` ran `SELECT model, input_tokens, output_tokens, cost_usd FROM jobs` — inference data leakage into evidence display.

**Fix:** Stripped to stub endpoints returning `{total_inferences: 0, total_tokens: 0, inference_cost: 0.0}`. Billing display is org-account only.

### Issue Found: enterprise_navigation.py imported db_models

`enterprise_navigation.py` imported `from db_models.organizations import Organization, OrgVertical, OrgJurisdiction` — db_models was not copied to the portal.

**Fix:** Replaced with a self-contained version that has the enum and model classes inline. No DB dependency for navigation.

### Issue Found: verify and ledger routes were not registered in production app.py

Production had only 3 routers registered (billing, audit, health). `verify_api` and `ledger` existed on disk but were not included.

**Fix:** Added `verify_router`, `ledger_router`, `ledger_api_router` to production app.py.

### Portal Route Audit Results

| Route | File | Status | Reason |
|-------|------|--------|--------|
| `GET /health` | routes/health.py | RETAINED | stdlib + fastapi only |
| `GET /billing` | routes/billing.py | RETAINED | auth-protected, stubbed |
| `GET /api/billing/*` | routes/billing.py | RETAINED | stubbed — no inference data |
| `GET /audit` | routes/audit.py | RETAINED | auth-protected, stubbed |
| `GET /api/audit/*` | routes/audit.py | RETAINED | stubbed — no inference data |
| `GET /ledger` | routes/ledger.py | RETAINED | auth-protected, uses ddc ledger |
| `GET /api/ledger` | routes/ledger_api.py | RETAINED | auth-protected |
| `GET /verify/{job_id}` | routes/verify_api.py | RETAINED | no auth, calls gateway |
| `GET /` | inline | RETAINED | static website |
| `GET /trust` | inline | RETAINED | static trust dashboard |
| `GET /inference` | — | REMOVED | 404 |
| `GET /v1/infer` | — | REMOVED | 404 |
| `GET /api/inferences` | — | REMOVED | 404 |

### Portal Boot Results (production)

```
ads-webapp: active (running) — no import errors
GET /health           → HTTP 200 {"status":"healthy"}
GET /billing          → HTTP 307 → /login (auth protected)
GET /api/billing/usage → HTTP 401 Unauthorized
GET /audit           → HTTP 307 → /login (auth protected)
GET /api/audit/stats  → HTTP 401 Unauthorized
GET /ledger          → HTTP 307 → /login (auth protected)
GET /api/ledger      → HTTP 401 Unauthorized (route registered, auth blocked)
GET /verify/test-job → HTTP 200 (full verification HTML UI)
GET /trust           → HTTP 200
GET /                → HTTP 200
GET /inference       → HTTP 404 (correctly removed)
```

---

## Phase D — Runtime Verification

### Gateway Running on Production

```
ardyn-gateway.service: active (running)
Uptime: 10h+ 
Monotonic counter: 185
Jobs processed: 122
enclave_active: true
```

Gateway is the Sentinel runtime — it has processed 122 sovereign executions and maintained counter integrity through all of them.

### Gateway Endpoints

```
GET /v1/health  → {"status":"healthy","enclave_active":true,"monotonic_counter":185,"jobs_processed":122}
GET /v1/verify/{job_id} → {"detail":"No proof found for job test"} (route works)
```

### SDK Verify Path

`sdk/ardyn/verify.py` — standalone DDC verification using only stdlib (`hashlib`). No external dependencies. Accepts either a full pipeline response or a standalone DDC dict. Runs 4 checks:
1. Structure (required fields)
2. Attestation hash (SHA-256 proof_hash + counter)
3. Proof hash format (64-char hex)
4. Counter monotonicity

### SDK Client

`sdk/ardyn/client.py` — `ArdynClient` class with `httpx`. Works with hosted, private VPC, and airgapped deployments. Single `httpx` dependency.

---

## Phase E — GitHub Push

### Repos Created

**ardyn-sentinel-runtime**
- URL: https://github.com/Kylewilson04/ardyn-sentinel-runtime
- Description: Sentinel runtime — injected into client environments. Proof/DDC generation, certificate signing, metering, hardware zeroization.
- Contents: gateway/, src/ads/, src/ddc/, src/sentinel/, src/attestation_metering.py, src/license_validator.py, sdk/ardyn/, docs/shared/
- Files: 223 total (93 non-git)

**ardyn-sentinel-portal**
- URL: https://github.com/Kylewilson04/ardyn-sentinel-portal
- Description: Sentinel evidence portal — marketing, org login, DDC verification, ledger viewing, billing display. No hosted inference.
- Contents: webapp/ (evidence routes only), website/, enterprise/billing/
- Files: 185 total (77 non-git)

### Files Intentionally Not Copied

**Inference surface:**
- routes/inference.py, routes/v1_api.py
- ads_pipeline.py, rag_pipeline.py, system_prompts.py, inference_config.py
- ollama_client.py, chroma_manager.py, document_processor.py
- feed/, mcp-servers/, blog_routes.py

**Deferred verticals:**
- clinical/, matters/, documents/, vault/, detection/, baa/
- sso/, us_compliance/, enterprise_dashboard/, proof_dashboard/
- monitoring/, archive/, jurisdiction_*, org_ddcs/, sms_demo/

**Old architecture:**
- archive/ (chaos, dead-services, enterprise-*)
- requirements-sidecar.txt, requirements.txt
- src/ads_boundary.py, src/cluster/, src/tests/test_skss.py

---

## Architecture Summary

```
PRODUCTION (20.119.179.146)
├── ardyn-gateway (port 8443)          → Sentinel runtime (4-core checks)
│   └── Monotonic counter: 185, Jobs: 122
│
└── ads-webapp (port 8080)            → Evidence portal (reduced)
    ├── /verify/{job_id}               → Public DDC verification (calls gateway)
    ├── /ledger, /api/ledger           → Attestation ledger (auth)
    ├── /api/billing/usage             → Org account (stubbed, no inference)
    ├── /api/audit/stats              → Audit trail (stubbed)
    ├── /health                       → Health
    └── /trust, /, /website/          → Marketing + trust dashboard

GITHUB
├── Kylewilson04/ardyn-sentinel-runtime
│   ├── gateway/                      → 4-core enforcement engine
│   ├── src/ads/                     → Proof, CA, zeroization
│   ├── src/ddc/                      → Attestation ledger, metering
│   ├── src/sentinel/                → Control plane, licensing, monitoring
│   ├── src/attestation_metering.py   → SCU pricing emission
│   └── sdk/ardyn/                   → Client SDK
│
└── Kylewilson04/ardyn-sentinel-portal
    ├── webapp/app.py                 → Evidence portal (clean)
    ├── webapp/routes/               → verify, ledger, billing, audit, health
    ├── webapp/certificate_archive.py → DDC storage
    ├── webapp/immutable_ledger.py   → Azure WORM backend
    ├── webapp/enterprise_navigation.py → Org nav (standalone)
    └── website/                      → Marketing + trust dashboard
```
