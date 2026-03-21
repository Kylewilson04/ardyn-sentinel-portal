# Phase A/B Extraction Report

**Source:** `/home/ardyn/ardyn-sentinel/` on prod (20.119.179.146)
**Date:** 2026-03-21
**Rule:** Prod reality → clean extraction → new repo

---

## What Was Created

### Repo 1: `ardyn-sentinel-runtime`
**Path:** `/home/kyle/ardyn-sentinel-runtime`
**Total files:** 223 (93 non-git)
**Size:** 1,399 KB

The Sentinel runtime — injected into client environments. Handles proof/DDC generation, certificate signing, metering/pricing emission, and hardware zeroization.

### Repo 2: `ardyn-sentinel-portal`
**Path:** `/home/kyle/ardyn-sentinel-portal`
**Total files:** 185 (77 non-git)
**Size:** 1,254 KB

The evidence portal — marketing, org login, DDC verification, stored DDC/ledger viewing, billing display only. No hosted inference.

---

## RUNTIME REPO — File List

```
gateway/
  app.py                        # Gateway FastAPI server (4-core checks, proof routing)
  sentinel_runtime.py           # SentinelRuntime class — the enforcement engine

src/ads/                        # ADS core — injected into client environments
  __init__.py
  boundary.py                   # Inference boundary / isolation
  certificate_authority.py      # CA signing
  hardware_shredder.py          # GPU VRAM destruction
  inference_engine.py            # Inference execution
  key_derivation.py             # Key derivation
  models.py                     # Pydantic models
  ollama_zeroization.py         # Ollama-specific zeroization
  proof_system.py              # Proof generation
  secure_memory.py              # Secure memory management
  zeroization.py               # Memory zeroization

src/ddc/                        # Distributed Death Certificate
  __init__.py
  attestation_ledger.py          # Hash-chained ledger (224 lines — canonical)
  metering.py                    # SCU metering
  proof_of_shred.py             # Proof of shred

src/attestation_metering.py     # SCU/pricing emission

src/license_validator.py        # License validation

src/sentinel/                   # Sentinel control plane
  __init__.py
  __version__.py
  api_server.py
  audit_logger.py
  auth.py
  cli.py
  config.py
  consensus.py
  control_plane/
    __init__.py
    admin_api.py
    policy.py
    tenant.py
  daemon.py
  daemon_basic.py
  endpoint_validator.py
  events.py
  inference_lock.py
  input_validation.py
  licensing/
    __init__.py
    features.py
    keystore.py
    license.py
    metering.py
  metering/
    __init__.py
    admin.py
    ddc_billing.py
    scu.py
    see.py
    tier_entitlements.py
  monitoring/
    __init__.py
    alerts.py
    compat_publisher.py
    platform_monitor.py
    probe_engine.py
    probe_model.py
    remote_probe.py
    sentinel_runner.py
    strategy_resolver.py
    vendor_monitor.py
  observability.py
  probes.py
  remediation.py
  sql_safe.py
  tls_helper.py

src/sentinel_runtime.py         # Runtime entry point

sdk/ardyn/                      # Client SDK for integration
  __init__.py
  client.py
  crypto.py
  exceptions.py
  models.py
  verify.py
  pyproject.toml
  README.md

docs/shared/
  ADS_PIPELINE.md
  DDC_SPECIFICATION.md
  SCU_METERING.md
  SDK_USAGE.md
  SECURITY_MODEL.md
  SOVEREIGN_INFERENCE_CONTRACT.md

configs/
  sentinel-standalone.toml

monitoring/
  monitor.py

tests/
  test_architecture_guard.py
  test_ca_production_fail_closed.py
  test_ddc_verification.py
  test_full_pipeline.py
  test_p0_sdk_protocol.py
  test_p1_counter_hardening.py
  test_p1_type_fix.py
  test_p2_concurrency.py
  test_proof_provenance.py

conftest.py
pyproject.toml
requirements-sentinel.txt
README.md
```

---

## PORTAL REPO — File List

```
webapp/
  app.py                        # Portal FastAPI (clean — all inference routes removed)

  # Evidence/account routes
  routes/
    health.py                   # Health endpoint ✓
    verify_api.py              # Public DDC verification ✓
    ledger.py                  # Local ledger view ✓
    ledger_api.py              # Ledger API ✓
    audit.py                   # Org audit trail ✓
    billing.py                 # Account/billing display ✓

  # Evidence infrastructure
  certificate_archive.py         # DDC storage/retrieval
  immutable_ledger.py           # Local immutable ledger
  enterprise_navigation.py       # Org navigation (if real org nav)

  # Portal access control
  route_guards.py              # Org access middleware

  # Auth
  auth.py                      # Login/session
  database.py                  # SQLite user store

  # Billing service
  billing.py                   # Stripe billing service

  # Middleware
  middleware/
    rate_limiting.py
    circuit_breaker.py
    org_verification.py
    session_timeout.py

  # Supporting
  event_bus.py
  api_metadata.py
  alerting.py
  memory_limits.py
  vertical_registry.py

  # Templates (org-verified views)
  templates/
    audit.html
    billing.html
    ledger.html
    login.html
    trust_dashboard.html
    enterprise/
      landing.html
    enterprise_base.html
    error.html
    base.html
    chat.html
    dashboard.html
    documents.html
    vault.html
    proofs.html
    settings.html
    onboarding.html
    history.html
    playground.html
    tutorial.html
    register.html
    import.html
    baa.html
    matters.html
    monitoring.html
    vault_org.html
    clinical/
      case_review.html
      new_case.html
      patients.html
    enterprise/
      counsel.html
      dashboard.html
      health-us.html
      legal-us.html
    blog_index.html
    blog_post.html
    proof_dashboard.html

  # Static
  static/
    app.js
    inference-ui.js
    robots.txt

  requirements.txt
  .env.example

website/                        # Marketing + evidence portal pages
  index.html
  admin.html
  api.html
  demo-portal.html
  monitor.html
  my-ddcs.html
  script.js
  trust-dashboard.html

enterprise/billing/             # Billing account display
  stripe_billing.py
  models.py
  sso.py
  middleware.py
  data_residency.py

README.md
```

---

## LEFT-BEHIND FILES (Inference Surface / Abandoned Architecture)

### Not copied to runtime:
```
archive/                        # Historical artifacts — not runtime
configs/compat.toml             # Compatibility config only
requirements-sidecar.txt        # Sidecar mode — superseded
src/ads_boundary.py            # Duplicate of ads/boundary.py
src/cluster/                    # Cluster mode — not in current scope
src/hardware_shredder.py        # Duplicate of ads/hardware_shredder.py
src/inference_engine.py         # Duplicate of ads/inference_engine.py
src/inference_lock.py           # Duplicate of sentinel/inference_lock.py
src/key_derivation.py           # Duplicate of ads/key_derivation.py
src/metering.py                 # Duplicate of sentinel/metering/see.py
src/models.py                   # Duplicate of ads/models.py
src/ollama_zeroization.py       # Duplicate of ads/ollama_zeroization.py
src/proof_of_shred.py           # Duplicate of ddc/proof_of_shred.py
src/proof_system.py            # Duplicate of ads/proof_system.py
src/requirements.txt           # Redundant
src/secure_memory.py            # Duplicate of ads/secure_memory.py
src/shared/                      # Shared compat layer
src/tier_resolver.py           # Duplicate
src/volume_tracker.py          # Duplicate
src/zeroization.py             # Duplicate of ads/zeroization.py
```

### Not copied to portal:
```
webapp/routes/inference.py       # Inference execution — not portal
webapp/routes/v1_api.py         # Inference API — not portal
webapp/routes/conversations.py  # Chat history — inference-adjacent
webapp/routes/context.py        # Context management — inference-adjacent
webapp/routes/reminders.py     # Reminders — inference-adjacent
webapp/routes/search.py        # Search — feed/inference-adjacent
webapp/routes/vault.py         # Inference vault — not evidence portal
webapp/routes/detection.py     # Detection — inference-adjacent
webapp/routes/rag.py           # RAG — inference surface
webapp/routes/matters.py       # Matters CRM — not evidence portal
webapp/routes/documents.py     # Document processing — inference-adjacent
webapp/routes/baa.py           # BAA — HIPAA billing, not core evidence
webapp/routes/baa_settings.py  # BAA settings — not core evidence
webapp/routes/sso.py           # SSO — deferred
webapp/routes/us_compliance.py # US compliance — deferred
webapp/routes/vault_org.py    # Org vault — deferred
webapp/routes/feed_api.py      # Feed/RSS — not evidence portal
webapp/routes/mcp_api.py       # MCP server — not evidence portal
webapp/routes/jurisdiction_api.py       # Jurisdiction — deferred
webapp/routes/jurisdiction_explicit_api.py
webapp/routes/enterprise_dashboard.py   # Enterprise dashboard — deferred
webapp/routes/clinical.py              # Clinical portal — deferred
webapp/routes/proof_dashboard.py       # Proof dashboard — deferred
webapp/routes/monitoring.py            # Monitoring — deferred
webapp/routes/monitor_api.py          # Monitor API — deferred
webapp/routes/archive.py              # Archive — deferred
webapp/routes/metrics_api.py          # Metrics — deferred
webapp/routes/reliability.py         # Reliability — deferred
webapp/routes/org_ddcs.py            # Org DDCs — deferred
webapp/routes/sms_demo.py            # SMS demo — not evidence
webapp/routes/admin.py               # Admin — deferred
webapp/routes/demo_api.py           # Demo API — deferred
webapp/routes/mock_endpoints.py     # Mock endpoints — deferred
webapp/routes/tutorials.py          # Tutorials — deferred
webapp/blog_routes.py               # Blog — marketing, deferred
webapp/inference_config.py          # Inference config — NOT portal
webapp/rag_pipeline.py              # RAG pipeline — NOT portal
webapp/system_prompts.py            # System prompts — NOT portal
webapp/ads_pipeline.py             # ADS pipeline — NOT portal
webapp/inference_attestation.py    # Inference attestation — NOT portal
webapp/inference_health.py        # Inference health — NOT portal
webapp/ollama_client.py           # Ollama client — NOT portal
webapp/ollama_zeroization.py     # Ollama zeroization — NOT portal
webapp/chroma_manager.py         # Vector DB — NOT portal
webapp/document_processor.py     # Document processing — NOT portal
webapp/document_processor_v2.py # Document processing v2 — NOT portal
webapp/drip_emails.py           # Drip emails — NOT portal
webapp/email_service.py         # Email service — NOT portal
webapp/email_service_v2.py      # Email service v2 — NOT portal
webapp/encrypted_database.py     # Encrypted DB — deferred
webapp/jurisdiction_router.py   # Jurisdiction router — deferred
webapp/mcp-config.json          # MCP config — NOT portal
webapp/mcp_client.py            # MCP client — NOT portal
webapp/mcp-servers/             # MCP servers — NOT portal
webapp/phi_detector.py          # PHI detection — deferred
webapp/pipeline.py              # Pipeline — NOT portal
webapp/queue_manager.py         # Queue manager — NOT portal
webapp/rbac.py                  # RBAC — deferred
webapp/retention.py             # Retention policy — deferred
webapp/tutorials.py             # Tutorials — deferred
webapp/upload_ui.py             # Upload UI — deferred
webapp/us_safety_guardrails.py  # US safety — deferred
webapp/vault_manager.py         # Vault manager — deferred
webapp/virus_scanner.py         # Virus scanner — deferred
webapp/worker_manager.py        # Worker manager — deferred
webapp/workers.yaml             # Worker config — deferred
webapp/verticals/               # Vertical configs — deferred
webapp/blog/                    # Blog content — deferred
webapp/canlii_config.py         # Legal feed config — deferred
webapp/context_config.py        # Context config — deferred
webapp/feed/                    # RSS feed infrastructure — NOT portal
webapp/services/                # Matter/patient services — deferred
webapp/audit_all.py             # Audit all — deferred
webapp/deploy.sh                # Deploy script — deferred
webapp/routes/conversations.py  # Already above
website/ (all other pages)      # Static marketing pages
enterprise/billing/dashboard/   # Full billing dashboard HTML — deferred
enterprise/billing/siem.py      # SIEM — deferred
enterprise/billing/migrations/  # DB migrations — deferred
```

---

## PORTAL DEPENDENCY GRAPH (Retained Evidence Routes)

```
app.py
  ├── routes/health.py          [stdlib + fastapi only]          → /health
  ├── routes/billing.py         [billing.py, database.py, auth.py] → /api/billing/*
  ├── routes/audit.py           [auth.py, database.py]           → /api/audit/*
  ├── routes/verify_api.py      [httpx, stdlib]                  → /verify, /v1/verify/*
  ├── routes/ledger.py          [src/ddc/attestation_ledger.py]   → /api/ledger/*
  └── routes/ledger_api.py      [auth.py]                         → /api/ledger/*
       │
       └── DEPENDS ON: src/ddc/attestation_ledger.py (from runtime repo)
           (ledger.py inserts ../src into sys.path to reach it)

certificate_archive.py           → imported by verify_api.py at runtime
immutable_ledger.py              → imported by verify_api.py at runtime
enterprise_navigation.py         → imported by app.py helpers
route_guards.py                  → app.py middleware
billing.py                       → routes/billing.py
auth.py                          → routes/*, app.py
database.py                      → routes/*, app.py
middleware/rate_limiting.py      → app.py
middleware/circuit_breaker.py     → app.py
middleware/org_verification.py   → app.py
middleware/session_timeout.py    → app.py
event_bus.py                     → app.py
```

---

## RUNTIME DEPENDENCY GRAPH

```
gateway/app.py
  └── gateway/sentinel_runtime.py
        ├── src/ads/proof_system.py
        ├── src/ads/certificate_authority.py
        ├── src/ads/hardware_shredder.py
        ├── src/ads/ollama_zeroization.py
        ├── src/ads/zeroization.py
        ├── src/ads/secure_memory.py
        ├── src/ads/inference_engine.py
        ├── src/ads/boundary.py
        ├── src/ads/key_derivation.py
        ├── src/ddc/attestation_ledger.py
        ├── src/ddc/metering.py
        ├── src/ddc/proof_of_shred.py
        └── src/attestation_metering.py

src/sentinel/cli.py              → sentinel runtime entry point
src/sentinel/daemon.py           → sentinel daemon
src/sentinel/api_server.py       → sentinel API
src/sentinel_runtime.py          → src-level entry point

sdk/ardyn/client.py             → client SDK (consumes gateway API)
sdk/ardyn/verify.py             → client-side DDC verification
```

---

## NEXT STEPS (in priority order)

### Phase C — Portal evidence-only reduction

1. **audit route** — confirm audit.py exports only org-portal activity (not inference logs). Currently imports only `auth` and `csv` — looks clean. Retain.
2. **billing route** — `routes/billing.py` calls `billing.py` which imports `stripe_billing.py`. Check if Stripe calls inference tokens. If yes, strip that field. Retain.
3. **`/verify/{job_id}` inline handler** — already in app.py, makes HTTP call to gateway. Works as evidence display. Retain.
4. **Static HTML templates** — reduce to only those for: login, billing, ledger, audit, trust-dashboard. Others are deferred.
5. **`enterprise_navigation.py`** — confirm it's real org nav (not vertical contamination). Looks like it includes org headers and nav structure — keep with audit.

### Phase D — Runtime verification

1. Boot `gateway/app.py` on prod and confirm 4-core check runs
2. Verify `src/ddc/attestation_ledger.py` hash-chain is intact
3. Confirm SDK `verify.py` can read a real DDC from the ledger

### Phase E — GitHub repos

1. Create `Kylewilson04/ardyn-sentinel-runtime` on GitHub
2. Create `Kylewilson04/ardyn-sentinel-portal` on GitHub
3. Push both from `/home/kyle/ardyn-sentinel-runtime` and `/home/kyle/ardyn-sentinel-portal`
4. Update prod deployment to pull from the new runtime repo
