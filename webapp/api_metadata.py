"""
Ardyn Intelligence — OpenAPI Metadata

Import and apply to FastAPI app:

    from api_metadata import API_METADATA, API_TAGS
    app = FastAPI(**API_METADATA)
"""

API_METADATA = {
    "title": "Ardyn Intelligence — Atomic Data Sovereignty API",
    "description": (
        "**Patent-pending** Atomic Data Sovereignty (ADS) platform for regulated industries.\n\n"
        "Every inference runs inside a Ardyn Sovereignty Pipeline. After processing, "
        "all user data is cryptographically destroyed via three-pass zeroization, verified by "
        "cryptographic commitment proofs, and recorded on an immutable attestation ledger.\n\n"
        "**Core guarantee**: You get AI inference *and* cryptographic proof that sensitive "
        "data was destroyed afterward.\n\n"
        "**Supported verticals**: Legal, Healthcare, Finance, Cybersecurity.\n\n"
        "## Authentication\n"
        "- **API Key**: `Authorization: Bearer <key>` or `X-API-Key: <key>`\n"
        "- **JWT**: HTTP-only cookie for dashboard sessions (7-day expiry)\n\n"
        "## Pricing\n"
        "- SCU-based pricing: Developer $0/SCU, Production $0.15/SCU, Enterprise $0.05/SCU\n"
        "- 15% volume discount at 100K+ events/month"
    ),
    "version": "1.0.0-beta",
    "docs_url": "/api/docs",
    "redoc_url": "/api/redoc",
    "openapi_tags": [
        {
            "name": "Inference",
            "description": "Submit queries for sovereignty-native AI inference. Every request produces a response, a cryptographic destruction proof, and an immutable death certificate.",
        },
        {
            "name": "Proofs",
            "description": "Retrieve and verify cryptographic destruction certificates. Each proof contains a SHA-256 commitment hash, Merkle root of zeroed memory, and monotonic counter value.",
        },
        {
            "name": "Billing",
            "description": "Usage tracking, billing history, and Stripe payment integration. Billing signatures are derived from destruction nonces — unforgeable proof of destruction.",
        },
        {
            "name": "Matters",
            "description": "Matter/case management with organization-level isolation. Organize documents and inferences by client, case, or project.",
        },
        {
            "name": "Documents",
            "description": "Upload documents to the sovereignty pipeline-native encrypted vault for retrieval-augmented generation (RAG). Documents are processed entirely within the sovereignty boundary.",
        },
        {
            "name": "Auth",
            "description": "Registration, login, API key management, and JWT token issuance. Rate-limited to prevent brute force.",
        },
        {
            "name": "Models",
            "description": "List sovereignty-approved models available for inference.",
        },
        {
            "name": "Admin",
            "description": "Administrative endpoints for waitlist management, drip email processing, and platform monitoring.",
        },
    ],
}

# Convenience: just the tags list
API_TAGS = API_METADATA["openapi_tags"]
