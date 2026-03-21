"""
Ardyn Billing — Data Residency Controls
==========================================
Enforces data residency per organization. Routes inference requests
to region-specific GPU endpoints based on org configuration.

Supported regions:
    us-east   — US East (default, Jetson + Azure East US 2)
    eu-west   — EU West (planned)
    ap-south  — Asia Pacific South (planned)
    any       — No restriction

Residency is enforced at the API middleware level:
    1. Org's data_region is checked on every /v1/process request
    2. Request is routed to the correct regional GPU endpoint
    3. Certificate includes region attestation
"""

import logging
import os
from typing import Dict, Tuple

logger = logging.getLogger("ardyn.billing.residency")

# ---------------------------------------------------------------------------
# Regional GPU endpoints
# ---------------------------------------------------------------------------

# Map region → inference endpoint
# As infrastructure scales, add region-specific endpoints
REGION_ENDPOINTS: Dict[str, Dict] = {
    "us-east": {
        "name": "US East",
        "endpoint": os.environ.get("GPU_ENDPOINT_US_EAST", "http://localhost:11434"),
        "azure_region": "eastus2",
        "available": True,
        "jurisdiction": ["US", "CA"],
    },
    "eu-west": {
        "name": "EU West",
        "endpoint": os.environ.get("GPU_ENDPOINT_EU_WEST", ""),
        "azure_region": "westeurope",
        "available": False,  # Not yet deployed
        "jurisdiction": ["EU", "UK", "CH"],
    },
    "ap-south": {
        "name": "Asia Pacific South",
        "endpoint": os.environ.get("GPU_ENDPOINT_AP_SOUTH", ""),
        "azure_region": "southeastasia",
        "available": False,  # Not yet deployed
        "jurisdiction": ["SG", "AU", "JP", "IN"],
    },
}


def get_region_endpoint(org_id: str) -> Tuple[str, str]:
    """
    Get the GPU inference endpoint for an org's data residency region.
    Returns (endpoint_url, region_name).
    Raises ValueError if region is not available.
    """
    from enterprise.billing.models import SessionLocal, Organization

    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise ValueError(f"Organization not found: {org_id}")

        region = org.data_region or "us-east"

        if region == "any":
            # No restriction — use default
            region = "us-east"

        if region not in REGION_ENDPOINTS:
            raise ValueError(f"Unknown data region: {region}")

        endpoint_info = REGION_ENDPOINTS[region]
        if not endpoint_info["available"]:
            raise ValueError(
                f"Region '{endpoint_info['name']}' is not yet available. "
                f"Contact compliance@ardyn.ai for regional deployment timeline."
            )

        return endpoint_info["endpoint"], region

    finally:
        db.close()


def get_available_regions() -> list:
    """Return list of available regions for org configuration."""
    return [
        {
            "id": region_id,
            "name": info["name"],
            "available": info["available"],
            "jurisdiction": info["jurisdiction"],
        }
        for region_id, info in REGION_ENDPOINTS.items()
    ]


def set_org_region(org_id: str, region: str) -> bool:
    """Set data residency region for an org. Returns True if successful."""
    if region not in REGION_ENDPOINTS and region != "any":
        return False

    from enterprise.billing.models import SessionLocal, Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            return False
        org.data_region = region
        db.commit()
        logger.info(f"Org {org.name} data residency set to: {region}")
        return True
    finally:
        db.close()


def get_residency_attestation(region: str) -> Dict:
    """
    Generate a data residency attestation for inclusion in destruction certificates.
    This is a contractual guarantee that data was processed in the specified region.
    """
    info = REGION_ENDPOINTS.get(region, REGION_ENDPOINTS["us-east"])
    return {
        "data_region": region,
        "region_name": info["name"],
        "azure_region": info["azure_region"],
        "jurisdiction": info["jurisdiction"],
        "attestation": f"Data processed exclusively within {info['name']} region. "
                       f"No data transferred outside {', '.join(info['jurisdiction'])} jurisdiction.",
    }
