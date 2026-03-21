"""Organization Multi-Tenancy Model"""
import time
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum

class OrgPlan(str, Enum):
    FREE = "free"
    STARTUP = "startup"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    HEALTHCARE = "healthcare"
    LEGAL = "legal"

class OrgStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    CANCELLED = "cancelled"

class OrgVertical(str, Enum):
    """Industry vertical for the organization."""
    HEALTHCARE = "healthcare"
    LEGAL = "legal"
    GENERAL = "general"

class OrgJurisdiction(str, Enum):
    """Primary jurisdiction for legal/compliance."""
    US = "us"                    # United States
    CANADA = "ca"                # Canada (federal)
    CANADA_ALBERTA = "ca-ab"     # Alberta
    CANADA_BC = "ca-bc"          # British Columbia
    CANADA_ONTARIO = "ca-on"     # Ontario
    CANADA_QUEBEC = "ca-qc"      # Quebec
    UK = "uk"                    # United Kingdom
    EU = "eu"                    # European Union
    OTHER = "other"

@dataclass
class Organization:
    id: str
    name: str
    slug: str
    plan: OrgPlan
    status: OrgStatus
    admin_email: str
    billing_email: Optional[str] = None
    phone: Optional[str] = None
    address_line1: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: str = "US"

    # Jurisdiction & Vertical (determines MCP routing)
    vertical: OrgVertical = OrgVertical.GENERAL  # healthcare, legal, general
    jurisdiction: OrgJurisdiction = OrgJurisdiction.US  # us, ca, ca-ab, etc.

    # Secondary jurisdictions (for multi-jurisdictional orgs)
    secondary_jurisdictions: List[OrgJurisdiction] = field(default_factory=list)

    settings: Dict = field(default_factory=dict)
    features_enabled: List[str] = field(default_factory=list)
    sso_enabled: bool = False
    sso_provider: Optional[str] = None
    mfa_required: bool = False
    hipaa_enabled: bool = False
    audit_retention_days: int = 2555
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    max_matters: Optional[int] = None
    max_documents: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "name": self.name, "slug": self.slug,
            "plan": self.plan.value, "status": self.status.value,
            "admin_email": self.admin_email, "billing_email": self.billing_email,
            "phone": self.phone, "address_line1": self.address_line1,
            "city": self.city, "state": self.state, "postal_code": self.postal_code,
            "country": self.country,
            "vertical": self.vertical.value,
            "jurisdiction": self.jurisdiction.value,
            "secondary_jurisdictions": [j.value for j in self.secondary_jurisdictions],
            "settings": self.settings,
            "features_enabled": self.features_enabled, "sso_enabled": self.sso_enabled,
            "sso_provider": self.sso_provider, "mfa_required": self.mfa_required,
            "hipaa_enabled": self.hipaa_enabled, "audit_retention_days": self.audit_retention_days,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "max_matters": self.max_matters, "max_documents": self.max_documents
        }

    def get_mcp_config(self) -> Dict:
        """
        Get MCP routing configuration based on vertical and jurisdiction.

        Returns which MCP servers to use for this organization.
        """
        config = {
            "vertical": self.vertical.value,
            "jurisdiction": self.jurisdiction.value,
            "mcp_servers": [],
            "tools_available": []
        }

        # Determine which MCP servers to use
        if self.vertical == OrgVertical.HEALTHCARE:
            # Healthcare uses PubMed globally
            config["mcp_servers"].append("pubmed-research")
            config["tools_available"].extend([
                "search_pubmed",
                "get_article",
                "check_retraction"
            ])

        elif self.vertical == OrgVertical.LEGAL:
            # Legal jurisdiction determines data source
            if self.jurisdiction in [OrgJurisdiction.US]:
                # US law: CourtListener
                config["mcp_servers"].append("legal-research")
                config["tools_available"].extend([
                    "search_courtlistener",
                    "verify_case_validity"
                ])
                config["legal_source"] = "courtlistener"

            elif self.jurisdiction in [
                OrgJurisdiction.CANADA,
                OrgJurisdiction.CANADA_ALBERTA,
                OrgJurisdiction.CANADA_BC,
                OrgJurisdiction.CANADA_ONTARIO,
                OrgJurisdiction.CANADA_QUEBEC
            ]:
                # Canadian law: CanLII
                config["mcp_servers"].append("legal-research")
                config["tools_available"].extend([
                    "search_canlii",
                    "get_case_metadata",
                    "get_case_citator"
                ])
                config["legal_source"] = "canlii"
                config["canlii_jurisdiction"] = self._get_canlii_jurisdiction()

        return config

    def _get_canlii_jurisdiction(self) -> str:
        """Map OrgJurisdiction to CanLII database ID."""
        mapping = {
            OrgJurisdiction.CANADA: "csc-scc",  # Supreme Court
            OrgJurisdiction.CANADA_ALBERTA: "abca",  # Alberta Court of Appeal
            OrgJurisdiction.CANADA_BC: "bcca",  # BC Court of Appeal
            OrgJurisdiction.CANADA_ONTARIO: "onca",  # Ontario Court of Appeal
            OrgJurisdiction.CANADA_QUEBEC: "qcca",  # Quebec Court of Appeal
        }
        return mapping.get(self.jurisdiction, "csc-scc")

@dataclass
class OrganizationMember:
    id: str
    org_id: str
    user_id: str
    role: str
    permissions: List[str] = field(default_factory=list)
    is_active: bool = True
    allowed_matters: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def has_permission(self, permission: str) -> bool:
        if self.role == "owner":
            return True
        return permission in self.permissions
