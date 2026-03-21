"""Enterprise Navigation Service — standalone version for portal.

Org model types are inlined to avoid db_models dependency.
Full db_models version available in runtime repo for org management features.
"""
from __future__ import annotations
from typing import List, Optional, Literal
from dataclasses import dataclass, field
from enum import Enum


class OrgVertical(Enum):
    HEALTHCARE = "healthcare"
    LEGAL = "legal"
    FINANCE = "finance"
    CYBERSECURITY = "cybersecurity"
    PHARMACY = "pharmacy"
    GENERAL = "general"


class OrgJurisdiction(Enum):
    US = "us"
    CANADA = "canada"
    EU = "eu"


class Organization:
    """Minimal org model for navigation — no DB required."""
    def __init__(self, id: int, name: str, slug: str,
                 vertical: OrgVertical = OrgVertical.GENERAL,
                 jurisdiction: OrgJurisdiction = OrgJurisdiction.US):
        self.id = id
        self.name = name
        self.slug = slug
        self.vertical = vertical
        self.jurisdiction = jurisdiction

    def __repr__(self):
        return f"Organization(id={self.id}, name={self.name!r}, vertical={self.vertical.value})"


@dataclass
class PersonalOrg:
    name: str = "Personal"
    vertical: OrgVertical = OrgVertical.GENERAL
    jurisdiction: OrgJurisdiction = OrgJurisdiction.US

    def __getattr__(self, name):
        if name == "vertical":
            return self.vertical
        if name == "jurisdiction":
            return self.jurisdiction
        raise AttributeError(name)


@dataclass
class NavItem:
    id: str
    label: str
    icon: str
    url: str
    badge: Optional[str] = None
    badge_color: Optional[str] = None
    children: Optional[List['NavItem']] = None
    requires_permission: Optional[str] = None


class EnterpriseNavigationService:
    """Generates org navigation for evidence portal."""

    ICONS = {
        "dashboard": "<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><rect x='3' y='3' width='7' height='7' rx='1.5'/><rect x='14' y='3' width='7' height='7' rx='1.5'/><rect x='3' y='14' width='7' height='7' rx='1.5'/><rect x='14' y='14' width='7' height='7' rx='1.5'/></svg>",
        "billing": "<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><rect x='2' y='5' width='20' height='14' rx='2'/><path d='M2 10h20'/></svg>",
        "ledger": "<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><path d='M12 2L2 7l10 5 10-5-10-5z'/><path d='M2 17l10 5 10-5'/><path d='M2 12l10 5 10-5'/></svg>",
        "audit": "<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><path d='M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z'/><path d='M14 2v6h6M16 13H8M16 17H8M10 9H8'/></svg>",
        "verify": "<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/><path d='M9 12l2 2 4-4'/></svg>",
        "settings": "<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><circle cx='12' cy='12' r='3'/><path d='M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z'/></svg>",
    }

    VERTICAL_LABELS = {
        OrgVertical.HEALTHCARE: "Healthcare",
        OrgVertical.LEGAL: "Legal",
        OrgVertical.FINANCE: "Finance",
        OrgVertical.CYBERSECURITY: "Cybersecurity",
        OrgVertical.PHARMACY: "Pharmacy",
        OrgVertical.GENERAL: "General",
    }

    def get_nav(self, org, user_role: str = "member") -> dict:
        primary = [
            NavItem(id="dashboard", label="Dashboard", icon=self.ICONS["dashboard"], url="/dashboard"),
            NavItem(id="ledger", label="Ledger", icon=self.ICONS["ledger"], url="/ledger"),
            NavItem(id="billing", label="Billing", icon=self.ICONS["billing"], url="/billing"),
            NavItem(id="audit", label="Audit", icon=self.ICONS["audit"], url="/audit"),
        ]
        secondary = [
            NavItem(id="verify", label="Verify DDC", icon=self.ICONS["verify"], url="/trust"),
        ]
        admin_items = []
        if user_role == "admin":
            admin_items.append(NavItem(id="settings", label="Settings", icon=self.ICONS["settings"], url="/settings"))

        return {
            "org_header": {
                "org_name": org.name if org else "Personal",
                "vertical_name": self.VERTICAL_LABELS.get(
                    org.vertical if org else OrgVertical.GENERAL, "General"
                ),
                "jurisdiction_name": (org.jurisdiction.value.upper() if org and org.jurisdiction else "US"),
            },
            "primary_nav": primary,
            "secondary_nav": secondary,
            "admin_nav": admin_items,
        }


def get_enterprise_nav(org, user_role: str = "member") -> dict:
    """Convenience function."""
    return EnterpriseNavigationService().get_nav(org, user_role)
