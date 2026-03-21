"""
Ardyn Billing — SSO (SAML 2.0 / OIDC)
========================================
Enterprise SSO federation with Okta, Azure AD, Google Workspace, etc.

SAML: Service Provider (SP) initiated flow
OIDC: Authorization Code flow with PKCE

Enterprise orgs configure their IdP settings in the admin dashboard.
Individual tier continues using email/password.
"""

import hashlib
import json
import logging
import secrets
import time
from typing import Optional, Dict
from urllib.parse import urlencode

import jwt
from fastapi import APIRouter, Request, HTTPException, Response
from fastapi.responses import RedirectResponse, HTMLResponse

logger = logging.getLogger("ardyn.billing.sso")

router = APIRouter(prefix="/platform/sso", tags=["sso"])

# ---------------------------------------------------------------------------
# SSO Configuration storage (per-org)
# ---------------------------------------------------------------------------

# In production these come from the database. For now, env vars + in-memory.
# Format: JSON blob per org stored in Organization.sso_config column

def _get_org_sso_config(org_id: str) -> Optional[Dict]:
    """Load SSO config for an org from the database."""
    from enterprise.billing.models import SessionLocal, Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            return None
        # sso_config stored as JSON string in a text column
        raw = getattr(org, 'sso_config', None)
        if raw:
            return json.loads(raw)
        return None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# OIDC (OpenID Connect) — Works with Okta, Azure AD, Google, Auth0
# ---------------------------------------------------------------------------

# Pending state storage (in-memory for now, Redis in production)
_oidc_states: Dict[str, Dict] = {}


@router.get("/oidc/authorize")
async def oidc_authorize(org_id: str, request: Request):
    """
    Start OIDC authorization code flow.
    Redirects user to their IdP login page.

    Usage: GET /platform/sso/oidc/authorize?org_id=<org_id>
    """
    config = _get_org_sso_config(org_id)
    if not config or config.get("type") != "oidc":
        raise HTTPException(400, "OIDC not configured for this organization")

    # Generate state + PKCE verifier
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        hashlib.sha256(code_verifier.encode()).digest()
    )
    import base64
    code_challenge_b64 = base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode()

    _oidc_states[state] = {
        "org_id": org_id,
        "code_verifier": code_verifier,
        "created_at": time.time(),
    }

    # Build authorization URL
    params = {
        "response_type": "code",
        "client_id": config["client_id"],
        "redirect_uri": "https://platform.ardyn.ai/platform/sso/oidc/callback",
        "scope": "openid email profile",
        "state": state,
        "code_challenge": code_challenge_b64,
        "code_challenge_method": "S256",
    }

    auth_url = f"{config['authorization_endpoint']}?{urlencode(params)}"
    return RedirectResponse(auth_url)


@router.get("/oidc/callback")
async def oidc_callback(code: str = "", state: str = "", error: str = "", response: Response = None):
    """
    OIDC callback — exchanges authorization code for tokens.
    Creates or links user account, sets session cookie.
    """
    if error:
        raise HTTPException(400, f"IdP error: {error}")

    if state not in _oidc_states:
        raise HTTPException(400, "Invalid or expired state parameter")

    state_data = _oidc_states.pop(state)

    # Check expiry (5 min)
    if time.time() - state_data["created_at"] > 300:
        raise HTTPException(400, "Authorization request expired")

    org_id = state_data["org_id"]
    config = _get_org_sso_config(org_id)
    if not config:
        raise HTTPException(400, "SSO configuration not found")

    # Exchange code for tokens
    import httpx
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://platform.ardyn.ai/platform/sso/oidc/callback",
                "client_id": config["client_id"],
                "client_secret": config.get("client_secret", ""),
                "code_verifier": state_data["code_verifier"],
            },
        )

    if token_resp.status_code != 200:
        logger.error(f"Token exchange failed: {token_resp.text}")
        raise HTTPException(502, "Token exchange failed with identity provider")

    tokens = token_resp.json()
    id_token = tokens.get("id_token", "")

    # Decode ID token (verify signature in production with IdP's JWKS)
    try:
        # For now, decode without verification (IdP-specific JWKS verification should be added)
        claims = jwt.decode(id_token, options={"verify_signature": False})
    except Exception as e:
        raise HTTPException(400, f"Invalid ID token: {e}")

    email = claims.get("email", "").lower()
    name = claims.get("name", email.split("@")[0])

    if not email:
        raise HTTPException(400, "ID token missing email claim")

    # Find or create user in the org
    from enterprise.billing.models import SessionLocal, Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(404, "Organization not found")

        # Set session cookies
        session_token = hashlib.sha256(f"{org.id}:{email}:ardyn-session-salt".encode()).hexdigest()[:32]

        resp = RedirectResponse("/platform", status_code=302)
        resp.set_cookie("ardyn_org_id", org.id, httponly=True, samesite="lax", max_age=86400 * 30)
        resp.set_cookie("ardyn_session", session_token, httponly=True, samesite="lax", max_age=86400 * 30)

        # SSO users are auto-verified
        if not org.email_verified:
            org.email_verified = True
            db.commit()

        logger.info(f"SSO login: {email} → org {org.name} via OIDC")
        return resp
    finally:
        db.close()


# ---------------------------------------------------------------------------
# SAML 2.0 — Works with Okta, Azure AD, OneLogin, etc.
# ---------------------------------------------------------------------------

@router.get("/saml/metadata")
async def saml_metadata():
    """
    Return Ardyn's SAML Service Provider metadata XML.
    Enterprise customers import this into their IdP.
    """
    metadata = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://platform.ardyn.ai/platform/sso/saml"
    validUntil="2030-01-01T00:00:00Z">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://platform.ardyn.ai/platform/sso/saml/acs"
        index="1" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
    return HTMLResponse(content=metadata, media_type="application/xml")


@router.post("/saml/acs")
async def saml_acs(request: Request):
    """
    SAML Assertion Consumer Service (ACS) endpoint.
    Receives SAML Response from IdP after successful authentication.
    """
    form = await request.form()
    saml_response = form.get("SAMLResponse", "")
    relay_state = form.get("RelayState", "")

    if not saml_response:
        raise HTTPException(400, "Missing SAMLResponse")

    # Parse relay_state to get org_id
    org_id = relay_state  # We pass org_id as RelayState

    config = _get_org_sso_config(org_id)
    if not config or config.get("type") != "saml":
        raise HTTPException(400, "SAML not configured for this organization")

    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.utils import OneLogin_Saml2_Utils

        # Build python3-saml request
        saml_req = {
            "https": "on",
            "http_host": "platform.ardyn.ai",
            "script_name": "/platform/sso/saml/acs",
            "post_data": {"SAMLResponse": saml_response, "RelayState": relay_state},
        }

        saml_settings = {
            "strict": True,
            "sp": {
                "entityId": "https://platform.ardyn.ai/platform/sso/saml",
                "assertionConsumerService": {
                    "url": "https://platform.ardyn.ai/platform/sso/saml/acs",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
            },
            "idp": {
                "entityId": config["idp_entity_id"],
                "singleSignOnService": {
                    "url": config["idp_sso_url"],
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": config["idp_x509_cert"],
            },
        }

        auth = OneLogin_Saml2_Auth(saml_req, saml_settings)
        auth.process_response()
        errors = auth.get_errors()

        if errors:
            logger.error(f"SAML errors: {errors}")
            raise HTTPException(400, f"SAML validation failed: {', '.join(errors)}")

        if not auth.is_authenticated():
            raise HTTPException(401, "SAML authentication failed")

        # Extract user info
        email = auth.get_nameid().lower()
        attrs = auth.get_attributes()
        name = (attrs.get("displayName", [""]) or attrs.get("name", [""]))[0] or email.split("@")[0]

    except ImportError:
        # python3-saml not installed — fall back to basic base64 decode
        logger.warning("python3-saml not installed — using basic SAML parsing")
        import base64
        from xml.etree import ElementTree

        raw = base64.b64decode(saml_response)
        tree = ElementTree.fromstring(raw)
        ns = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
        name_id = tree.find(".//saml:NameID", ns)
        email = name_id.text.lower() if name_id is not None else ""
        name = email.split("@")[0]

        if not email:
            raise HTTPException(400, "Could not extract email from SAML response")

    # Set session
    from enterprise.billing.models import SessionLocal, Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(404, "Organization not found")

        session_token = hashlib.sha256(f"{org.id}:{email}:ardyn-session-salt".encode()).hexdigest()[:32]
        resp = RedirectResponse("/platform", status_code=302)
        resp.set_cookie("ardyn_org_id", org.id, httponly=True, samesite="lax", max_age=86400 * 30)
        resp.set_cookie("ardyn_session", session_token, httponly=True, samesite="lax", max_age=86400 * 30)

        if not org.email_verified:
            org.email_verified = True
            db.commit()

        logger.info(f"SSO login: {email} → org {org.name} via SAML")
        return resp
    finally:
        db.close()


@router.get("/saml/login")
async def saml_login(org_id: str):
    """
    Initiate SAML SP-initiated login.
    Redirects to the IdP's SSO URL.
    """
    config = _get_org_sso_config(org_id)
    if not config or config.get("type") != "saml":
        raise HTTPException(400, "SAML not configured for this organization")

    # Simple redirect to IdP with RelayState
    params = urlencode({"RelayState": org_id})
    return RedirectResponse(f"{config['idp_sso_url']}?{params}")
