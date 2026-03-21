"""Organization Verification Middleware - CRIT-004
Ensures users can only access resources belonging to their organization
"""
from functools import wraps
from fastapi import HTTPException
from database import get_db

class OrgVerificationError(Exception):
    """Raised when org verification fails"""
    pass

def verify_resource_access(user: dict, resource_type: str, resource_id: str) -> bool:
    """
    Verify that a user has access to a specific resource.

    Args:
        user: The current user dict with org_id
        resource_type: Type of resource ('patient_vault', 'patient_case', 'matter', 'document')
        resource_id: UUID of the resource

    Returns:
        True if user has access, False otherwise
    """
    user_org_id = user.get("org_id", user.get("sub"))

    conn = get_db()
    try:
        if resource_type == "patient_vault":
            row = conn.execute(
                "SELECT org_id FROM patient_vaults WHERE id = ? AND is_active = 1",
                (resource_id,)
            ).fetchone()
        elif resource_type == "patient_case":
            row = conn.execute(
                """SELECT pv.org_id FROM patient_cases pc
                   JOIN patient_vaults pv ON pc.vault_id = pv.id
                   WHERE pc.id = ? AND pc.is_active = 1""",
                (resource_id,)
            ).fetchone()
        elif resource_type == "matter":
            # Assuming matters table exists with org_id column
            row = conn.execute(
                "SELECT org_id FROM matters WHERE id = ? AND is_active = 1",
                (resource_id,)
            ).fetchone()
        elif resource_type == "document":
            # Check document through matter or vault association
            row = conn.execute(
                """SELECT COALESCE(m.org_id, pv.org_id) as org_id
                   FROM documents d
                   LEFT JOIN matters m ON d.matter_id = m.id
                   LEFT JOIN patient_vaults pv ON d.vault_id = pv.id
                   WHERE d.id = ? AND d.is_active = 1""",
                (resource_id,)
            ).fetchone()
        else:
            return False

        if not row:
            return False

        resource_org_id = row["org_id"]
        return resource_org_id == user_org_id

    finally:
        conn.close()

def require_org_access(resource_type: str):
    """
    Decorator to require org access verification.

    Usage:
        @router.get("/patients/{vault_id}")
        @require_org_access("patient_vault")
        async def get_patient(vault_id: str, user=Depends(get_current_user)):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find user and resource_id in kwargs
            user = kwargs.get('user') or kwargs.get('current_user')
            resource_id = kwargs.get('vault_id') or kwargs.get('case_id') or \
                         kwargs.get('matter_id') or kwargs.get('document_id')

            if not user:
                raise HTTPException(401, "Authentication required")

            if not resource_id:
                raise HTTPException(400, f"Resource ID required for {resource_type}")

            # Admin can access anything within their org
            if user.get("role") == "admin":
                # Still verify same org
                if not verify_resource_access(user, resource_type, resource_id):
                    raise HTTPException(403, "Resource not found or access denied")
            else:
                # Non-admin users must pass org verification
                if not verify_resource_access(user, resource_type, resource_id):
                    raise HTTPException(403, "Resource not found or access denied")

            return await func(*args, **kwargs)
        return wrapper
    return decorator

class OrgVerificationMiddleware:
    """Middleware for org verification on all protected routes"""

    # Routes that require org verification
    PROTECTED_ROUTES = [
        ("/api/clinical/patients/", "patient_vault"),
        ("/api/clinical/cases/", "patient_case"),
        ("/api/matters/", "matter"),
        ("/api/documents/", "document"),
    ]

    @staticmethod
    def verify_org_membership(user: dict, resource_org_id: str) -> bool:
        """Verify user belongs to the resource's organization"""
        user_org_id = user.get("org_id", user.get("sub"))
        return user_org_id == resource_org_id
