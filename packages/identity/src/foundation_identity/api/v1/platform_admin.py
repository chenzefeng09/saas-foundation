"""Platform-level admin endpoints — cross-tenant management.

Prefix: /platform

All endpoints in this module are guarded by TWO layers:
1. ``require_super_admin`` dependency — fail-closed httpx call to authz /check
   verifying action=platform.admin for the calling user_id.
2. ``admin_session_scope`` — an app_admin DB connection that sets
   ``SET LOCAL app.actor = 'ADMIN'`` inside the transaction, enabling the
   admin_all RLS policies that bypass tenant isolation.

Security invariant enforced here:
──────────────────────────────────
  actor=ADMIN is NEVER sourced from an X-Actor HTTP header.
  It is set server-side (via SET LOCAL) only after the super_admin authz
  check passes.  The middleware strips any X-Actor=ADMIN from incoming
  requests (see identity/api/middleware.py), so clients have no path to
  forge ADMIN privilege regardless of what they send.

Tenant table:
  We query ``tenant.tenant`` directly — this table has NO RLS (it is owned
  by the org service schema and is not tenant-scoped).  The app_admin role
  has SELECT/INSERT/UPDATE privilege on it.
"""

from __future__ import annotations

import re
from typing import Any, Literal

import httpx
import ulid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.domain.base import foundation_context
from foundation_identity.domain.db import admin_session_scope
from foundation_identity.observability import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/platform", tags=["platform-admin"])

_AUTHZ_TIMEOUT = 2.0  # seconds; fail-closed on timeout
_USER_ID_RE = re.compile(r"^usr_[0-9A-Z]{26}$")
_TNT_ID_RE = re.compile(r"^tnt_[0-9A-Z]{26}$")


# ─────────────────────────────────────────────────────────────────────────────
# require_super_admin FastAPI dependency
# ─────────────────────────────────────────────────────────────────────────────

async def require_super_admin(request: Request) -> str:
    """FastAPI dependency: verify the caller has action=platform.admin.

    Fail-closed: any network error, non-200 response, or allowed!=True → 403.

    Returns the caller's user_id on success (for downstream audit logging).
    """
    ctx = foundation_context.get()
    if ctx is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PLATFORM: tenant context missing",
        )

    user_id = ctx.user_id
    if not user_id or not _USER_ID_RE.match(user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PLATFORM: valid user_id required",
        )

    settings = request.app.state.settings if hasattr(request.app.state, "settings") else None
    from foundation_identity.config import get_settings as _gs
    authz_url: str = (settings.authz_url if settings and hasattr(settings, "authz_url") else None) or _gs().authz_url

    try:
        async with httpx.AsyncClient(timeout=_AUTHZ_TIMEOUT) as client:
            resp = await client.post(
                f"{authz_url}/check",
                json={
                    "user_id": user_id,
                    "action": "platform.admin",
                    "resource_type": "platform",
                },
                headers={"X-Tenant-Id": ctx.tenant_id},
            )
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as exc:
        log.warning("platform.require_super_admin.authz_unreachable", exc=str(exc))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PLATFORM: authz service unreachable",
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"PLATFORM: authz returned HTTP {resp.status_code}",
        )

    try:
        body = resp.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PLATFORM: authz response unparseable",
        )

    if body.get("allowed") is not True:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PLATFORM: permission denied (platform.admin required)",
        )

    return user_id


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────

class TenantRead(BaseModel):
    id: str
    name: str
    tier: str
    status: str
    created_at: str


class CreateTenantRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # Tiers must match the CHECK constraint on tenant.tenant.tier
    tier: str = Field(default="FREE", pattern=r"^(FREE|PRO|BUSINESS|ENTERPRISE|DEDICATED)$")
    admin_email: str = Field(min_length=5, max_length=254)
    admin_display_name: str | None = None


class PatchTenantRequest(BaseModel):
    # Tiers must match the CHECK constraint on tenant.tenant.tier
    tier: Literal["FREE", "PRO", "BUSINESS", "ENTERPRISE", "DEDICATED"] | None = None
    # Statuses must match the CHECK constraint on tenant.tenant.status
    status: Literal["ACTIVE", "SUSPENDED", "TERMINATING", "TERMINATED"] | None = None


class UserReadCross(BaseModel):
    id: str
    tenant_id: str
    email: str
    display_name: str | None
    status: str
    created_at: str


# ─────────────────────────────────────────────────────────────────────────────
# GET /platform/tenants
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/tenants", response_model=dict)
async def list_tenants(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    actor_user_id: str = Depends(require_super_admin),
) -> dict[str, Any]:
    """List all tenants across the platform (no RLS, app_admin reads tenant.tenant)."""
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        # tenant.tenant has no RLS; app_admin can SELECT freely.
        q = "SELECT id, name, tier, status, created_at FROM tenant.tenant WHERE TRUE"
        params: dict[str, Any] = {"limit": limit + 1}
        if cursor:
            q += " AND id > :cursor"
            params["cursor"] = cursor
        q += " ORDER BY id LIMIT :limit"
        rows = (await session.execute(text(q), params)).fetchall()

    next_cursor = rows[-1][0] if len(rows) > limit else None
    items = [
        {"id": r[0], "name": r[1], "tier": r[2], "status": r[3], "created_at": str(r[4])}
        for r in rows[:limit]
    ]
    return {"items": items, "next_cursor": next_cursor}


# ─────────────────────────────────────────────────────────────────────────────
# POST /platform/tenants
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/tenants", status_code=201, response_model=dict)
async def create_tenant(
    body: CreateTenantRequest,
    request: Request,
    actor_user_id: str = Depends(require_super_admin),
) -> dict[str, Any]:
    """Provision a new tenant (calls TenantProvisioningService)."""
    from foundation_identity.services.tenant_provisioning_service import (
        TenantProvisioningService,
    )
    from foundation_identity.adapters.keycloak_admin import get_keycloak_admin
    from foundation_identity.adapters.audit_publisher import get_audit_publisher
    from foundation_identity.config import get_settings

    settings = get_settings()
    svc = TenantProvisioningService(
        keycloak=get_keycloak_admin(),
        audit=get_audit_publisher(),
        org_url=settings.org_url,
        billing_url=settings.billing_url,
        authz_url=settings.authz_url,
    )

    result = await svc.provision(
        name=body.name,
        tier=body.tier,
        admin_email=body.admin_email,
        admin_display_name=body.admin_display_name,
        actor_user_id=actor_user_id,
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# GET /platform/tenants/{tid}
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/tenants/{tid}", response_model=dict)
async def get_tenant(
    tid: str,
    actor_user_id: str = Depends(require_super_admin),
) -> dict[str, Any]:
    """Fetch a single tenant row (cross-tenant, no RLS)."""
    if not _TNT_ID_RE.match(tid):
        raise HTTPException(status_code=400, detail="Invalid tenant id format")
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        row = (
            await session.execute(
                text(
                    "SELECT id, name, tier, status, created_at "
                    "FROM tenant.tenant WHERE id = :id"
                ),
                {"id": tid},
            )
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"id": row[0], "name": row[1], "tier": row[2], "status": row[3], "created_at": str(row[4])}


# ─────────────────────────────────────────────────────────────────────────────
# PATCH /platform/tenants/{tid}
# ─────────────────────────────────────────────────────────────────────────────

@router.patch("/tenants/{tid}", response_model=dict)
async def patch_tenant(
    tid: str,
    body: PatchTenantRequest,
    actor_user_id: str = Depends(require_super_admin),
) -> dict[str, Any]:
    """Update tier or status of a tenant."""
    if not _TNT_ID_RE.match(tid):
        raise HTTPException(status_code=400, detail="Invalid tenant id format")

    updates: list[str] = []
    params: dict[str, Any] = {"id": tid}
    if body.tier is not None:
        updates.append("tier = :tier")
        params["tier"] = body.tier
    if body.status is not None:
        updates.append("status = :status")
        params["status"] = body.status

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    set_clause = ", ".join(updates)
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        result = await session.execute(
            text(
                f"UPDATE tenant.tenant SET {set_clause}, updated_at = now() "
                "WHERE id = :id RETURNING id, name, tier, status, created_at"
            ),
            params,
        )
        row = result.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"id": row[0], "name": row[1], "tier": row[2], "status": row[3], "created_at": str(row[4])}


# ─────────────────────────────────────────────────────────────────────────────
# GET /platform/users?tenant_id=
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/users", response_model=dict)
async def list_users_cross_tenant(
    tenant_id: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    actor_user_id: str = Depends(require_super_admin),
) -> dict[str, Any]:
    """List users across all tenants (or filtered by tenant_id)."""
    params: dict[str, Any] = {"limit": limit + 1}
    where_clauses = ["deleted_at IS NULL"]

    if tenant_id:
        if not _TNT_ID_RE.match(tenant_id):
            raise HTTPException(status_code=400, detail="Invalid tenant_id format")
        where_clauses.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id

    if cursor:
        where_clauses.append("id > :cursor")
        params["cursor"] = cursor

    where = " AND ".join(where_clauses)
    q = (
        f"SELECT id, tenant_id, email, display_name, status, created_at "
        f"FROM identity.user WHERE {where} ORDER BY id LIMIT :limit"
    )

    async with admin_session_scope(tenant_id=tenant_id or "", user_id=actor_user_id) as session:
        rows = (await session.execute(text(q), params)).fetchall()

    next_cursor = rows[-1][0] if len(rows) > limit else None
    items = [
        {
            "id": r[0], "tenant_id": r[1], "email": r[2],
            "display_name": r[3], "status": r[4], "created_at": str(r[5]),
        }
        for r in rows[:limit]
    ]
    return {"items": items, "next_cursor": next_cursor}
