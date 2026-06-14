"""Large-attachment entitlement endpoints (two-layer BOOLEAN admission).

Tenant-level admin endpoints (gated by the ``large_attachment.admin`` scope)
manage the tenant switch and the per-user allowlist. A resolve endpoint lets
services / the BFF check admission on behalf of a user.

Tenant scoping follows the storage-quotas convention: ``tenant_id`` comes from
the FoundationContext (the ``X-Tenant-Id`` request context / RLS scope), never
from the request body.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.adapters.org_client import OrgClient
from foundation_lifecycle.api.dependencies import (
    current_context,
    db_session,
    large_attachment_service,
    org_client,
    require_scope,
)
from foundation_lifecycle.domain.base import FoundationContext
from foundation_lifecycle.services.large_attachment_service import (
    LargeAttachmentService,
)

router = APIRouter()

_ADMIN_SCOPE = "large_attachment.admin"


class PutTenantSettingRequest(BaseModel):
    enabled: bool


class PutUserAllowRequest(BaseModel):
    user_id: str
    allowed: bool


class PutSubjectAllowRequest(BaseModel):
    # Enforce the enum at the pydantic layer → FastAPI returns 422 on garbage
    # before it reaches the service. The service-level ValueError→400 catch is
    # kept as defense in depth.
    subject_type: Literal["USER", "TEAM", "ORG_UNIT"]
    subject_id: str
    allowed: bool


# ── tenant layer (admin) ─────────────────────────────────────────────────────
@router.get(
    "/large-attachment/tenant-setting",
    operation_id="getLargeAttachmentTenantSetting",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def get_tenant_setting(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    row = await svc.get_tenant_setting(session, tenant_id=ctx.tenant_id)
    if row is None:
        # No row yet → the switch defaults to off.
        return {
            "id": None,
            "tenant_id": ctx.tenant_id,
            "large_attachment_enabled": False,
            "updated_at": None,
            "updated_by": None,
        }
    return svc.serialize_setting(row)


@router.put(
    "/large-attachment/tenant-setting",
    operation_id="putLargeAttachmentTenantSetting",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def put_tenant_setting(
    body: PutTenantSettingRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    row = await svc.upsert_tenant_setting(
        session,
        tenant_id=ctx.tenant_id,
        enabled=body.enabled,
        actor=ctx.user_id or "",
    )
    return svc.serialize_setting(row)


# ── user layer (admin) ───────────────────────────────────────────────────────
@router.get(
    "/large-attachment/user-allows",
    operation_id="listLargeAttachmentUserAllows",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def list_user_allows(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    rows = await svc.list_user_allows(session, tenant_id=ctx.tenant_id)
    return {"items": [svc.serialize_allow(r) for r in rows]}


@router.put(
    "/large-attachment/user-allows",
    operation_id="putLargeAttachmentUserAllow",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def put_user_allow(
    body: PutUserAllowRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    row = await svc.upsert_user_allow(
        session,
        tenant_id=ctx.tenant_id,
        user_id=body.user_id,
        allowed=body.allowed,
        actor=ctx.user_id or "",
    )
    return svc.serialize_allow(row)


@router.delete(
    "/large-attachment/user-allows/{user_id}",
    operation_id="deleteLargeAttachmentUserAllow",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def delete_user_allow(
    user_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    deleted = await svc.delete_user_allow(
        session, tenant_id=ctx.tenant_id, user_id=user_id
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="user allow not found")
    return {"deleted": True, "user_id": user_id}


# ── subject layer (admin — generalized USER / TEAM / ORG_UNIT) ───────────────
@router.get(
    "/large-attachment/subject-allows",
    operation_id="listLargeAttachmentSubjectAllows",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def list_subject_allows(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    rows = await svc.list_subject_allows(session, tenant_id=ctx.tenant_id)
    return {"items": [svc.serialize_subject_allow(r) for r in rows]}


@router.put(
    "/large-attachment/subject-allows",
    operation_id="putLargeAttachmentSubjectAllow",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def put_subject_allow(
    body: PutSubjectAllowRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    try:
        row = await svc.upsert_subject_allow(
            session,
            tenant_id=ctx.tenant_id,
            subject_type=body.subject_type,
            subject_id=body.subject_id,
            allowed=body.allowed,
            actor=ctx.user_id or "",
        )
    except ValueError as exc:
        # Defense in depth — the pydantic Literal already 422s on a bad enum,
        # but the service also guards, so translate its ValueError to a 400.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return svc.serialize_subject_allow(row)


@router.delete(
    "/large-attachment/subject-allows/{subject_type}/{subject_id}",
    operation_id="deleteLargeAttachmentSubjectAllow",
    dependencies=[Depends(require_scope(_ADMIN_SCOPE))],
)
async def delete_subject_allow(
    subject_type: str,
    subject_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
) -> dict[str, Any]:
    deleted = await svc.delete_subject_allow(
        session,
        tenant_id=ctx.tenant_id,
        subject_type=subject_type,
        subject_id=subject_id,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="subject allow not found")
    return {
        "deleted": True,
        "subject_type": subject_type,
        "subject_id": subject_id,
    }


# ── resolution (callable by services / BFF on behalf of a user) ──────────────
@router.get(
    "/large-attachment/resolve",
    operation_id="resolveLargeAttachment",
)
async def resolve(
    user_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LargeAttachmentService = Depends(large_attachment_service),
    org: OrgClient = Depends(org_client),
) -> dict[str, Any]:
    return await svc.resolve(
        session, tenant_id=ctx.tenant_id, user_id=user_id, org_client=org
    )
