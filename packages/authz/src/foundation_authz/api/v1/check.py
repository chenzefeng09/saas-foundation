"""/check, /check:batch, /list-accessible-ids — the hottest endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.api.dependencies import (
    check_service,
    current_context,
    db_session,
)
from foundation_authz.domain.base import FoundationContext
from foundation_authz.schemas.check import (
    BatchCheckRequest,
    BatchCheckResponse,
    CheckRequest,
    CheckResponse,
    EffectivePermissionsResponse,
    ListAccessibleIdsRequest,
    ListAccessibleIdsResponse,
)
from foundation_authz.services.check_service import CheckService

router = APIRouter(tags=["check"])


@router.get(
    "/my-permissions",
    response_model=EffectivePermissionsResponse,
    operation_id="myEffectivePermissions",
)
async def my_permissions(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: CheckService = Depends(check_service),
) -> EffectivePermissionsResponse:
    """Return the caller's own effective permission set for the current tenant.

    Reads ``ctx.tenant_id`` / ``ctx.user_id`` from the request context and
    flattens the caller's active, in-tenant role bindings (inheritance + wildcards
    expanded) via ``CheckService.effective_permissions``.  This is a self-read of
    one's own grants, so it carries no ``require_permission`` guard — any
    authenticated principal may inspect what they themselves hold.

    An unauthenticated context (``ctx.user_id is None``) returns an empty list
    with 200 rather than 401, so the BFF/SPA can treat "no permissions" uniformly
    without special-casing the anonymous path.
    """
    if ctx.user_id is None:
        return EffectivePermissionsResponse(permissions=[])
    perms = await svc.effective_permissions(
        session, tenant_id=ctx.tenant_id, user_id=ctx.user_id
    )
    return EffectivePermissionsResponse(permissions=sorted(perms))


@router.post("/check", response_model=CheckResponse, operation_id="checkPermission")
async def check_permission(
    body: CheckRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: CheckService = Depends(check_service),
) -> CheckResponse:
    return await svc.check(
        session,
        tenant_id=ctx.tenant_id,
        user_id=body.user_id,
        action=body.action,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        context=body.context,
    )


@router.post(
    "/check:batch",
    response_model=BatchCheckResponse,
    operation_id="batchCheckPermission",
)
async def batch_check(
    body: BatchCheckRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: CheckService = Depends(check_service),
) -> BatchCheckResponse:
    results: list[CheckResponse] = []
    for c in body.checks:
        results.append(
            await svc.check(
                session,
                tenant_id=ctx.tenant_id,
                user_id=c.user_id,
                action=c.action,
                resource_type=c.resource_type,
                resource_id=c.resource_id,
                context=c.context,
            )
        )
    return BatchCheckResponse(results=results)


@router.post(
    "/list-accessible-ids",
    response_model=ListAccessibleIdsResponse,
    operation_id="listAccessibleIds",
)
async def list_accessible_ids(
    body: ListAccessibleIdsRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: CheckService = Depends(check_service),
) -> ListAccessibleIdsResponse:
    """Return the set of scope IDs the requesting user may access.

    When the user holds a TENANT- or GLOBAL_SYSTEM-scoped role that grants the
    requested action, `all_in_tenant=True` is returned (ids=[], complete=True),
    meaning the caller should apply no RBAC ACL filter.  It does not waive the
    mandatory clearance-vs-sensitivity check.

    When the result is truncated to `max`, `complete=False` signals that the
    caller must fall back to a per-resource permission check.

    This API intentionally returns `clearance_filtered=False`: sensitivity is a
    per-resource DLP attribute and is not resolved during scope enumeration.
    Callers must run `/check` (or an equivalent trusted DLP filter) before
    returning each resource.
    """
    return await svc.list_accessible_ids(
        session,
        tenant_id=ctx.tenant_id,
        user_id=body.user_id,
        resource_type=body.resource_type,
        action=body.action,
        max=body.max,
    )
