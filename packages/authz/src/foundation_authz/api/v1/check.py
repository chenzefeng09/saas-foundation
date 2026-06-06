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
    ListAccessibleIdsRequest,
    ListAccessibleIdsResponse,
)
from foundation_authz.services.check_service import CheckService

router = APIRouter(tags=["check"])


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
    meaning the caller should apply no ACL filter.

    When the result is truncated to `max`, `complete=False` signals that the
    caller must fall back to a per-resource permission check.
    """
    return await svc.list_accessible_ids(
        session,
        tenant_id=ctx.tenant_id,
        user_id=body.user_id,
        resource_type=body.resource_type,
        action=body.action,
        max=body.max,
    )
