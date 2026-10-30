"""Role binding endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.api.dependencies import (
    binding_service,
    check_service,
    current_context,
    db_session,
    require_permission,
)
from foundation_authz.domain.base import FoundationContext
from foundation_authz.errors import PERMISSION_DENIED, FoundationError
from foundation_authz.schemas.binding import (
    BINDING_STATUSES,
    DEFAULT_LIST_STATUSES,
    BindingStatus,
    CreateBindingRequest,
    RoleBindingRead,
)
from foundation_authz.schemas.common import CursorPage
from foundation_authz.services.binding_service import BindingService
from foundation_authz.services.check_service import CheckService

router = APIRouter(prefix="/bindings", tags=["bindings"])

# filter.status follows the list-filter convention (comma-separated values).
_STATUS_ALTERNATION = "|".join(BINDING_STATUSES)
_STATUS_FILTER_PATTERN = rf"^({_STATUS_ALTERNATION})(,({_STATUS_ALTERNATION}))*$"


def _parse_status_filter(raw: str | None) -> frozenset[BindingStatus]:
    if raw is None:
        return DEFAULT_LIST_STATUSES
    # The Query pattern has already rejected anything outside BINDING_STATUSES.
    return frozenset(s for s in BINDING_STATUSES if s in raw.split(","))


@router.get("", response_model=CursorPage[RoleBindingRead], operation_id="listBindings")
async def list_bindings(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    principal_kind: str | None = Query(default=None, alias="filter.principal_kind"),
    principal_id: str | None = Query(default=None, alias="filter.principal_id"),
    role_id: str | None = Query(default=None, alias="filter.role_id"),
    status_filter: str | None = Query(
        default=None,
        alias="filter.status",
        pattern=_STATUS_FILTER_PATTERN,
        description=(
            "Comma-separated binding states to return: ACTIVE, EXPIRED, REVOKED. "
            "Defaults to ACTIVE; revoked bindings are only listed when REVOKED is "
            "requested explicitly."
        ),
    ),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BindingService = Depends(binding_service),
) -> CursorPage[RoleBindingRead]:
    rows, next_cursor = await svc.list(
        session,
        tenant_id=ctx.tenant_id,
        cursor=cursor,
        limit=limit,
        principal_kind=principal_kind,
        principal_id=principal_id,
        role_id=role_id,
        statuses=_parse_status_filter(status_filter),
    )
    return CursorPage[RoleBindingRead](
        items=[RoleBindingRead.model_validate(r) for r in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "",
    response_model=RoleBindingRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="createBinding",
    dependencies=[Depends(require_permission("authz.binding.manage"))],
)
async def create_binding(
    body: CreateBindingRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BindingService = Depends(binding_service),
    check_svc: CheckService = Depends(check_service),
) -> RoleBindingRead:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    actor_perms = await check_svc.effective_permissions(
        session, tenant_id=ctx.tenant_id, user_id=ctx.user_id
    )
    b = await svc.create(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        actor_perms=actor_perms,
        check_svc=check_svc,
        principal_kind=body.principal_kind,
        principal_id=body.principal_id,
        role_id=body.role_id,
        scope_kind=body.scope_kind,
        scope_id=body.scope_id,
        expires_at=body.expires_at,
        grant_reason=body.grant_reason,
    )
    return RoleBindingRead.model_validate(b)


@router.delete(
    "/{binding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteBinding",
    response_class=Response,
    dependencies=[Depends(require_permission("authz.binding.manage"))],
)
async def revoke_binding(
    binding_id: str = Path(pattern=r"^rbd_[0-9A-Z]{26}$"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BindingService = Depends(binding_service),
) -> Response:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    await svc.revoke(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        binding_id=binding_id,
        reason="API revoke",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
