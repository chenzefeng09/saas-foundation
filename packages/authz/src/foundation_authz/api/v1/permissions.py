"""Permission catalogue."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.api.dependencies import (
    current_context,
    db_session,
    permission_registry,
)
from foundation_authz.domain.base import FoundationContext
from foundation_authz.schemas.permission import PermissionRead
from foundation_authz.services.permission_registry import PermissionRegistry

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.get("", response_model=list[PermissionRead], operation_id="listPermissions")
async def list_permissions(
    service_filter: str | None = Query(default=None, alias="filter.service"),
    ctx: FoundationContext = Depends(current_context),  # noqa: ARG001 — for auth
    session: AsyncSession = Depends(db_session),
    svc: PermissionRegistry = Depends(permission_registry),
) -> list[PermissionRead]:
    perms = await svc.list_all(session, service=service_filter)
    return [PermissionRead.model_validate(p) for p in perms]
