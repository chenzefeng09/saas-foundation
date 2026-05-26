"""User membership + transfer + secondary OU endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_org.api.dependencies import (
    current_context,
    db_session,
    membership_service,
)
from foundation_org.domain.base import FoundationContext
from foundation_org.errors import PERMISSION_DENIED, FoundationError
from foundation_org.schemas.common import USER_ID_PATTERN
from foundation_org.schemas.membership import (
    CreateSecondaryAssignmentRequest,
    SecondaryAssignmentRead,
    TransferUserRequest,
    UpsertUserMembershipRequest,
    UserMembershipRead,
)
from foundation_org.services.membership_service import MembershipService

router = APIRouter(prefix="/users", tags=["memberships"])


def _require_actor(ctx: FoundationContext) -> str:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    return ctx.user_id


@router.get(
    "/{user_id}/membership",
    response_model=UserMembershipRead,
    operation_id="getUserMembership",
)
async def get_membership(
    user_id: str = Path(pattern=USER_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MembershipService = Depends(membership_service),
) -> UserMembershipRead:
    return UserMembershipRead.model_validate(
        await svc.get(session, tenant_id=ctx.tenant_id, user_id=user_id)
    )


@router.put(
    "/{user_id}/membership",
    response_model=UserMembershipRead,
    operation_id="upsertUserMembership",
)
async def upsert_membership(
    user_id: str = Path(pattern=USER_ID_PATTERN),
    body: UpsertUserMembershipRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MembershipService = Depends(membership_service),
) -> UserMembershipRead:
    actor_id = _require_actor(ctx)
    m = await svc.upsert(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        user_id=user_id,
        primary_org_unit_id=body.primary_org_unit_id,
        job_title=body.job_title,
        employee_no=body.employee_no,
        join_date=body.join_date,
        manager_user_id=body.manager_user_id,
        employment_kind=body.employment_kind,
        metadata=body.metadata,
    )
    return UserMembershipRead.model_validate(m)


@router.post(
    "/{user_id}/transfer",
    response_model=UserMembershipRead,
    operation_id="transferUser",
)
async def transfer_user(
    user_id: str = Path(pattern=USER_ID_PATTERN),
    body: TransferUserRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MembershipService = Depends(membership_service),
) -> UserMembershipRead:
    actor_id = _require_actor(ctx)
    m = await svc.transfer(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        user_id=user_id,
        to_org_unit_id=body.to_org_unit_id,
        to_team_ids=body.to_team_ids,
        effective_date=body.effective_date,
        reason=body.reason,
    )
    return UserMembershipRead.model_validate(m)


@router.get(
    "/{user_id}/secondary-org-units",
    response_model=list[SecondaryAssignmentRead],
    operation_id="listSecondaryAssignments",
)
async def list_secondary(
    user_id: str = Path(pattern=USER_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MembershipService = Depends(membership_service),
) -> list[SecondaryAssignmentRead]:
    rows = await svc.list_secondary(
        session, tenant_id=ctx.tenant_id, user_id=user_id
    )
    return [SecondaryAssignmentRead.model_validate(r) for r in rows]


@router.post(
    "/{user_id}/secondary-org-units",
    response_model=SecondaryAssignmentRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="addSecondaryAssignment",
)
async def add_secondary(
    user_id: str = Path(pattern=USER_ID_PATTERN),
    body: CreateSecondaryAssignmentRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MembershipService = Depends(membership_service),
) -> SecondaryAssignmentRead:
    actor_id = _require_actor(ctx)
    row = await svc.add_secondary(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        user_id=user_id,
        org_unit_id=body.org_unit_id,
        reason=body.reason,
        valid_until=body.valid_until,
    )
    return SecondaryAssignmentRead.model_validate(row)
