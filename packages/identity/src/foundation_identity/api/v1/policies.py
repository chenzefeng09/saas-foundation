"""Password policy GET / PUT."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.api.dependencies import (
    current_context,
    db_session,
    password_policy_service,
)
from foundation_identity.domain.base import FoundationContext
from foundation_identity.domain.models import PasswordPolicy
from foundation_identity.schemas.policy import PasswordPolicyRead, PasswordPolicyUpdate
from foundation_identity.services.password_policy_service import PasswordPolicyService

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("/password", response_model=PasswordPolicyRead, operation_id="getPasswordPolicy")
async def get_password_policy(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: PasswordPolicyService = Depends(password_policy_service),
) -> PasswordPolicyRead:
    pol = await svc.get(session, tenant_id=ctx.tenant_id)
    return PasswordPolicyRead.model_validate(pol)


@router.put(
    "/password",
    response_model=PasswordPolicyRead,
    status_code=status.HTTP_200_OK,
    operation_id="updatePasswordPolicy",
)
async def update_password_policy(
    body: PasswordPolicyUpdate,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: PasswordPolicyService = Depends(password_policy_service),
) -> PasswordPolicyRead:
    # M1: compliance_modes hardcoded; M4 fetches from compliance-service.
    compliance_modes: list[str] = ["pipl", "equal_protection_3"]

    proposed = PasswordPolicy(
        tenant_id=ctx.tenant_id,
        **body.model_dump(),
    )
    saved = await svc.update(
        session,
        tenant_id=ctx.tenant_id,
        proposed=proposed,
        compliance_modes=compliance_modes,
    )
    return PasswordPolicyRead.model_validate(saved)
