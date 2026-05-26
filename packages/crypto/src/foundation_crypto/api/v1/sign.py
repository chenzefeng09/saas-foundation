"""Sign / verify endpoints."""

import base64

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.api.dependencies import (
    current_context,
    db_session,
    sign_service,
)
from foundation_crypto.domain.base import FoundationContext
from foundation_crypto.schemas.sign import (
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)
from foundation_crypto.services.sign_service import SignService

router = APIRouter()


@router.post("/sign", operation_id="signData")
async def sign(
    body: SignRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SignService = Depends(sign_service),
) -> SignResponse:
    return await svc.sign(
        session, tenant_id=ctx.tenant_id, request=body,
    )


@router.post("/verify", operation_id="verifySignature")
async def verify(
    body: VerifyRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SignService = Depends(sign_service),
) -> VerifyResponse:
    return await svc.verify(
        session, tenant_id=ctx.tenant_id, request=body,
    )
