"""Password hash / verify endpoints."""

from fastapi import APIRouter, Depends

from foundation_crypto.api.dependencies import password_service
from foundation_crypto.schemas.password import (
    PasswordHashRequest,
    PasswordHashResponse,
    PasswordVerifyRequest,
    PasswordVerifyResponse,
)
from foundation_crypto.services.password_service import PasswordService

router = APIRouter()


@router.post("/password-hash", operation_id="hashPassword")
async def hash_password(
    body: PasswordHashRequest,
    svc: PasswordService = Depends(password_service),
) -> PasswordHashResponse:
    return svc.hash(body)


@router.post("/password-verify", operation_id="verifyPassword")
async def verify_password(
    body: PasswordVerifyRequest,
    svc: PasswordService = Depends(password_service),
) -> PasswordVerifyResponse:
    return svc.verify(body)
