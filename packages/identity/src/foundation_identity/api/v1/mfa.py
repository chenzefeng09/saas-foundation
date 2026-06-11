"""MFA (TOTP enroll / verify) endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.api.dependencies import current_context, db_session, mfa_service
from foundation_identity.domain.base import FoundationContext
from foundation_identity.schemas.mfa import (
    MfaChallengeResponse,
    MfaConfirmRequest,
    MfaEnrollResponse,
    MfaMethodRead,
    MfaVerifyRequest,
    SmsEnrollRequest,
    WebAuthnCredentialRead,
    WebAuthnRegisterRequest,
)
from foundation_identity.services.mfa_service import MfaService

router = APIRouter(prefix="/mfa", tags=["mfa"])


@router.get(
    "/methods",
    response_model=list[MfaMethodRead],
    operation_id="listMfaMethods",
)
async def list_mfa_methods(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> list[MfaMethodRead]:
    """List active MFA methods for the current user."""
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    return await svc.list_methods(session, tenant_id=ctx.tenant_id, user_id=ctx.user_id)


@router.post(
    "/enroll",
    response_model=MfaEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="enrollMfa",
)
async def enroll_mfa(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> MfaEnrollResponse:
    """Begin TOTP enrollment — returns secret + QR URL."""
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    return await svc.enroll(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        request_id=ctx.request_id,
    )


@router.post(
    "/enroll/confirm",
    response_model=MfaMethodRead,
    operation_id="confirmMfaEnrollment",
)
async def confirm_mfa_enrollment(
    body: MfaConfirmRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> MfaMethodRead:
    """Confirm TOTP enrollment with the first code from the authenticator app."""
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    return await svc.confirm_enrollment(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        request_id=ctx.request_id,
        enrollment_id=body.enrollment_id,
        code=body.code,
    )


@router.delete(
    "/methods/{method_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteMfaMethod",
    response_class=Response,
)
async def delete_mfa_method(
    method_id: str = Path(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> Response:
    """Disable (soft-delete) a MFA method."""
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    await svc.delete_method(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        request_id=ctx.request_id,
        method_id=method_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/challenge",
    response_model=MfaChallengeResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="beginMfaChallenge",
)
async def begin_mfa_challenge(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> MfaChallengeResponse:
    """Begin a MFA verification challenge (step-up auth)."""
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    return await svc.begin_challenge(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
    )


@router.post(
    "/challenge/verify",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="verifyMfaChallenge",
    response_class=Response,
)
async def verify_mfa_challenge(
    body: MfaVerifyRequest = Body(...),
    svc: MfaService = Depends(mfa_service),
) -> Response:
    """Verify a MFA challenge code."""
    await svc.verify_challenge(challenge_id=body.challenge_id, code=body.code)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── WebAuthn (delegated to Keycloak) ───────────────────────────────────────── #


@router.get(
    "/webauthn/credentials",
    response_model=list[WebAuthnCredentialRead],
    operation_id="listWebAuthnCredentials",
    summary="List the user's WebAuthn keys registered at Keycloak",
)
async def list_webauthn_credentials(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> list[WebAuthnCredentialRead]:
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    items = await svc.list_webauthn_credentials(
        session, tenant_id=ctx.tenant_id, user_id=ctx.user_id
    )
    return [WebAuthnCredentialRead(**i) for i in items]


@router.post(
    "/webauthn/register",
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="triggerWebAuthnRegister",
    response_class=Response,
    summary="Email a Keycloak required-action link to enrol a WebAuthn key",
)
async def trigger_webauthn_register(
    body: WebAuthnRegisterRequest = Body(default=WebAuthnRegisterRequest()),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> Response:
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    await svc.trigger_webauthn_register(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        request_id=ctx.request_id,
        passwordless=body.passwordless,
    )
    return Response(status_code=status.HTTP_202_ACCEPTED)


@router.delete(
    "/webauthn/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteWebAuthnCredential",
    response_class=Response,
    summary="Remove one WebAuthn key (revoke an authenticator)",
)
async def delete_webauthn_credential(
    credential_id: str = Path(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> Response:
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    await svc.delete_webauthn_credential(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        request_id=ctx.request_id,
        credential_id=credential_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── SMS OTP ─────────────────────────────────────────────────────────────── #


@router.post(
    "/sms/enroll",
    response_model=MfaMethodRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="enrollSmsMfa",
    summary="Register a phone number for SMS-OTP delivery",
)
async def enroll_sms_mfa(
    body: SmsEnrollRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: MfaService = Depends(mfa_service),
) -> MfaMethodRead:
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="user_id required")
    return await svc.enroll_sms(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        request_id=ctx.request_id,
        phone=body.phone,
        label=body.label,
    )
