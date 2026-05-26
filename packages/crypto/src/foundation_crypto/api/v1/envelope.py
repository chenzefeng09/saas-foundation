"""Envelope encrypt / decrypt endpoints."""

import base64

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.api.dependencies import (
    current_context,
    db_session,
    envelope_service,
)
from foundation_crypto.domain.base import FoundationContext
from foundation_crypto.schemas.envelope import (
    BatchEncryptRequest,
    BatchEncryptResponse,
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    RewrapRequest,
    RewrapResponse,
)
from foundation_crypto.services.envelope_service import EnvelopeService

router = APIRouter()


@router.post("/encrypt", operation_id="encryptData")
async def encrypt(
    body: EncryptRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: EnvelopeService = Depends(envelope_service),
) -> EncryptResponse:
    envelope = await svc.encrypt(
        session,
        tenant_id=ctx.tenant_id,
        label=body.key_label,
        plaintext=_b64d(body.plaintext_b64),
        context=body.context,
    )
    return EncryptResponse(envelope=envelope)


@router.post("/decrypt", operation_id="decryptData")
async def decrypt(
    body: DecryptRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: EnvelopeService = Depends(envelope_service),
) -> DecryptResponse:
    plaintext = await svc.decrypt(
        session,
        envelope=body.envelope,
        expected_context=body.expected_context,
    )
    return DecryptResponse(plaintext_b64=_b64e(plaintext))


@router.post("/batch-encrypt", operation_id="batchEncrypt")
async def batch_encrypt(
    body: BatchEncryptRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: EnvelopeService = Depends(envelope_service),
) -> BatchEncryptResponse:
    envelopes = []
    for item in body.items:
        env = await svc.encrypt(
            session,
            tenant_id=ctx.tenant_id,
            label=item.key_label,
            plaintext=_b64d(item.plaintext_b64),
            context=item.context,
        )
        envelopes.append(env)
    return BatchEncryptResponse(envelopes=envelopes)


@router.post("/rewrap", operation_id="rewrapData")
async def rewrap(
    body: RewrapRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: EnvelopeService = Depends(envelope_service),
) -> RewrapResponse:
    envelope = await svc.rewrap(
        session,
        envelope=body.envelope,
        target_kek_version=body.target_kek_version,
    )
    return RewrapResponse(envelope=envelope)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)
