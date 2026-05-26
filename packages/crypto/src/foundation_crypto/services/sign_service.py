"""Signature / verification service (crypto-v1 §6.2).

Supports:
  - Detached signature (default): sign(data) → signature; verify(data, sig) → bool.
  - Prehash mode: caller hashes input before calling sign/verify.
  - Algorithm selection based on KEK type (Ed25519 / ECDSA-P256 / SM2 / RSA).

Used by: audit hash chain, destruction certificate signing, OPA bundle signing.
"""

from __future__ import annotations

import base64
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.adapters.key_provider import KeyProvider
from foundation_crypto.domain.models import KEK
from foundation_crypto.errors import KEK_NOT_FOUND, FoundationError
from foundation_crypto.observability import get_logger
from foundation_crypto.schemas.sign import (
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)

log = get_logger(__name__)


class SignService:
    """Orchestrate sign / verify over a KeyProvider."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._kp = key_provider

    async def sign(
        self, session: AsyncSession, *, tenant_id: str, request: SignRequest,
    ) -> SignResponse:
        kek = await self._resolve_kek(session, tenant_id, request.key_label)
        data = _b64d(request.data_b64)
        bundle = await self._kp.sign(
            vault_path=kek.vault_path,
            data=data,
            prehashed=not request.prehash,
        )
        return SignResponse(
            algorithm=bundle.algorithm,
            kek_id=kek.id,
            kek_version=bundle.kek_version,
            signature_b64=_b64e(bundle.signature),
        )

    async def verify(
        self, session: AsyncSession, *, tenant_id: str, request: VerifyRequest,
    ) -> VerifyResponse:
        kek = await self._resolve_kek(session, tenant_id, request.key_label)
        data = _b64d(request.data_b64)
        signature = _b64d(request.signature_b64)
        valid = await self._kp.verify(
            vault_path=kek.vault_path,
            data=data,
            signature=signature,
            prehashed=not request.prehash,
            kek_version=request.kek_version,
        )
        return VerifyResponse(
            valid=valid,
            algorithm=kek.algorithm_id,
            kek_id=kek.id,
            kek_version=request.kek_version or kek.current_version,
        )

    async def _resolve_kek(
        self, session: AsyncSession, tenant_id: str, label: str,
    ) -> KEK:
        from sqlalchemy import select
        stmt = select(KEK).where(
            KEK.tenant_id == tenant_id,
            KEK.label == label,
            KEK.status != "DESTROYED",
        ).limit(1)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            raise FoundationError(KEK_NOT_FOUND, detail=f"KEK '{label}' not found")
        return row


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)
