"""FastAPI dependency-injection wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.adapters.key_provider import KeyProvider
from foundation_crypto.adapters.vault_provider import VaultKeyProvider
from foundation_crypto.adapters.local_test_provider import LocalTestKeyProvider
from foundation_crypto.config import get_settings
from foundation_crypto.domain.base import FoundationContext, foundation_context
from foundation_crypto.domain.db import session_scope
from foundation_crypto.services.envelope_service import EnvelopeService
from foundation_crypto.services.kek_service import KekService
from foundation_crypto.services.sign_service import SignService
from foundation_crypto.services.password_service import PasswordService


def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None:
        raise HTTPException(status_code=401, detail="Tenant context missing")
    return ctx


def current_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


def key_provider() -> KeyProvider:
    settings = get_settings()
    if settings.crypto_provider == "local_test":
        return LocalTestKeyProvider()
    return VaultKeyProvider()


def envelope_service(kp: KeyProvider = Depends(key_provider)) -> EnvelopeService:
    return EnvelopeService(key_provider=kp)


def kek_service(kp: KeyProvider = Depends(key_provider)) -> KekService:
    return KekService(key_provider=kp)


def sign_service(kp: KeyProvider = Depends(key_provider)) -> SignService:
    return SignService(key_provider=kp)


def password_service() -> PasswordService:
    return PasswordService()
