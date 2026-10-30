"""FastAPI DI wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_dlp.config import get_settings
from foundation_dlp.domain.base import FoundationContext, foundation_context
from foundation_dlp.domain.db import session_scope
from foundation_dlp.domain.models import SensitivityLevel
from foundation_dlp.errors import (
    CLEARANCE_UNAVAILABLE,
    DLP_DENIED,
    IDENTITY_CONTEXT_MISSING,
    TENANT_CONTEXT_MISSING,
    FoundationError,
)
from foundation_dlp.services.clearance_provider import (
    ClearanceProvider,
    ClearanceProviderError,
    IdentityClearanceProvider,
)
from foundation_dlp.services.dlp_service import DLPService

_LEVELS = frozenset({"L1", "L2", "L3", "L4", "L5"})


def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None:
        raise FoundationError(TENANT_CONTEXT_MISSING)
    return ctx


def current_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


def dlp_service() -> DLPService:
    return DLPService(default_sensitivity=get_settings().unclassified_sensitivity)


def clearance_provider() -> ClearanceProvider:
    """Return the authoritative identity-backed provider (overrideable in tests)."""
    return IdentityClearanceProvider()


@dataclass(frozen=True, slots=True)
class TrustedUserClearance:
    user_id: str
    clearance: SensitivityLevel


async def trusted_user_clearance(
    ctx: FoundationContext = Depends(current_context),
    provider: ClearanceProvider = Depends(clearance_provider),
    request_id: str = Depends(current_request_id),
) -> TrustedUserClearance:
    """Resolve the context user and their clearance, failing closed on any error."""
    if not ctx.user_id:
        raise FoundationError(IDENTITY_CONTEXT_MISSING)
    try:
        clearance = await provider.get_clearance(
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            request_id=request_id,
        )
    except ClearanceProviderError as exc:
        raise FoundationError(CLEARANCE_UNAVAILABLE) from exc
    if clearance not in _LEVELS:
        # Defend the policy boundary even when a custom provider implementation
        # violates its type contract.
        raise FoundationError(
            CLEARANCE_UNAVAILABLE,
            detail="The clearance authority returned an invalid L1-L5 value; access is denied.",
        )
    return TrustedUserClearance(user_id=ctx.user_id, clearance=clearance)


#: Actors trusted to administer classification labels and DLP rules.
MANAGEMENT_ACTORS = frozenset({"SERVICE", "ADMIN"})


def is_management_actor(ctx: FoundationContext) -> bool:
    """Whether ``ctx`` may write classification labels / DLP rules."""
    return ctx.actor in MANAGEMENT_ACTORS


def require_management_actor(
    ctx: FoundationContext = Depends(current_context),
) -> FoundationContext:
    """Restrict classification/rule administration to trusted platform actors."""
    if not is_management_actor(ctx):
        raise FoundationError(
            DLP_DENIED,
            detail="Classification and DLP-rule management requires SERVICE or ADMIN authority.",
        )
    return ctx
