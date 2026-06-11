"""FastAPI DI wiring."""

from __future__ import annotations
from collections.abc import AsyncIterator, Callable

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.base import FoundationContext, foundation_context
from foundation_lifecycle.domain.db import session_scope
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.legal_hold_service import LegalHoldService
from foundation_lifecycle.services.storage_quota_service import StorageQuotaService

def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None: raise HTTPException(status_code=401, detail="Tenant context missing")
    return ctx

def current_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")

async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session: yield session

def lifecycle_service() -> LifecycleService: return LifecycleService()

def legal_hold_service() -> LegalHoldService: return LegalHoldService()

def storage_quota_service() -> StorageQuotaService: return StorageQuotaService()


# ---------------------------------------------------------------------------
# Scope check — Phase 3 self-built dep (storage-v1 §10.1). FoundationContext
# does not yet carry a ``scopes`` field; until identity threads them through,
# scopes come from the ``X-Foundation-Scopes`` header (space-separated).
# TODO(identity): replace header parsing with ``FoundationContext.scopes`` once
# identity wires the claim into the request context.
# ---------------------------------------------------------------------------
_SCOPES_HEADER = "X-Foundation-Scopes"


def _request_scopes(request: Request) -> frozenset[str]:
    raw = request.headers.get(_SCOPES_HEADER, "")
    return frozenset(s for s in raw.split() if s)


def require_scope(scope: str) -> Callable[[Request], None]:
    """Return a FastAPI dep that 403s when ``scope`` is missing from the actor."""
    def _dep(request: Request) -> None:
        if scope not in _request_scopes(request):
            raise HTTPException(status_code=403, detail=f"missing scope: {scope}")
    return _dep
