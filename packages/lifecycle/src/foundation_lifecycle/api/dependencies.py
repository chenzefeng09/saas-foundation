"""FastAPI DI wiring."""

from __future__ import annotations
from collections.abc import AsyncIterator, Callable
from datetime import timedelta

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.adapters.org_client import OrgClient
from foundation_lifecycle.config import get_settings
from foundation_lifecycle.domain.base import FoundationContext, foundation_context
from foundation_lifecycle.domain.db import admin_session_scope, session_scope
from foundation_lifecycle.errors import (
    INSUFFICIENT_SCOPE,
    PERMISSION_DENIED,
    TENANT_CONTEXT_MISSING,
    FoundationError,
)
from foundation_lifecycle.services.approval_service import ApprovalService
from foundation_lifecycle.services.large_attachment_service import LargeAttachmentService
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.legal_hold_service import LegalHoldService
from foundation_lifecycle.services.storage_quota_service import StorageQuotaService
from foundation_lifecycle.services.storage_report_service import StorageReportService

def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None: raise FoundationError(TENANT_CONTEXT_MISSING)
    return ctx

def current_user_id(ctx: FoundationContext = Depends(current_context)) -> str:
    """The user the request is authenticated as: who acted, for routes that record it.

    The gateway sets ``X-User-Id`` from the verified token (CONVENTIONS §3.2); a
    ``*_by`` field in a body only says whom the client names. A request without a
    user (a service-account token) is refused instead of being recorded as nobody.
    """
    if not ctx.user_id:
        raise FoundationError(PERMISSION_DENIED,
                              detail="A user must perform this action; X-User-Id is missing.")
    return ctx.user_id

def current_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")

async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session: yield session


async def admin_db_session() -> AsyncIterator[AsyncSession]:
    """Cross-tenant app_admin session for Phase 7 platform-admin endpoints.

    Combine with ``Depends(require_scope("storage.admin"))`` — the scope check
    fences who can reach this handler and the admin session activates the
    ``admin_all`` RLS policies for the ADMIN actor.
    """
    async with admin_session_scope() as session:
        yield session

def lifecycle_service() -> LifecycleService: return LifecycleService()

def legal_hold_service() -> LegalHoldService: return LegalHoldService()

def approval_service(
    lifecycle: LifecycleService = Depends(lifecycle_service),
    holds: LegalHoldService = Depends(legal_hold_service),
) -> ApprovalService:
    """Carries out an approved operation through the same services the other routes use."""
    return ApprovalService(lifecycle=lifecycle, holds=holds,
                           window=timedelta(minutes=get_settings().approval_window_minutes))

def storage_quota_service() -> StorageQuotaService: return StorageQuotaService()

def storage_report_service() -> StorageReportService: return StorageReportService()

def large_attachment_service() -> LargeAttachmentService: return LargeAttachmentService()

def org_client() -> OrgClient:
    """Org reverse-lookup client for large-attachment subject resolve.

    Built fresh per request from ``settings.org_url``; the resolve route injects
    it into ``LargeAttachmentService.resolve(..., org_client=...)``.
    """
    return OrgClient(get_settings().org_url)


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
            raise FoundationError(INSUFFICIENT_SCOPE, detail=f"Missing required scope: {scope}",
                                  extra={"required_scope": scope})
    return _dep
