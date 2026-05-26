"""Tenant / user / request context propagation.

Per CONVENTIONS.md §3 — SDK reads from contextvars set by upstream middleware
(or business code's explicit `with tenant_context(...)`). SDK never accepts
tenant_id as an explicit parameter to public methods.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Iterator


@dataclass(frozen=True, slots=True)
class FoundationContext:
    """Per-request context carried via contextvars."""

    tenant_id: str
    user_id: str | None = None
    request_id: str = field(default_factory=lambda: f"req_{uuid.uuid4().hex[:26].upper()}")
    trace_id: str | None = None
    locale: str = "zh-CN"


_context_var: ContextVar[FoundationContext | None] = ContextVar(
    "foundation.context", default=None
)


def current_context() -> FoundationContext:
    """Get current context or raise if missing.

    Raises:
        RuntimeError: if no context is active. Business code must always run
            inside a tenant_context() block or under a request whose middleware
            populated context.
    """
    ctx = _context_var.get()
    if ctx is None:
        raise RuntimeError(
            "No FoundationContext active. Wrap call in `with tenant_context(...)` "
            "or ensure request middleware populated context."
        )
    return ctx


def current_context_or_none() -> FoundationContext | None:
    """Get current context without raising. For internal use only."""
    return _context_var.get()


@contextmanager
def tenant_context(
    tenant_id: str,
    *,
    user_id: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    locale: str = "zh-CN",
) -> Iterator[FoundationContext]:
    """Push a FoundationContext for the duration of the block.

    Usage:
        with tenant_context("tnt_01J..."):
            user = client.users.get("usr_01J...")

    Nested calls are allowed; inner context fully replaces outer.
    """
    ctx = FoundationContext(
        tenant_id=tenant_id,
        user_id=user_id,
        request_id=request_id or f"req_{uuid.uuid4().hex[:26].upper()}",
        trace_id=trace_id,
        locale=locale,
    )
    token = _context_var.set(ctx)
    try:
        yield ctx
    finally:
        _context_var.reset(token)


@contextmanager
def as_tenant(tenant_id: str) -> Iterator[FoundationContext]:
    """Explicit cross-tenant operation. AUDITED.

    Business code is forbidden from calling this casually. Used only by
    platform-level workers (e.g., billing rollups, compliance scans) with
    documented justification.
    """
    # TODO: emit audit event "foundation.sdk.cross_tenant_invocation"
    with tenant_context(tenant_id=tenant_id, user_id="SYSTEM") as ctx:
        yield ctx
