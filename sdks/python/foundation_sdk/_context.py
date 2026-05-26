"""Tenant / user / request context propagation for the Foundation SDK."""

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
    ctx = _context_var.get()
    if ctx is None:
        raise RuntimeError(
            "No FoundationContext active. Wrap call in `with tenant_context(...)` "
            "or ensure request middleware populated context."
        )
    return ctx


@contextmanager
def tenant_context(
    tenant_id: str,
    *,
    user_id: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    locale: str = "zh-CN",
) -> Iterator[FoundationContext]:
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
