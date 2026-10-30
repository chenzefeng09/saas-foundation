"""Helpers for the integration tier (see conftest.py for the fixtures)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import ulid
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_security_ops.domain.base import ActorKind, FoundationContext, foundation_context
from foundation_security_ops.domain.db import session_scope
from foundation_security_ops.domain.models import (
    Drill,
    Incident,
    LicenseFinding,
    Outbox,
    SbomRecord,
    SbomWatch,
    ScanRun,
    Vulnerability,
)

API = "/api/security-ops/v1"
MODELS = (ScanRun, Vulnerability, Incident, SbomRecord, SbomWatch, LicenseFinding, Drill, Outbox)


def new_request_id() -> str:
    return f"req_{ulid.new()!s}"


@asynccontextmanager
async def as_actor(actor: ActorKind) -> AsyncIterator[AsyncSession]:
    """One committed transaction through the app's own session_scope, as ``actor``."""
    token = foundation_context.set(
        FoundationContext(tenant_id="", user_id=None, actor=actor, request_id=new_request_id())
    )
    try:
        async with session_scope() as session:
            yield session
    finally:
        foundation_context.reset(token)
