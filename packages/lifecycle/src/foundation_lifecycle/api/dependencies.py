"""FastAPI DI wiring."""

from __future__ import annotations
from collections.abc import AsyncIterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.base import FoundationContext, foundation_context
from foundation_lifecycle.domain.db import session_scope
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.legal_hold_service import LegalHoldService

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
