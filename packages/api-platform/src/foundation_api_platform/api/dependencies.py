"""FastAPI DI wiring."""
from __future__ import annotations
from collections.abc import AsyncIterator
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_api_platform.domain.base import FoundationContext, foundation_context
from foundation_api_platform.domain.db import session_scope
from foundation_api_platform.errors import TENANT_CONTEXT_MISSING, FoundationError
from foundation_api_platform.services.api_platform_service import APIPlatformService

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

def api_platform_service() -> APIPlatformService:
    return APIPlatformService()
