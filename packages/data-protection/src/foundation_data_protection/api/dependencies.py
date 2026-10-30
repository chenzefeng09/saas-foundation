"""FastAPI DI wiring."""
from __future__ import annotations
from collections.abc import AsyncIterator
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_data_protection.domain.base import FoundationContext, foundation_context
from foundation_data_protection.domain.db import session_scope
from foundation_data_protection.errors import TENANT_CONTEXT_MISSING, FoundationError
from foundation_data_protection.services.data_protection_service import DataProtectionService
from foundation_data_protection.services.masking_engine import MaskingEngine

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

def data_protection_service() -> DataProtectionService:
    return DataProtectionService()

def masking_engine() -> MaskingEngine:
    return MaskingEngine()
