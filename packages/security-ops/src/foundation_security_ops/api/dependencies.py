"""FastAPI DI wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_security_ops.domain.db import session_scope
from foundation_security_ops.services.security_ops_service import SecurityOpsService


def current_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


def security_ops_service() -> SecurityOpsService:
    return SecurityOpsService()
