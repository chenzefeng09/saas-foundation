"""FastAPI DI wiring."""
from __future__ import annotations
from collections.abc import AsyncIterator
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_search.domain.base import FoundationContext, foundation_context
from foundation_search.domain.db import session_scope
from foundation_search.errors import TENANT_CONTEXT_MISSING, FoundationError
from foundation_search.services.search_service import SearchService

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

def search_service() -> SearchService:
    from foundation_search.adapters.opensearch_client import get_opensearch_client
    from foundation_search.adapters.authz_client import get_authz_client
    return SearchService(os_client=get_opensearch_client(), authz_client=get_authz_client())
