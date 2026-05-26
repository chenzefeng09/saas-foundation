"""Async SQLAlchemy engine + session factory."""

from __future__ import annotations
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from foundation_dlp.config import get_settings
from foundation_dlp.domain.base import FoundationContext, foundation_context

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None

def _random_stmt_name() -> str: return f"__asyncpg_{uuid.uuid4().hex[:12]}__"

def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        s = get_settings()
        _engine = create_async_engine(str(s.db_dsn), pool_size=s.db_pool_size, max_overflow=s.db_max_overflow,
            pool_pre_ping=True, echo=False, connect_args={"statement_cache_size": 0, "prepared_statement_cache_size": 0,
            "prepared_statement_name_func": _random_stmt_name})
    return _engine

def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(bind=get_engine(), expire_on_commit=False, class_=AsyncSession, autoflush=False)
    return _sessionmaker

@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    s = get_settings(); ctx = foundation_context.get()
    if ctx is None and s.require_tenant_context: raise RuntimeError("FoundationContext missing")
    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            if ctx is not None:
                await session.execute(text(f"SET LOCAL app.tenant_id = '{ctx.tenant_id}'"))
                await session.execute(text(f"SET LOCAL app.user_id = '{ctx.user_id or ''}'"))
                await session.execute(text(f"SET LOCAL app.actor = '{ctx.actor}'"))
            yield session

async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None: await _engine.dispose(); _engine = None; _sessionmaker = None
