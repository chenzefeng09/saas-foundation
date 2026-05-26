"""Async SQLAlchemy engine + session factory with RLS context."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from foundation_authz.config import get_settings
from foundation_authz.domain.base import FoundationContext, foundation_context
from foundation_authz.observability import get_logger

log = get_logger(__name__)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _random_stmt_name() -> str:
    """Unique prepared statement names per call — required for PgBouncer
    transaction mode (otherwise pooled backends collide)."""
    return f"__asyncpg_{uuid.uuid4().hex[:12]}__"


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            str(settings.db_dsn),
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout_seconds,
            pool_pre_ping=True,
            echo=settings.db_echo,
            connect_args={
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
                "prepared_statement_name_func": _random_stmt_name,
            },
            execution_options={"compiled_cache": None},
        )
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
            autoflush=False,
        )
    return _sessionmaker


def _assert_safe(value: str) -> None:
    if not value:
        raise RuntimeError("RLS context value cannot be empty")
    for ch in value:
        if not (ch.isalnum() or ch in "_-"):
            raise RuntimeError(f"RLS context value contains unsafe char: {value!r}")


async def _apply_rls_context(session: AsyncSession, ctx: FoundationContext) -> None:
    _assert_safe(ctx.tenant_id)
    if ctx.user_id is not None:
        _assert_safe(ctx.user_id)
    _assert_safe(ctx.actor)
    await session.execute(text(f"SET LOCAL app.tenant_id = '{ctx.tenant_id}'"))
    await session.execute(text(f"SET LOCAL app.user_id = '{ctx.user_id or ''}'"))
    await session.execute(text(f"SET LOCAL app.actor = '{ctx.actor}'"))


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    settings = get_settings()
    ctx = foundation_context.get()
    if ctx is None and settings.require_tenant_context:
        raise RuntimeError(
            "FoundationContext missing — middleware did not run or this code path "
            "is invoked outside an HTTP request."
        )

    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            if ctx is not None:
                await _apply_rls_context(session, ctx)
            yield session


@asynccontextmanager
async def system_session_scope() -> AsyncIterator[AsyncSession]:
    """For background jobs: actor=SYSTEM, no tenant filter."""
    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            await session.execute(text("SET LOCAL app.actor = 'SYSTEM'"))
            await session.execute(text("SET LOCAL app.tenant_id = ''"))
            await session.execute(text("SET LOCAL app.user_id = ''"))
            yield session


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
