"""Async SQLAlchemy engine + session factory with RLS context."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from foundation_lifecycle.config import get_settings
from foundation_lifecycle.domain.base import FoundationContext, foundation_context

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None
# Separate app_admin engine for Phase 7 cross-tenant endpoints. app_admin is
# NOBYPASSRLS but is granted by the admin_all policies added in migration 0003,
# which activate when ``app.actor = 'ADMIN'`` is set inside the transaction.
_admin_engine: AsyncEngine | None = None
_admin_sessionmaker: async_sessionmaker[AsyncSession] | None = None


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


def get_admin_engine() -> AsyncEngine:
    """Lazy app_admin engine — Phase 7 cross-tenant admin endpoints."""
    global _admin_engine
    if _admin_engine is None:
        s = get_settings()
        _admin_engine = create_async_engine(
            str(s.db_dsn_admin),
            pool_size=s.db_pool_size,
            max_overflow=s.db_max_overflow,
            pool_pre_ping=True,
            echo=False,
            connect_args={
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
                "prepared_statement_name_func": _random_stmt_name,
            },
        )
    return _admin_engine


def get_admin_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _admin_sessionmaker
    if _admin_sessionmaker is None:
        _admin_sessionmaker = async_sessionmaker(
            bind=get_admin_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
            autoflush=False,
        )
    return _admin_sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    s = get_settings(); ctx = foundation_context.get()
    if ctx is None and s.require_tenant_context: raise RuntimeError("FoundationContext missing")
    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            if ctx is not None:
                await session.execute(text(f"SET LOCAL app.tenant_id = '{ctx.tenant_id}'"))  # nosemgrep: avoid-sqlalchemy-text
                await session.execute(text(f"SET LOCAL app.user_id = '{ctx.user_id or ''}'"))  # nosemgrep: avoid-sqlalchemy-text
                await session.execute(text(f"SET LOCAL app.actor = '{ctx.actor}'"))  # nosemgrep: avoid-sqlalchemy-text
            yield session


@asynccontextmanager
async def system_session_scope() -> AsyncIterator[AsyncSession]:
    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            await session.execute(text("SET LOCAL app.actor = 'SYSTEM'"))  # nosemgrep: avoid-sqlalchemy-text
            yield session


@asynccontextmanager
async def admin_session_scope(
    *, tenant_id: str = "", user_id: str = "PLATFORM"
) -> AsyncIterator[AsyncSession]:
    """Acquire an app_admin session with ``app.actor = 'ADMIN'``.

    This is the ONLY legitimate way for server-side code to obtain ADMIN
    privilege (storage-v1 §10.1).  The actor is set in-transaction via
    ``SET LOCAL`` — it never travels over HTTP headers and cannot be forged
    by clients.  Use ONLY from platform-admin endpoints that have already
    passed ``require_scope("storage.admin")`` / equivalent authz.
    """
    sm = get_admin_sessionmaker()
    async with sm() as session:
        async with session.begin():
            # SET LOCAL is transaction-scoped — disappears at commit/rollback.
            await session.execute(text("SET LOCAL app.actor = 'ADMIN'"))
            await session.execute(text(f"SET LOCAL app.tenant_id = '{tenant_id}'"))
            await session.execute(text(f"SET LOCAL app.user_id = '{user_id}'"))
            yield session


async def dispose_engine() -> None:
    global _engine, _sessionmaker, _admin_engine, _admin_sessionmaker
    if _engine is not None: await _engine.dispose(); _engine = None; _sessionmaker = None
    if _admin_engine is not None:
        await _admin_engine.dispose()
        _admin_engine = None
        _admin_sessionmaker = None
