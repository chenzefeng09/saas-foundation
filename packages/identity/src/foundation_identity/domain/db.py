"""Async SQLAlchemy engine + session factory with mandatory RLS context.

Critical contract (docs/multi-tenancy.md §3):
    Every session's first statement must be:
        SET LOCAL app.tenant_id = '<tenant_id>';
        SET LOCAL app.user_id   = '<user_id_or_blank>';
        SET LOCAL app.actor     = '<USER|SYSTEM|...>';

If `foundation_context` is None and `settings.require_tenant_context` is True,
session acquisition raises — this catches "missing middleware" bugs at the DB layer.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from foundation_identity.config import get_settings
from foundation_identity.domain.base import FoundationContext, foundation_context
from foundation_identity.observability import get_logger

log = get_logger(__name__)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Lazy global engine; safe to call from any layer."""
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
            # PgBouncer transaction mode requires no server-side prepared statements.
            # Three layers needed:
            #   1. asyncpg-level: disable both caches.
            #   2. SQLAlchemy dialect: disable its own statement cache.
            #   3. asyncpg-level: unique prepared statement names per connection
            #      (so any accidental prepare won't collide across pool sessions).
            connect_args={
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
                "prepared_statement_name_func": _random_stmt_name,
            },
            execution_options={"compiled_cache": None},
        )
    return _engine


def _random_stmt_name() -> str:
    """Per-statement unique name; required when PgBouncer is in transaction mode
    because asyncpg's auto-generated names collide across pooled backends."""
    import uuid

    return f"__asyncpg_{uuid.uuid4().hex[:12]}__"


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


async def _apply_rls_context(session: AsyncSession, ctx: FoundationContext) -> None:
    """Set per-transaction RLS variables. Must run inside a transaction."""
    # IMPORTANT: use parametrised SET LOCAL via 2-step (Postgres doesn't accept bind in SET).
    # We validate that values are safe (alphanumeric + underscore + dash) at middleware level.
    _assert_safe(ctx.tenant_id)
    if ctx.user_id is not None:
        _assert_safe(ctx.user_id)
    _assert_safe(ctx.actor)

    await session.execute(text(f"SET LOCAL app.tenant_id = '{ctx.tenant_id}'"))
    await session.execute(text(f"SET LOCAL app.user_id = '{ctx.user_id or ''}'"))
    await session.execute(text(f"SET LOCAL app.actor = '{ctx.actor}'"))


def _assert_safe(value: str) -> None:
    """Defence-in-depth: refuse anything that could break SET LOCAL.

    Values are sourced from JWT claims after Keycloak signature verification +
    middleware regex check; this is a final fence.
    """
    if not value:
        raise RuntimeError("RLS context value cannot be empty")
    for ch in value:
        if not (ch.isalnum() or ch in "_-"):
            raise RuntimeError(f"RLS context value contains unsafe char: {value!r}")


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Acquire a session bound to the current FoundationContext.

    Raises if no tenant context is present and settings require one. Always
    BEGIN/COMMIT (or ROLLBACK on exception); SET LOCAL is applied inside that
    transaction so RLS policies see it.
    """
    settings = get_settings()
    ctx = foundation_context.get()
    if ctx is None and settings.require_tenant_context:
        raise RuntimeError(
            "FoundationContext missing — middleware did not run or this code path "
            "is invoked outside an HTTP request. Use `with_tenant_context()` for "
            "background jobs."
        )

    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            if ctx is not None:
                await _apply_rls_context(session, ctx)
            yield session


@asynccontextmanager
async def system_session_scope() -> AsyncIterator[AsyncSession]:
    """Session with `app.actor = 'SYSTEM'` and **no tenant filter**.

    Use ONLY for cross-tenant background jobs (e.g. outbox publisher).
    The actor=SYSTEM RLS policy is configured in the migration; it must be
    narrow (e.g. only outbox / audit tables readable).
    """
    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            await session.execute(text("SET LOCAL app.actor = 'SYSTEM'"))
            await session.execute(text("SET LOCAL app.tenant_id = ''"))
            await session.execute(text("SET LOCAL app.user_id = ''"))
            yield session


async def dispose_engine() -> None:
    """Graceful shutdown."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
