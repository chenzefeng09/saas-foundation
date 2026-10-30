import uuid; from collections.abc import AsyncIterator; from contextlib import asynccontextmanager
from sqlalchemy import text; from sqlalchemy.ext.asyncio import AsyncEngine,AsyncSession,async_sessionmaker,create_async_engine
from foundation_llm_gateway.config import get_settings; from foundation_llm_gateway.domain.base import FoundationContext,foundation_context
from foundation_llm_gateway.observability import get_logger
log=get_logger(__name__)
_engine:AsyncEngine|None=None; _sm:async_sessionmaker[AsyncSession]|None=None
_admin_engine:AsyncEngine|None=None; _admin_sm:async_sessionmaker[AsyncSession]|None=None
def _rsn()->str:return f"__asyncpg_{uuid.uuid4().hex[:12]}__"
def get_engine()->AsyncEngine:
    global _engine
    if _engine is None:
        # PgBouncer (transaction pooling) trap: asyncpg must disable BOTH the
        # statement cache AND the prepared-statement cache, plus use a unique
        # per-statement name, or pooled connections raise
        # ``prepared statement "__asyncpg_..." does not exist`` intermittently.
        # ``statement_cache_size=0`` alone is NOT enough — see foundation
        # org/audit db.py for the canonical working combination.
        s=get_settings(); _engine=create_async_engine(str(s.db_dsn),pool_size=s.db_pool_size,max_overflow=s.db_max_overflow,pool_timeout=s.db_pool_timeout_seconds,pool_pre_ping=True,echo=s.db_echo,connect_args={"statement_cache_size":0,"prepared_statement_cache_size":0,"prepared_statement_name_func":_rsn})
    return _engine
def get_admin_engine()->AsyncEngine:
    """Lazy app_admin engine for background jobs. Same PgBouncer-safe asyncpg
    settings as get_engine(); the jobs run one transaction at a time, so the
    pool stays small."""
    global _admin_engine
    if _admin_engine is None:
        s=get_settings(); _admin_engine=create_async_engine(str(s.db_dsn_admin),pool_size=2,max_overflow=0,pool_timeout=s.db_pool_timeout_seconds,pool_pre_ping=True,echo=s.db_echo,connect_args={"statement_cache_size":0,"prepared_statement_cache_size":0,"prepared_statement_name_func":_rsn})
    return _admin_engine
@asynccontextmanager
async def session_scope()->AsyncIterator[AsyncSession]:
    global _sm
    if _sm is None: _sm=async_sessionmaker(bind=get_engine(),expire_on_commit=False,class_=AsyncSession,autoflush=False)
    ctx=foundation_context.get()
    async with _sm() as session:
        async with session.begin():
            if ctx is not None:
                await session.execute(text(f"SET LOCAL app.tenant_id = '{ctx.tenant_id}'"))  # nosemgrep: avoid-sqlalchemy-text
                await session.execute(text(f"SET LOCAL app.user_id = '{ctx.user_id or ''}'"))  # nosemgrep: avoid-sqlalchemy-text
                await session.execute(text(f"SET LOCAL app.actor = '{ctx.actor}'"))  # nosemgrep: avoid-sqlalchemy-text
            yield session
@asynccontextmanager
async def admin_session_scope()->AsyncIterator[AsyncSession]:
    """Cross-tenant app_admin session with ``app.actor = 'ADMIN'`` (admin_all RLS policy).

    Only for server-side background jobs, which have no request context — never
    use it from a request handler. The actor is set with SET LOCAL inside the
    transaction; it never comes from a client header.
    """
    global _admin_sm
    if _admin_sm is None: _admin_sm=async_sessionmaker(bind=get_admin_engine(),expire_on_commit=False,class_=AsyncSession,autoflush=False)
    async with _admin_sm() as session:
        async with session.begin():
            await session.execute(text("SET LOCAL app.actor = 'ADMIN'"))  # nosemgrep: avoid-sqlalchemy-text
            yield session
async def dispose_engine()->None:
    global _engine,_sm,_admin_engine,_admin_sm
    if _engine is not None: await _engine.dispose(); _engine=None; _sm=None
    if _admin_engine is not None: await _admin_engine.dispose(); _admin_engine=None; _admin_sm=None
