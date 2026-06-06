import uuid; from collections.abc import AsyncIterator; from contextlib import asynccontextmanager
from sqlalchemy import text; from sqlalchemy.ext.asyncio import AsyncEngine,AsyncSession,async_sessionmaker,create_async_engine
from foundation_search.config import get_settings; from foundation_search.domain.base import FoundationContext,foundation_context
from foundation_search.observability import get_logger
log=get_logger(__name__)
_engine:AsyncEngine|None=None; _sm:async_sessionmaker[AsyncSession]|None=None
def _rsn()->str:return f"__asyncpg_{uuid.uuid4().hex[:12]}__"
def get_engine()->AsyncEngine:
    global _engine
    if _engine is None:
        s=get_settings(); _engine=create_async_engine(str(s.db_dsn),pool_size=s.db_pool_size,max_overflow=s.db_max_overflow,pool_timeout=s.db_pool_timeout_seconds,pool_pre_ping=True,echo=s.db_echo,connect_args={"statement_cache_size":0,"prepared_statement_name_func":_rsn})
    return _engine
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
async def dispose_engine()->None:
    global _engine,_sm
    if _engine is not None: await _engine.dispose(); _engine=None; _sm=None
