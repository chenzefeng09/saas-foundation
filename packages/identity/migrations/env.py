"""Alembic env — async engine; reads DSN from settings (migrator role)."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from foundation_identity.config import get_settings
from foundation_identity.domain.base import Base
from foundation_identity.domain import models  # noqa: F401 — registers ORM mappers

# Alembic Config object
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject migrator DSN (BYPASSRLS) — never use app_user here.
settings = get_settings()
config.set_main_option("sqlalchemy.url", str(settings.db_dsn_migrator))

target_metadata = Base.metadata


def _include_object(obj, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
    """Only manage objects under the identity schema."""
    if type_ == "table":
        return obj.schema == "identity"
    if type_ == "schema":
        return name == "identity"
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=str(settings.db_dsn_migrator),
        target_metadata=target_metadata,
        literal_binds=True,
        include_schemas=True,
        include_object=_include_object,
        version_table_schema="identity",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_migrations(connection):  # type: ignore[no-untyped-def]
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        include_object=_include_object,
        version_table_schema="identity",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(_do_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
