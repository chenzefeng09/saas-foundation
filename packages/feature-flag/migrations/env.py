"""Alembic env — async engine; reads DSN from settings (migrator role)."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

from foundation_feature_flag.config import get_settings
from foundation_feature_flag.domain import models  # noqa: F401 — registers ORM mappers
from foundation_feature_flag.domain.base import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
config.set_main_option("sqlalchemy.url", str(settings.db_dsn_migrator))

target_metadata = Base.metadata


def _include_object(obj, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
    if type_ == "table":
        return obj.schema == "feature_flag"
    if type_ == "schema":
        return name == "feature_flag"
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=str(settings.db_dsn_migrator),
        target_metadata=target_metadata,
        literal_binds=True,
        include_schemas=True,
        include_object=_include_object,
        version_table_schema="feature_flag",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_migrations(connection):  # type: ignore[no-untyped-def]
    # alembic_version lives in the service schema (version_table_schema below),
    # so the schema must exist before run_migrations on DBs whose init SQL
    # predates this service.
    connection.execute(text("CREATE SCHEMA IF NOT EXISTS feature_flag"))
    # Commit now: SQLAlchemy autobegin would otherwise leave an open transaction,
    # making alembic skip its own commit and the whole upgrade roll back on close.
    connection.commit()
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        include_object=_include_object,
        version_table_schema="feature_flag",
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
