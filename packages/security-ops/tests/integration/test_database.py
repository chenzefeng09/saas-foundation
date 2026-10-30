"""Preconditions the rest of the integration tier relies on."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from tests.integration._support import as_actor

pytestmark = pytest.mark.integration

PACKAGE_ROOT = Path(__file__).resolve().parents[2]


async def test_runtime_role_is_bound_by_rls() -> None:
    # A superuser or BYPASSRLS role would make every RLS assertion in this tier vacuous.
    async with as_actor("SERVICE") as session:
        row = (
            await session.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            )
        ).one()
    assert (row.rolsuper, row.rolbypassrls) == (False, False)


async def test_schema_is_at_alembic_head() -> None:
    cfg = Config(str(PACKAGE_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PACKAGE_ROOT / "migrations"))
    heads = set(ScriptDirectory.from_config(cfg).get_heads())

    async with as_actor("SERVICE") as session:
        applied = set(
            (
                await session.scalars(text("SELECT version_num FROM security_ops.alembic_version"))
            ).all()
        )
    assert applied == heads
