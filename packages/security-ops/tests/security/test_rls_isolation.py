"""RLS isolation for the security_ops schema (docs/multi-tenancy.md §8.3, §10.2).

security-ops is platform-scoped: its policies gate on app.actor, not on tenant_id.
The isolation property fuzzed here is therefore "only the ADMIN / SYSTEM / SERVICE
actors can read or write any table, whatever tenant or user the session claims",
checked straight against Postgres as the runtime role, below the application.
"""

from __future__ import annotations

import random
import string
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from foundation_security_ops.domain.models import (
    Drill,
    Incident,
    LicenseFinding,
    Outbox,
    SbomRecord,
    SbomWatch,
    ScanRun,
    Vulnerability,
)
from tests._db import foundation_db_url

pytestmark = [pytest.mark.security, pytest.mark.asyncio(loop_scope="module")]

ATTEMPTS = 1000
MODELS: tuple[type[Any], ...] = (
    ScanRun,
    Vulnerability,
    Incident,
    SbomRecord,
    SbomWatch,
    LicenseFinding,
    Drill,
    Outbox,
)
COMMANDS = ("SELECT", "INSERT", "UPDATE", "DELETE")
# alembic's bookkeeping table carries no business data.
NOT_RLS = frozenset({"alembic_version"})

PLATFORM_ACTORS = ("ADMIN", "SYSTEM", "SERVICE")
# What else a session may claim: the other ActorKind values, case and whitespace
# variants, empty, list- and injection-shaped strings, and no claim at all.
OTHER_ACTORS: tuple[str | None, ...] = (
    "USER",
    "MIGRATOR",
    "",
    "admin",
    "Service",
    " SERVICE",
    "SYSTEM ",
    "ADMIN,SERVICE",
    "ADMIN' OR '1'='1",
    "_platform",
    "NULL",
    None,
)

UPDATES: dict[type[Any], dict[str, Any]] = {
    ScanRun: {"status": "ERRORED"},
    Vulnerability: {"status": "TRIAGED"},
    Incident: {"status": "INVESTIGATING"},
    SbomRecord: {"component_count": 1},
    SbomWatch: {"new_cves_count": 1},
    LicenseFinding: {"verdict": "REVIEW_REQUIRED"},
    Drill: {"status": "RUNNING"},
    Outbox: {"event_type": "foundation.security_ops.fuzz.updated"},
}

_SET_LOCAL = text("SELECT set_config(:name, :value, true)")
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid(rng: random.Random) -> str:
    return "".join(rng.choices(_CROCKFORD, k=26))


def _garbage_actor(rng: random.Random) -> str:
    while True:
        value = "".join(
            rng.choices(string.ascii_letters + string.digits + "_-' ", k=rng.randint(1, 12))
        )
        if value not in PLATFORM_ACTORS:
            return value


def _row(model: type[Any], rng: random.Random) -> dict[str, Any]:
    tag = _ulid(rng)[:12]
    now = datetime.now(UTC)
    rows: dict[type[Any], dict[str, Any]] = {
        ScanRun: {
            "id": f"scan_{tag}",
            "type": "SAST",
            "tool": "fuzz",
            "target": "fuzz",
            "started_at": now,
            "status": "PASSED",
        },
        Vulnerability: {
            "id": f"vuln_{tag}",
            "source": "SAST",
            "title": "fuzz",
            "severity": "LOW",
            "status": "OPEN",
            "found_at": now,
            "due_at": now,
        },
        Incident: {
            "id": f"inc_{tag}",
            "severity": "LOW",
            "category": "OTHER",
            "title": "fuzz",
            "detected_at": now,
            "reported_by": "fuzz",
            "status": "DETECTED",
        },
        SbomRecord: {"id": f"sbom_{tag}", "image_ref": f"fuzz/{tag}", "generated_at": now},
        SbomWatch: {"id": f"sbomwatch_{tag}", "image_ref": f"fuzz/{tag}", "registered_at": now},
        LicenseFinding: {
            "id": f"lic_{tag}",
            "scan_run_id": f"scan_{tag}",
            "package_name": "fuzz",
            "license_spdx": "MIT",
            "verdict": "ALLOWED",
        },
        Drill: {
            "id": f"drill_{tag}",
            "kind": "TABLETOP",
            "scheduled_at": now,
            "status": "SCHEDULED",
        },
        Outbox: {"event_type": "foundation.security_ops.fuzz", "payload": {"tag": tag}},
    }
    return rows[model]


async def _claim(
    conn: AsyncConnection, *, actor: str | None, tenant_id: str = "", user_id: str = ""
) -> None:
    """What session_scope does per transaction: SET LOCAL the request context."""
    for name, value in (
        ("app.tenant_id", tenant_id),
        ("app.user_id", user_id),
        ("app.actor", actor),
    ):
        if value is not None:
            await conn.execute(_SET_LOCAL, {"name": name, "value": value})


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine() -> AsyncIterator[AsyncEngine]:
    """The runtime role's engine, with one committed row per table to try to reach."""
    eng = create_async_engine(foundation_db_url())
    rng = random.Random("rls-seed")
    seeded: list[tuple[type[Any], Any]] = []
    async with eng.begin() as conn:
        await _claim(conn, actor="SERVICE")
        for model in MODELS:
            result = await conn.execute(
                insert(model).values(**_row(model, rng)).returning(model.id)
            )
            seeded.append((model, result.scalar_one()))
    yield eng
    async with eng.begin() as conn:
        await _claim(conn, actor="SERVICE")
        for model, pk in seeded:
            await conn.execute(delete(model).where(model.id == pk))
    await eng.dispose()


# ─── Static checks (§8.3) ────────────────────────────────────────────────────


async def test_runtime_role_is_bound_by_rls(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            )
        ).one()
    assert (row.rolsuper, row.rolbypassrls) == (False, False)


async def test_every_table_enables_and_forces_rls(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity"
                    " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                    " WHERE n.nspname = 'security_ops' AND c.relkind IN ('r', 'p')"
                )
            )
        ).all()
    flags = {
        r.relname: (r.relrowsecurity, r.relforcerowsecurity)
        for r in rows
        if r.relname not in NOT_RLS
    }
    # A table missing here is a table the fuzz below does not cover.
    assert set(flags) == {m.__tablename__ for m in MODELS}
    assert {t: f for t, f in flags.items() if f != (True, True)} == {}


async def test_every_command_has_an_actor_gated_policy(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT tablename, policyname, cmd, roles, qual, with_check"
                    " FROM pg_policies WHERE schemaname = 'security_ops'"
                )
            )
        ).all()
    covered = {
        (r.tablename, cmd)
        for r in rows
        if "app_user" in r.roles
        for cmd in (COMMANDS if r.cmd == "ALL" else (r.cmd,))
    }
    expected = {(m.__tablename__, cmd) for m in MODELS for cmd in COMMANDS}
    assert expected - covered == set()
    # Platform scope: every predicate is gated on the actor; none is unconditional.
    ungated = [
        (r.tablename, r.policyname, clause)
        for r in rows
        for clause in (r.qual, r.with_check)
        if clause is not None and "current_setting('app.actor'" not in clause
    ]
    assert ungated == []


async def test_session_that_never_claims_an_actor_sees_nothing(engine: AsyncEngine) -> None:
    # A brand-new connection: app.actor was never set, so current_setting() is NULL.
    fresh = create_async_engine(foundation_db_url(), poolclass=NullPool)
    try:
        async with fresh.connect() as conn:
            for model in MODELS:
                visible = (await conn.execute(select(func.count()).select_from(model))).scalar_one()
                assert visible == 0, model.__tablename__
            with pytest.raises(DBAPIError, match="row-level security"):
                await conn.execute(insert(Incident).values(**_row(Incident, random.Random(0))))
    finally:
        await fresh.dispose()


# ─── Fuzz (§10.2) ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("attempt", range(ATTEMPTS))
async def test_rls_fuzz(engine: AsyncEngine, attempt: int) -> None:
    # Cycle through every (table, command, allowed?) combination so each one is hit
    # ~15 times; within a combination the actor spelling, tenant and user are random.
    rng = random.Random(f"rls-fuzz-{attempt}")
    model = MODELS[attempt % len(MODELS)]
    command = COMMANDS[(attempt // len(MODELS)) % len(COMMANDS)]
    allowed = (attempt // (len(MODELS) * len(COMMANDS))) % 2 == 0
    actor = (
        rng.choice(PLATFORM_ACTORS) if allowed else rng.choice((*OTHER_ACTORS, _garbage_actor(rng)))
    )
    tenant_id = rng.choice(("", "_platform", f"tnt_{_ulid(rng)}"))
    user_id = rng.choice(("", f"usr_{_ulid(rng)}"))
    context = (model.__tablename__, command, actor, tenant_id, user_id)

    async with engine.connect() as conn:
        try:
            await _claim(conn, actor=actor, tenant_id=tenant_id, user_id=user_id)
            if command == "SELECT":
                visible = (await conn.execute(select(func.count()).select_from(model))).scalar_one()
                assert (visible > 0) is allowed, context
            elif command == "UPDATE":
                changed = (await conn.execute(update(model).values(**UPDATES[model]))).rowcount
                assert (changed > 0) is allowed, context
            elif command == "DELETE":
                removed = (await conn.execute(delete(model))).rowcount
                assert (removed > 0) is allowed, context
            else:
                stmt = insert(model).values(**_row(model, rng))
                if allowed:
                    await conn.execute(stmt)
                else:
                    with pytest.raises(DBAPIError, match="row-level security"):
                        await conn.execute(stmt)
        finally:
            await conn.rollback()
