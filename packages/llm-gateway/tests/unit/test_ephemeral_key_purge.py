"""Purge of expired run-scoped (ephemeral) virtual keys.

One key is minted per agent run and per canvas/title call. Once expired it no
longer authenticates, and nothing references its row, so the purge job
hard-deletes it after a grace period. The service method runs against a real
SQLite table (which rows go, which stay); the Postgres-only parts (row locking,
ordering) are checked on the compiled SQL.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from foundation_llm_gateway import jobs
from foundation_llm_gateway.config import Settings
from foundation_llm_gateway.domain.models import LLMTenantKey
from foundation_llm_gateway.services.llm_gateway_service import LLMGatewayService

NOW = datetime.now(UTC)
GRACE = timedelta(days=7)
TABLE = "llm_gateway.llm_tenant_key"


@pytest.fixture
def db() -> Any:
    engine = create_engine("sqlite://", poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def _attach_schema(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        dbapi_conn.execute("ATTACH DATABASE ':memory:' AS llm_gateway")

    LLMTenantKey.__table__.create(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


class _AsyncSession:
    """The two AsyncSession calls the purge makes, over a sync SQLite session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    async def scalars(self, stmt):  # type: ignore[no-untyped-def]
        return self._session.scalars(stmt)

    async def execute(self, stmt):  # type: ignore[no-untyped-def]
        return self._session.execute(stmt)


def _key(key_id: str, *, ephemeral: bool, expires_at: datetime | None,
         enabled: bool = True, tenant_id: str = "tnt_A") -> LLMTenantKey:
    return LLMTenantKey(
        id=key_id, tenant_id=tenant_id, provider_id="llmp_1", name=f"run:{key_id}",
        virtual_key=f"sk-foundation-eph-{key_id}", rate_limit_rpm=60, enabled=enabled,
        expires_at=expires_at, run_id=key_id if ephemeral else None, ephemeral=ephemeral,
        created_at=NOW,
    )


def _ids(session: Session) -> set[str]:
    return set(session.scalars(select(LLMTenantKey.id)))


async def test_purge_deletes_only_ephemeral_keys_expired_before_the_cutoff(db: Session) -> None:
    db.add_all([
        _key("gone_expired_8d", ephemeral=True, expires_at=NOW - timedelta(days=8)),
        _key("gone_revoked_30d", ephemeral=True, expires_at=NOW - timedelta(days=30), enabled=False),
        _key("gone_other_tenant", ephemeral=True, expires_at=NOW - timedelta(days=9), tenant_id="tnt_B"),
        _key("kept_within_grace", ephemeral=True, expires_at=NOW - timedelta(days=6)),
        _key("kept_unexpired", ephemeral=True, expires_at=NOW + timedelta(minutes=10)),
        _key("kept_long_lived", ephemeral=False, expires_at=None),
        _key("kept_long_lived_past_expiry", ephemeral=False, expires_at=NOW - timedelta(days=30)),
        _key("kept_ephemeral_without_expiry", ephemeral=True, expires_at=None),
    ])
    db.commit()

    purged = await LLMGatewayService().purge_expired_ephemeral_keys(
        _AsyncSession(db), expired_before=NOW - GRACE, limit=500,
    )

    assert purged == 3
    assert _ids(db) == {
        "kept_within_grace", "kept_unexpired", "kept_long_lived",
        "kept_long_lived_past_expiry", "kept_ephemeral_without_expiry",
    }


async def test_purge_takes_one_batch_of_the_oldest_keys_per_call(db: Session) -> None:
    db.add_all([
        _key(f"k{age}", ephemeral=True, expires_at=NOW - timedelta(days=age))
        for age in (8, 12, 10, 9, 11)
    ])
    db.commit()
    svc, session = LLMGatewayService(), _AsyncSession(db)

    first = await svc.purge_expired_ephemeral_keys(session, expired_before=NOW - GRACE, limit=2)

    assert first == 2
    assert _ids(db) == {"k8", "k9", "k10"}
    rest = [await svc.purge_expired_ephemeral_keys(session, expired_before=NOW - GRACE, limit=2)
            for _ in range(3)]
    assert rest == [2, 1, 0]
    assert _ids(db) == set()


class _RecordingSession:
    def __init__(self, ids: list[str]) -> None:
        self.ids, self.statements = ids, []

    async def scalars(self, stmt):  # type: ignore[no-untyped-def]
        self.statements.append(stmt)
        return _Rows(self.ids)

    async def execute(self, stmt):  # type: ignore[no-untyped-def]
        self.statements.append(stmt)
        return _Result(len(self.ids))


class _Rows:
    def __init__(self, rows: list[str]) -> None: self._rows = rows
    def all(self) -> list[str]: return list(self._rows)


class _Result:
    def __init__(self, rowcount: int) -> None: self.rowcount = rowcount


def _pg(stmt: Any) -> str:
    return " ".join(str(stmt.compile(dialect=postgresql.dialect())).split())


async def test_purge_locks_its_batch_then_deletes_it_by_id() -> None:
    """SKIP LOCKED lets every replica's purger take a different batch. The
    delete targets the locked ids, not a subquery: Postgres can rescan an
    IN (... LIMIT n) subquery once per row and so delete more than n."""
    session = _RecordingSession(["llmk_1", "llmk_2"])

    purged = await LLMGatewayService().purge_expired_ephemeral_keys(
        session, expired_before=NOW - GRACE, limit=500,  # type: ignore[arg-type]
    )

    assert purged == 2
    pick, delete = (_pg(s) for s in session.statements)
    assert pick.startswith(f"SELECT {TABLE}.id FROM {TABLE} WHERE")
    assert f"{TABLE}.ephemeral IS true AND {TABLE}.expires_at < " in pick
    assert pick.endswith(f"ORDER BY {TABLE}.expires_at LIMIT %(param_1)s FOR UPDATE SKIP LOCKED")
    assert delete.startswith(f"DELETE FROM {TABLE} WHERE {TABLE}.id IN (")
    assert "SELECT" not in delete


async def test_purge_with_nothing_to_delete_issues_no_delete() -> None:
    session = _RecordingSession([])

    purged = await LLMGatewayService().purge_expired_ephemeral_keys(
        session, expired_before=NOW - GRACE, limit=500,  # type: ignore[arg-type]
    )

    assert purged == 0
    assert len(session.statements) == 1


# ---------------------------------------------------------------------------
# The scheduled job: batches, one transaction each, until a short batch
# ---------------------------------------------------------------------------

class _Log:
    def __init__(self) -> None: self.events: list[tuple[str, str, dict]] = []
    def info(self, event: str, **kw: Any) -> None: self.events.append(("info", event, kw))
    def error(self, event: str, **kw: Any) -> None: self.events.append(("error", event, kw))


@pytest.fixture
def batches(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Feed the job a sequence of batch results; record what it did."""
    seen: dict[str, Any] = {"results": [], "sessions": [], "cutoffs": [], "limits": [], "log": _Log()}

    @asynccontextmanager
    async def fake_admin_session_scope():  # type: ignore[no-untyped-def]
        session = object()
        seen["sessions"].append(session)
        yield session

    async def fake_purge(self, session, *, expired_before, limit):  # type: ignore[no-untyped-def]
        assert session is seen["sessions"][-1]
        seen["cutoffs"].append(expired_before)
        seen["limits"].append(limit)
        result = seen["results"].pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(jobs, "admin_session_scope", fake_admin_session_scope)
    monkeypatch.setattr(LLMGatewayService, "purge_expired_ephemeral_keys", fake_purge)
    monkeypatch.setattr(jobs, "log", seen["log"])
    return seen


async def test_job_purges_batch_after_batch_until_one_comes_back_short(batches: dict) -> None:
    batches["results"] = [3, 3, 1]

    purged = await jobs.purge_expired_ephemeral_keys_job(grace_hours=168, batch_size=3)

    assert purged == 7
    assert len(batches["sessions"]) == 3  # one transaction per batch
    assert batches["limits"] == [3, 3, 3]
    # One cutoff for the whole run, so keys expiring meanwhile cannot keep it going.
    assert len(set(batches["cutoffs"])) == 1
    expected = datetime.now(UTC) - timedelta(hours=168)
    assert abs(batches["cutoffs"][0] - expected) < timedelta(seconds=5)
    ((level, event, fields),) = batches["log"].events
    assert (level, event, fields["purged"]) == ("info", "ephemeral_key.purge_complete", 7)


async def test_job_stops_on_an_empty_batch_after_full_ones(batches: dict) -> None:
    batches["results"] = [2, 2, 0]

    assert await jobs.purge_expired_ephemeral_keys_job(grace_hours=0, batch_size=2) == 4
    assert len(batches["sessions"]) == 3


async def test_job_logs_a_failure_and_returns_what_it_purged(batches: dict) -> None:
    """A failed run must not take the scheduler down; the next run resumes."""
    batches["results"] = [2, RuntimeError("connection reset")]

    assert await jobs.purge_expired_ephemeral_keys_job(grace_hours=168, batch_size=2) == 2
    assert batches["log"].events == [
        ("error", "ephemeral_key.purge_error", {"purged": 2, "error": "connection reset"}),
    ]


# ---------------------------------------------------------------------------
# Wiring: settings and the scheduler started from the app lifespan
# ---------------------------------------------------------------------------

def test_purge_settings_default_to_hourly_with_a_seven_day_grace() -> None:
    s = Settings()
    assert s.ephemeral_key_purge_enabled is True
    assert s.ephemeral_key_purge_cron == "0 * * * *"
    assert s.ephemeral_key_purge_grace_hours == 168
    assert s.ephemeral_key_purge_batch_size == 500


@pytest.mark.parametrize("field,value", [
    ("ephemeral_key_purge_grace_hours", -1),
    ("ephemeral_key_purge_batch_size", 0),
])
def test_purge_settings_reject_out_of_range_values(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_no_scheduler_when_the_purge_is_disabled() -> None:
    assert jobs.start_scheduler(Settings(ephemeral_key_purge_enabled=False)) is None


async def test_scheduler_runs_the_purge_on_its_cron_in_utc() -> None:
    settings = Settings(
        ephemeral_key_purge_cron="15 */2 * * *",
        ephemeral_key_purge_grace_hours=24,
        ephemeral_key_purge_batch_size=100,
    )

    scheduler = jobs.start_scheduler(settings)
    try:
        assert scheduler is not None and scheduler.running
        (job,) = scheduler.get_jobs()
        assert job.id == "ephemeral_key_purge"
        assert job.func is jobs.purge_expired_ephemeral_keys_job
        assert job.kwargs == {"grace_hours": 24, "batch_size": 100}
        fields = {f.name: str(f) for f in job.trigger.fields}
        assert (fields["minute"], fields["hour"]) == ("15", "*/2")
        assert job.trigger.timezone.utcoffset(None) == timedelta(0)
    finally:
        scheduler.shutdown(wait=False)
