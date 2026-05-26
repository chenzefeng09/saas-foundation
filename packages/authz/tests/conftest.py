"""Shared fixtures for authz unit + integration tests.

We do NOT spin up a real Postgres in unit tests — that is integration-tier
work. Unit tests assert decision-path logic and CRUD branching, so we stub
`AsyncSession` with a small in-memory `FakeAsyncSession` that supports:

- session.get(Model, pk)              → in-memory PK lookup
- session.add(obj)                    → append to in-memory table
- session.flush()                     → no-op
- session.scalar(stmt)                → caller stages return values
- session.scalars(stmt) → .all()      → caller stages return values
- session.execute(stmt) → .all()      → caller stages return values (for JOINs)

For SELECT-based assertions tests stage return values via
`fake_session.queue_scalar(...)`, `.queue_scalars([...])`,
`.queue_execute([...])`. We assert on what the service did (added rows,
audit events) rather than on the SQL.

Factory helpers (`make_role`, `make_binding`, `make_permission`) live in
`tests/_factories.py` so they can be imported plainly:

    from tests._factories import make_role
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest


# ---------------------------------------------------------------------------
# Hermetic environment — must run before `foundation_authz.config` import.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def monkeypatch_session() -> Iterator[pytest.MonkeyPatch]:
    mp = pytest.MonkeyPatch()
    try:
        yield mp
    finally:
        mp.undo()


@pytest.fixture(autouse=True, scope="session")
def _env_defaults(monkeypatch_session: pytest.MonkeyPatch) -> None:
    """Make tests hermetic: don't require .env / Postgres / Redis / OPA to import settings."""
    monkeypatch_session.setenv("AUTHZ_ENV", "dev")
    monkeypatch_session.setenv("AUTHZ_LOG_FORMAT", "console")
    monkeypatch_session.setenv("AUTHZ_OTEL_ENABLED", "false")
    monkeypatch_session.setenv("AUTHZ_AUDIT_PUBLISHER_KIND", "log_only")
    monkeypatch_session.setenv("AUTHZ_REQUIRE_TENANT_CONTEXT", "false")


# Late imports so the env vars above take effect first.
from foundation_authz.adapters.audit_publisher import AuditPublisher  # noqa: E402
from foundation_authz.domain.base import FoundationContext, foundation_context  # noqa: E402


# ---------------------------------------------------------------------------
# Fake AsyncSession
# ---------------------------------------------------------------------------

class _ScalarsResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


class _ExecuteResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


@dataclass
class FakeAsyncSession:
    """Minimal stand-in for sqlalchemy.ext.asyncio.AsyncSession used in unit tests."""

    pk_store: dict[type, dict[str, Any]] = field(default_factory=lambda: defaultdict(dict))
    added: list[Any] = field(default_factory=list)
    flush_calls: int = 0

    _scalar_queue: list[Any] = field(default_factory=list)
    _scalars_queue: list[list[Any]] = field(default_factory=list)
    _execute_queue: list[list[Any]] = field(default_factory=list)

    # ---- staging helpers (test setup) ----
    def put(self, obj: Any) -> None:
        """Seed an object so `session.get(Model, obj.id)` returns it."""
        self.pk_store[type(obj)][obj.id] = obj

    def queue_scalar(self, value: Any) -> None:
        self._scalar_queue.append(value)

    def queue_scalars(self, rows: list[Any]) -> None:
        self._scalars_queue.append(list(rows))

    def queue_execute(self, rows: list[Any]) -> None:
        self._execute_queue.append(list(rows))

    # ---- AsyncSession surface ----
    async def get(self, model: type, pk: Any) -> Any | None:
        return self.pk_store.get(model, {}).get(pk)

    async def scalar(self, _stmt: Any) -> Any:
        if not self._scalar_queue:
            return None
        return self._scalar_queue.pop(0)

    async def scalars(self, _stmt: Any) -> _ScalarsResult:
        if not self._scalars_queue:
            return _ScalarsResult([])
        return _ScalarsResult(self._scalars_queue.pop(0))

    async def execute(self, _stmt: Any) -> _ExecuteResult:
        if not self._execute_queue:
            return _ExecuteResult([])
        return _ExecuteResult(self._execute_queue.pop(0))

    def add(self, obj: Any) -> None:
        self.added.append(obj)
        pk = getattr(obj, "id", None)
        if pk is not None:
            self.pk_store[type(obj)][pk] = obj

    async def flush(self) -> None:
        self.flush_calls += 1


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_session() -> FakeAsyncSession:
    return FakeAsyncSession()


@pytest.fixture
def audit_publisher() -> AsyncMock:
    """AuditPublisher protocol mock — records calls; never raises."""
    return AsyncMock(spec=AuditPublisher)


@pytest.fixture
def opa_mock() -> AsyncMock:
    """OpaClient mock — replace .evaluate per test."""
    from foundation_authz.adapters.opa_client import OpaClient, OpaDecision

    m = AsyncMock(spec=OpaClient)
    m.evaluate.return_value = OpaDecision(allow=True, matched_policy="default")
    return m


@pytest.fixture
def tenant_id() -> str:
    return "tnt_01J0000000000000000000TNT1"


@pytest.fixture
def user_id() -> str:
    return "usr_01J0000000000000000000USR1"


@pytest.fixture
def actor_id() -> str:
    return "usr_01J0000000000000000000ACT1"


@pytest.fixture
def request_id() -> str:
    return "req_01J0000000000000000000REQ1"


@pytest.fixture
def foundation_ctx(
    tenant_id: str,
    user_id: str,
    request_id: str,
) -> Iterator[FoundationContext]:
    ctx = FoundationContext(
        tenant_id=tenant_id,
        user_id=user_id,
        actor="USER",
        request_id=request_id,
    )
    token = foundation_context.set(ctx)
    try:
        yield ctx
    finally:
        foundation_context.reset(token)
