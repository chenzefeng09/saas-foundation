"""Shared fixtures for org unit tests."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest


# ---------------------------------------------------------------------------
# Hermetic environment
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
    monkeypatch_session.setenv("ORG_ENV", "dev")
    monkeypatch_session.setenv("ORG_LOG_FORMAT", "console")
    monkeypatch_session.setenv("ORG_OTEL_ENABLED", "false")
    monkeypatch_session.setenv("ORG_REQUIRE_TENANT_CONTEXT", "false")


# Late imports after env vars
from foundation_org.domain.base import FoundationContext, foundation_context  # noqa: E402


# ---------------------------------------------------------------------------
# Fake AsyncSession
# ---------------------------------------------------------------------------

class _ScalarsResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self


class _ExecuteResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalars(self):
        return _ScalarsResult(self._rows)


@dataclass
class FakeAsyncSession:
    """Minimal stand-in for AsyncSession used in unit tests."""

    pk_store: dict[type, dict[str, Any]] = field(default_factory=lambda: defaultdict(dict))
    added: list[Any] = field(default_factory=list)
    flush_calls: int = 0

    _scalar_queue: list[Any] = field(default_factory=list)
    _scalars_queue: list[list[Any]] = field(default_factory=list)
    _execute_queue: list[list[Any]] = field(default_factory=list)

    # ---- staging helpers ----
    def put(self, obj: Any) -> None:
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

    async def refresh(self, obj: Any, attribute_names: list[str] | None = None) -> None:
        pass  # no-op in fake session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_session() -> FakeAsyncSession:
    return FakeAsyncSession()


@pytest.fixture
def audit_publisher() -> AsyncMock:
    m = AsyncMock()
    m.publish = AsyncMock()
    return m


@pytest.fixture
def tenant_id() -> str:
    return "tnt_01J0000000000000000000TNT1"


@pytest.fixture
def actor_id() -> str:
    return "usr_01J0000000000000000000ACT1"


@pytest.fixture
def user_id() -> str:
    return "usr_01J0000000000000000000USR1"


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
