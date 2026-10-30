"""Shared fixtures for security-ops unit tests."""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

# Set before any test module imports foundation_security_ops.main, which builds the
# app (and caches Settings) at import time. With OTEL on, the tests would try to
# export spans to a collector at 127.0.0.1:4317 and stall on retries at exit.
os.environ["SECURITY_OPS_OTEL_ENABLED"] = "false"


class _ScalarsResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)

    def first(self) -> Any | None:
        return self._rows[0] if self._rows else None

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalars(self) -> _ScalarsResult:
        return self


class _ExecuteResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)

    def scalars(self) -> _ScalarsResult:
        return _ScalarsResult(self._rows)


@dataclass
class FakeAsyncSession:
    pk_store: dict[type, dict[str, Any]] = field(default_factory=lambda: defaultdict(dict))
    added: list[Any] = field(default_factory=list)
    flush_calls: int = 0

    _scalars_queue: list[list[Any]] = field(default_factory=list)

    def put(self, obj: Any) -> None:
        """Pre-load an object into the session store so `get()` finds it."""
        self.pk_store[type(obj)][obj.id] = obj

    def queue_scalars(self, rows: list[Any]) -> None:
        self._scalars_queue.append(list(rows))

    async def get(self, model: type, pk: Any) -> Any | None:
        return self.pk_store.get(model, {}).get(pk)

    async def scalars(self, _stmt: Any) -> _ScalarsResult:
        if not self._scalars_queue:
            return _ScalarsResult([])
        return _ScalarsResult(self._scalars_queue.pop(0))

    async def execute(self, _stmt: Any) -> _ExecuteResult:
        return _ExecuteResult([])

    def add(self, obj: Any) -> None:
        self.added.append(obj)
        pk = getattr(obj, "id", None)
        if pk is not None:
            self.pk_store[type(obj)][pk] = obj

    async def flush(self) -> None:
        self.flush_calls += 1


@pytest.fixture
def fake_session() -> FakeAsyncSession:
    return FakeAsyncSession()


@pytest.fixture
def request_id() -> str:
    return "req_01J0000000000000000000REQ1"


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)
