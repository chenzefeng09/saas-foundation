"""Shared test infrastructure for data-protection."""

from __future__ import annotations
from collections import defaultdict; from collections.abc import Iterator; from dataclasses import dataclass, field
from typing import Any
import pytest

@pytest.fixture(scope="session")
def monkeypatch_session() -> Iterator[pytest.MonkeyPatch]:
    mp = pytest.MonkeyPatch()
    try: yield mp
    finally: mp.undo()

@pytest.fixture(autouse=True, scope="session")
def _env_defaults(monkeypatch_session: pytest.MonkeyPatch) -> None:
    monkeypatch_session.setenv("DP_ENV", "dev")
    monkeypatch_session.setenv("DP_LOG_FORMAT", "console")
    monkeypatch_session.setenv("DP_OTEL_ENABLED", "false")
    monkeypatch_session.setenv("DP_REQUIRE_TENANT_CONTEXT", "false")

from foundation_data_protection.domain.base import FoundationContext, foundation_context  # noqa: E402


class _ScalarsResult:
    def __init__(self, rows): self._rows = rows
    def all(self): return list(self._rows)

@dataclass
class FakeAsyncSession:
    pk_store: dict = field(default_factory=lambda: defaultdict(dict))
    added: list = field(default_factory=list)
    flush_calls: int = 0
    _scalar_queue: list = field(default_factory=list)
    _scalars_queue: list = field(default_factory=list)

    def put(self, obj): self.pk_store[type(obj)][obj.id] = obj
    def queue_scalar(self, v): self._scalar_queue.append(v)
    def queue_scalars(self, rows): self._scalars_queue.append(list(rows))

    async def get(self, model, pk): return self.pk_store.get(model, {}).get(pk)
    async def scalar(self, _stmt): return self._scalar_queue.pop(0) if self._scalar_queue else None
    async def scalars(self, _stmt): return _ScalarsResult(self._scalars_queue.pop(0)) if self._scalars_queue else _ScalarsResult([])
    def add(self, obj):
        self.added.append(obj)
        if (pk := getattr(obj, "id", None)) is not None: self.pk_store[type(obj)][pk] = obj
    async def flush(self): self.flush_calls += 1


@pytest.fixture
def fake_session() -> FakeAsyncSession:
    return FakeAsyncSession()

@pytest.fixture
def tenant_id() -> str:
    return "tnt_01J0000000000000000000TNT1"

@pytest.fixture
def request_id() -> str:
    return "req_01J0000000000000000000REQ1"
