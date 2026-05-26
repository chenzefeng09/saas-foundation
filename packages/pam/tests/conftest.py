"""Test infrastructure for PAM."""
from collections import defaultdict; from dataclasses import dataclass, field
import pytest

class _ScalarsResult:
    def __init__(self, rows): self._rows = rows
    def all(self): return list(self._rows)

@dataclass
class FakeAsyncSession:
    pk_store: dict = field(default_factory=lambda: defaultdict(dict))
    added: list = field(default_factory=list)
    flush_calls: int = 0
    _scalars_queue: list = field(default_factory=list)

    def put(self, obj): self.pk_store[type(obj)][obj.id] = obj
    def queue_scalars(self, rows): self._scalars_queue.append(list(rows))

    async def get(self, model, pk): return self.pk_store.get(model, {}).get(pk)
    async def scalars(self, _stmt):
        return _ScalarsResult(self._scalars_queue.pop(0)) if self._scalars_queue else _ScalarsResult([])
    def add(self, obj):
        self.added.append(obj)
        if (pk := getattr(obj, "id", None)) is not None: self.pk_store[type(obj)][pk] = obj
    async def flush(self): self.flush_calls += 1


@pytest.fixture
def fake_session(): return FakeAsyncSession()

@pytest.fixture
def tenant_id(): return "tnt_01J0000000000000000000TNT1"

@pytest.fixture
def request_id(): return "req_01J0000000000000000000REQ1"
