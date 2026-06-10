"""Unit tests for the /flags API: preset+DB merge on list, DB persistence on PUT.

All tests run without a real database:
  - session_scope is monkeypatched to yield a fake in-memory session
  - unleash_enabled=False so the gateway short-circuits to presets

Covers the "PUT write invisible to GET list" regression:
  - list merges in-memory preset baseline with DB override rows
  - list includes DB-only flags
  - list falls back to preset baseline on DB failure
  - PUT persists, and a subsequent list sees the write (read-after-write)
  - PUT returns 503 when DB persistence fails (no synthetic 200)
  - PUT requires ADMIN actor
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import foundation_feature_flag.api.v1.flags as flags_module
from foundation_feature_flag.api.exception_handlers import install_exception_handlers
from foundation_feature_flag.api.middleware import TenantContextMiddleware
from foundation_feature_flag.api.v1.flags import router as flags_router
from foundation_feature_flag.domain.models import Flag
from foundation_feature_flag.services.feature_flag_service import FeatureFlagService
from foundation_feature_flag.services.unleash_gateway import UnleashGateway

ADMIN_HEADERS = {
    "X-Tenant-Id": "tnt_01J0000000000000000000TNT1",
    "X-Actor": "ADMIN",
    "X-User-Id": "usr_admin",
}

USER_HEADERS = {
    "X-Tenant-Id": "tnt_01J0000000000000000000TNT1",
    "X-Actor": "USER",
}


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, rows: list[Flag]) -> None:
        self._rows = rows

    def scalars(self) -> FakeResult:
        return self

    def all(self) -> list[Flag]:
        return self._rows


class FakeSession:
    """Minimal AsyncSession stand-in backed by a dict keyed by Flag.key."""

    def __init__(self, store: dict[str, Flag]) -> None:
        self._store = store

    async def get(self, model: type, key: str) -> Flag | None:
        return self._store.get(key)

    def add(self, obj: Flag) -> None:
        self._store[obj.key] = obj

    async def execute(self, stmt: object) -> FakeResult:
        return FakeResult(sorted(self._store.values(), key=lambda f: f.key))


def make_gateway() -> UnleashGateway:
    """Gateway with unleash_enabled=False (no Unleash server needed)."""
    import threading

    gw = UnleashGateway.__new__(UnleashGateway)
    gw._settings = MagicMock()
    gw._settings.unleash_enabled = False
    gw._settings.unleash_fail_open_flags = []
    gw._client = None
    gw._presets = {}
    gw._killed = set()
    gw._lock = threading.Lock()
    return gw


def make_db_flag(key: str, *, enabled: bool, description: str | None = None) -> Flag:
    return Flag(
        key=key,
        name=key,
        description=description,
        enabled=enabled,
        default_value=enabled,
        fail_open=False,
    )


@pytest.fixture
def gw() -> UnleashGateway:
    return make_gateway()


@pytest.fixture
def svc(gw: UnleashGateway) -> FeatureFlagService:
    service = FeatureFlagService(gateway=gw)
    service.load_presets()
    return service


@pytest.fixture
def store() -> dict[str, Flag]:
    return {}


@pytest.fixture
def client(
    gw: UnleashGateway,
    svc: FeatureFlagService,
    store: dict[str, Flag],
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    @asynccontextmanager
    async def fake_session_scope():
        yield FakeSession(store)

    monkeypatch.setattr(flags_module, "session_scope", fake_session_scope)

    app = FastAPI()
    app.add_middleware(TenantContextMiddleware)
    install_exception_handlers(app)
    app.state.unleash_gateway = gw
    app.state.feature_flag_service = svc
    app.include_router(flags_router)
    return TestClient(app)


@pytest.fixture
def client_db_down(
    gw: UnleashGateway,
    svc: FeatureFlagService,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    @asynccontextmanager
    async def failing_session_scope():
        raise RuntimeError("db down")
        yield  # pragma: no cover

    monkeypatch.setattr(flags_module, "session_scope", failing_session_scope)

    app = FastAPI()
    app.add_middleware(TenantContextMiddleware)
    install_exception_handlers(app)
    app.state.unleash_gateway = gw
    app.state.feature_flag_service = svc
    app.include_router(flags_router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /flags — preset baseline + DB override merge
# ---------------------------------------------------------------------------


class TestListFlagsMerge:
    def test_db_override_wins_over_preset(self, client: TestClient, store: dict[str, Flag]):
        """A DB row for a preset key overrides the preset default."""
        store["billing.saas_mode"] = make_db_flag(
            "billing.saas_mode", enabled=True, description="overridden"
        )

        resp = client.get("/flags", headers=ADMIN_HEADERS)
        assert resp.status_code == 200
        by_key = {f["key"]: f for f in resp.json()}

        # Overridden key takes the DB value
        assert by_key["billing.saas_mode"]["enabled"] is True
        assert by_key["billing.saas_mode"]["description"] == "overridden"
        # Other preset keys keep their defaults
        assert by_key["ai.thinking_ui"]["enabled"] is True
        assert by_key["auth.social_login.google"]["enabled"] is False
        assert by_key["export.allow_l4_download"]["enabled"] is False

    def test_db_only_flag_appears_in_list(self, client: TestClient, store: dict[str, Flag]):
        """A DB row whose key is not in the presets is appended to the list."""
        store["custom.db_only_flag"] = make_db_flag("custom.db_only_flag", enabled=True)

        resp = client.get("/flags", headers=ADMIN_HEADERS)
        assert resp.status_code == 200
        by_key = {f["key"]: f for f in resp.json()}

        assert "custom.db_only_flag" in by_key
        assert by_key["custom.db_only_flag"]["enabled"] is True
        # Presets are still present alongside the DB-only flag
        assert "billing.saas_mode" in by_key

    def test_db_failure_falls_back_to_preset_baseline(self, client_db_down: TestClient):
        """DB read failure → preset baseline only, no error."""
        resp = client_db_down.get("/flags", headers=ADMIN_HEADERS)
        assert resp.status_code == 200
        by_key = {f["key"]: f for f in resp.json()}

        assert len(by_key) >= 8
        assert by_key["billing.saas_mode"]["enabled"] is False
        assert by_key["ai.thinking_ui"]["enabled"] is True

    def test_list_sorted_by_key(self, client: TestClient, store: dict[str, Flag]):
        store["zzz.last_flag"] = make_db_flag("zzz.last_flag", enabled=False)
        resp = client.get("/flags", headers=ADMIN_HEADERS)
        keys = [f["key"] for f in resp.json()]
        assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# PUT /flags/{flag} — DB persistence and read-after-write visibility
# ---------------------------------------------------------------------------


class TestSetFlagPersistence:
    def test_put_persists_and_list_sees_it(self, client: TestClient, store: dict[str, Flag]):
        """The original bug: PUT returned 200 but list still showed the seed default."""
        # Preset default is False
        resp = client.get("/flags", headers=ADMIN_HEADERS)
        by_key = {f["key"]: f for f in resp.json()}
        assert by_key["billing.saas_mode"]["enabled"] is False

        # PUT enabled=True
        resp = client.put(
            "/flags/billing.saas_mode",
            json={"enabled": True, "rollout_percentage": 100},
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True

        # Upsert reached the (fake) DB
        assert "billing.saas_mode" in store
        assert store["billing.saas_mode"].enabled is True

        # Read-after-write: list now reflects the PUT
        resp = client.get("/flags", headers=ADMIN_HEADERS)
        by_key = {f["key"]: f for f in resp.json()}
        assert by_key["billing.saas_mode"]["enabled"] is True

    def test_put_updates_existing_row(self, client: TestClient, store: dict[str, Flag]):
        store["billing.saas_mode"] = make_db_flag("billing.saas_mode", enabled=False)

        resp = client.put(
            "/flags/billing.saas_mode",
            json={"enabled": True, "rollout_percentage": 100},
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 200
        assert store["billing.saas_mode"].enabled is True

    def test_put_db_failure_returns_503(self, client_db_down: TestClient):
        """DB write failure must surface as 503, not a synthetic 200."""
        resp = client_db_down.put(
            "/flags/billing.saas_mode",
            json={"enabled": True, "rollout_percentage": 100},
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 503
        assert "DB persistence failed" in resp.json()["detail"]

    def test_put_requires_admin_actor(self, client: TestClient, store: dict[str, Flag]):
        resp = client.put(
            "/flags/billing.saas_mode",
            json={"enabled": True, "rollout_percentage": 100},
            headers=USER_HEADERS,
        )
        assert resp.status_code == 403
        assert resp.json()["code"] == "FOUNDATION.FEATURE_FLAG.AUTHZ.ACCESS_DENIED"
        assert "billing.saas_mode" not in store
