"""HTTP-facing runtime tests for lifecycle service."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import create_autospec

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from foundation_lifecycle.api import dependencies
from foundation_lifecycle.api.exception_handlers import install_exception_handlers
from foundation_lifecycle.errors import RESOURCE_NOT_IN_BIN, FoundationError
from foundation_lifecycle.main import create_app
from foundation_lifecycle.services.legal_hold_service import LegalHoldService
from foundation_lifecycle.services.lifecycle_service import LifecycleService

from tests._factories import make_legal_hold


def test_healthz_includes_request_id_header() -> None:
    client = TestClient(create_app())

    response = client.get("/api/lifecycle/v1/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "OK"
    assert response.headers["X-Request-Id"].startswith("req_")


def test_invalid_tenant_header_returns_problem_json() -> None:
    client = TestClient(create_app())

    response = client.get(
        "/api/lifecycle/v1/recycle-bin",
        headers={"X-Tenant-Id": "bad"},
    )

    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "FOUNDATION.LIFECYCLE.INPUT.VALIDATION_FAILED"


def test_foundation_error_handler_returns_problem_json() -> None:
    app = FastAPI()
    install_exception_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise FoundationError(RESOURCE_NOT_IN_BIN, extra={"bin_id": "bin_missing"})

    response = TestClient(app).get("/boom")

    assert response.status_code == RESOURCE_NOT_IN_BIN.http_status
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["bin_id"] == "bin_missing"


@pytest.mark.parametrize(("path", "stale_cursor"), [
    ("/api/lifecycle/v1/legal-holds", "lhd_01J0000000000000000000HLD1"),
    ("/api/lifecycle/v1/recycle-bin", "bin_01J0000000000000000000BIN1"),
])
def test_list_with_a_cursor_it_did_not_issue_is_422_not_500(path: str, stale_cursor: str) -> None:
    app = create_app()

    async def _no_db() -> AsyncIterator[None]:
        yield None  # the cursor is rejected before any query runs

    app.dependency_overrides[dependencies.db_session] = _no_db

    response = TestClient(app).get(
        path,
        params={"cursor": stale_cursor},  # a bare id: what these lists used to hand out
        headers={"X-Tenant-Id": "tnt_01J0000000000000000000TNT1"},
    )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "FOUNDATION.LIFECYCLE.INPUT.VALIDATION_FAILED"


_TENANT = "tnt_01J0000000000000000000TNT1"
_CALLER, _OTHER_USER = "usr_01J0000000000000000000USR1", "usr_01J0000000000000000000USR2"
_RESTORE = "/api/lifecycle/v1/recycle-bin/bin_01J0000000000000000000BIN1:restore"
_HARD_DELETE = "/api/lifecycle/v1/recycle-bin/bin_01J0000000000000000000BIN1:hard-delete"
_RELEASE = "/api/lifecycle/v1/legal-holds/lhd_01J0000000000000000000HLD1:release"


@pytest.fixture
def lifecycle_svc() -> Any:
    return create_autospec(LifecycleService, instance=True)  # calls must fit the real signature


@pytest.fixture
def hold_svc() -> Any:
    return create_autospec(LegalHoldService, instance=True)


@pytest.fixture
def client(lifecycle_svc: Any, hold_svc: Any) -> TestClient:
    app = create_app()

    async def _no_db() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[dependencies.db_session] = _no_db
    app.dependency_overrides[dependencies.lifecycle_service] = lambda: lifecycle_svc
    app.dependency_overrides[dependencies.legal_hold_service] = lambda: hold_svc
    return TestClient(app)


# Each route: its path, the service it calls, the method, and the keyword saying who acted.
_RESTORE_ROUTE = (_RESTORE, "lifecycle", "restore", "restored_by")
_HARD_DELETE_ROUTE = (_HARD_DELETE, "lifecycle", "hard_delete", "destroyed_by")
_RELEASE_ROUTE = (_RELEASE, "hold", "release", "released_by")

# "admin" is what agent-platform's admin web sends as destroyed_by / released_by until
# the user's profile has loaded.
_ACTOR_CASES = [
    pytest.param(*_RESTORE_ROUTE, None, id="restore-no-body"),
    pytest.param(*_RESTORE_ROUTE, {}, id="restore-empty-body"),
    pytest.param(*_RESTORE_ROUTE, {"restored_by": None}, id="restore-null"),
    pytest.param(*_RESTORE_ROUTE, {"restored_by": _OTHER_USER}, id="restore-other-user"),
    pytest.param(*_HARD_DELETE_ROUTE, None, id="hard-delete-no-body"),
    pytest.param(*_HARD_DELETE_ROUTE, {"destroyed_by": _CALLER}, id="hard-delete-the-caller"),
    pytest.param(*_HARD_DELETE_ROUTE, {"destroyed_by": _OTHER_USER}, id="hard-delete-other-user"),
    pytest.param(*_HARD_DELETE_ROUTE, {"destroyed_by": "admin"}, id="hard-delete-web-fallback"),
    pytest.param(*_RELEASE_ROUTE, None, id="release-no-body"),
    pytest.param(*_RELEASE_ROUTE, {"released_by": _OTHER_USER}, id="release-other-user"),
    pytest.param(*_RELEASE_ROUTE, {"released_by": "admin"}, id="release-web-fallback"),
]


@pytest.mark.parametrize(("path", "service", "method", "actor_kwarg", "body"), _ACTOR_CASES)
def test_the_caller_is_recorded_whoever_the_body_names(
    client: TestClient, lifecycle_svc: Any, hold_svc: Any,
    path: str, service: str, method: str, actor_kwarg: str, body: dict[str, Any] | None,
) -> None:
    svc = {"lifecycle": lifecycle_svc, "hold": hold_svc}[service]

    response = client.post(path, json=body, headers={"X-Tenant-Id": _TENANT, "X-User-Id": _CALLER})

    assert response.status_code == 200, response.text
    call = getattr(svc, method)
    call.assert_awaited_once()
    assert call.await_args.kwargs[actor_kwarg] == _CALLER
    assert call.await_args.kwargs["tenant_id"] == _TENANT


def test_hard_delete_records_no_witness_the_caller_names(
    client: TestClient, lifecycle_svc: Any,
) -> None:
    response = client.post(
        _HARD_DELETE,
        json={"destroyed_by": _CALLER, "witness_user_id": _OTHER_USER},
        headers={"X-Tenant-Id": _TENANT, "X-User-Id": _CALLER},
    )

    assert response.status_code == 200, response.text
    kwargs = lifecycle_svc.hard_delete.await_args.kwargs
    assert (kwargs["destroyed_by"], kwargs["witness_user_id"]) == (_CALLER, None)


@pytest.mark.parametrize(("path", "body"), [
    pytest.param(_RESTORE, None, id="restore"),
    pytest.param(_HARD_DELETE, {"destroyed_by": _OTHER_USER}, id="hard-delete"),
    pytest.param(_RELEASE, {"released_by": _OTHER_USER}, id="release"),
])
def test_a_call_without_a_user_is_refused_not_recorded_as_whoever_it_names(
    client: TestClient, lifecycle_svc: Any, hold_svc: Any,
    path: str, body: dict[str, Any] | None,
) -> None:
    # What a service-account token brings: a tenant and no user.
    response = client.post(path, json=body, headers={"X-Tenant-Id": _TENANT, "X-Actor": "SERVICE"})

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "FOUNDATION.LIFECYCLE.POLICY.PERMISSION_DENIED"
    for call in (lifecycle_svc.restore, lifecycle_svc.hard_delete, hold_svc.release):
        call.assert_not_awaited()


def test_the_openapi_marks_the_body_actor_fields_deprecated_and_no_body_required() -> None:
    spec = create_app().openapi()
    schemas = spec["components"]["schemas"]

    for path, model, fields in [
        (_RESTORE, "RestoreRequest", {"restored_by"}),
        (_HARD_DELETE, "HardDeleteRequest", {"destroyed_by", "witness_user_id"}),
        (_RELEASE, "ReleaseLegalHoldRequest", {"released_by"}),
    ]:
        template = path.replace("bin_01J0000000000000000000BIN1", "{bin_id}").replace(
            "lhd_01J0000000000000000000HLD1", "{hold_id}")
        assert not spec["paths"][template]["post"]["requestBody"].get("required"), path
        assert "required" not in schemas[model], model
        assert set(schemas[model]["properties"]) == fields
        assert all(schemas[model]["properties"][f].get("deprecated") for f in fields), model


def test_list_legal_holds_hands_the_resource_filters_to_the_query(fake_session: Any) -> None:
    app = create_app()

    async def _fake_db() -> AsyncIterator[Any]:
        yield fake_session  # the real LegalHoldService builds the query; the fake records it

    app.dependency_overrides[dependencies.db_session] = _fake_db
    fake_session.queue_scalars([
        make_legal_hold(hold_id="lhd_1", placed_at=datetime(2026, 10, 30, 12, 0, tzinfo=UTC)),
    ])

    response = TestClient(app).get(
        "/api/lifecycle/v1/legal-holds",
        params={"filter.resource_type": "user_data", "filter.resource_id": "res_123"},
        headers={"X-Tenant-Id": "tnt_01J0000000000000000000TNT1"},
    )

    assert response.status_code == 200
    assert [h["id"] for h in response.json()["items"]] == ["lhd_1"]
    (stmt,) = fake_session.statements
    sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert "lifecycle.legal_hold.resource_type_id = 'user_data'" in sql
    assert "lifecycle.legal_hold.resource_id = 'res_123'" in sql
