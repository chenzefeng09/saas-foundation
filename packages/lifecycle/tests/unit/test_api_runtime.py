"""HTTP-facing runtime tests for lifecycle service."""

from __future__ import annotations

import re
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
from foundation_lifecycle.domain.models import DestructionCertificate
from foundation_lifecycle.errors import RESOURCE_NOT_IN_BIN, FoundationError
from foundation_lifecycle.main import create_app
from foundation_lifecycle.services.approval_service import ApprovalService
from foundation_lifecycle.services.lifecycle_service import LifecycleService

from tests._factories import (
    make_approval_request,
    make_legal_hold,
    make_recycle_bin_entry,
    make_resource_type,
)

# docs/errors.md §3.1, as contracts/openapi/_common.yaml's Error.code pattern.
CODE_FORMAT = re.compile(r"FOUNDATION\.[A-Z_]+\.[A-Z_]+\.[A-Z_]+")


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


def test_missing_tenant_header_returns_problem_json_401() -> None:
    client = TestClient(create_app())

    response = client.get("/api/lifecycle/v1/recycle-bin")

    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["code"] == "FOUNDATION.LIFECYCLE.AUTH.TENANT_CONTEXT_MISSING"
    assert CODE_FORMAT.fullmatch(body["code"])
    assert body["status"] == 401
    assert body["instance"] == "/api/lifecycle/v1/recycle-bin"
    assert body["request_id"] == response.headers["X-Request-Id"]


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
_BIN, _HOLD = "bin_01J0000000000000000000BIN1", "lhd_01J0000000000000000000HLD1"
_APR = "apr_01J0000000000000000000APR1"
_RESTORE = f"/api/lifecycle/v1/recycle-bin/{_BIN}:restore"
_HARD_DELETE = f"/api/lifecycle/v1/recycle-bin/{_BIN}:hard-delete"
_RELEASE = f"/api/lifecycle/v1/legal-holds/{_HOLD}:release"
_APPROVALS = "/api/lifecycle/v1/approval-requests"
_APPROVE, _REJECT = f"{_APPROVALS}/{_APR}/approve", f"{_APPROVALS}/{_APR}/reject"


def _as(user: str) -> dict[str, str]:
    return {"X-Tenant-Id": _TENANT, "X-User-Id": user}


@pytest.fixture
def lifecycle_svc() -> Any:
    return create_autospec(LifecycleService, instance=True)  # calls must fit the real signature


@pytest.fixture
def approvals() -> Any:
    svc = create_autospec(ApprovalService, instance=True)
    svc.request_hard_delete.return_value = make_approval_request(
        approval_id=_APR, tenant_id=_TENANT, target_id=_BIN, requested_by=_CALLER)
    svc.request_release.return_value = make_approval_request(
        approval_id=_APR, tenant_id=_TENANT, operation="RELEASE_LEGAL_HOLD", target_id=_HOLD,
        requested_by=_CALLER)
    svc.approve.return_value = make_approval_request(
        approval_id=_APR, tenant_id=_TENANT, requested_by=_CALLER, status="APPROVED")
    svc.reject.return_value = make_approval_request(
        approval_id=_APR, tenant_id=_TENANT, requested_by=_CALLER, status="REJECTED")
    return svc


@pytest.fixture
def client(lifecycle_svc: Any, approvals: Any) -> TestClient:
    app = create_app()

    async def _no_db() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[dependencies.db_session] = _no_db
    app.dependency_overrides[dependencies.lifecycle_service] = lambda: lifecycle_svc
    app.dependency_overrides[dependencies.approval_service] = lambda: approvals
    return TestClient(app)


# Each route: its path, the service it calls, the method, the keyword saying who acted or
# asked, and its answer. Hard-delete and release only ask: a second user approves.
_RESTORE_ROUTE = (_RESTORE, "lifecycle", "restore", "restored_by", 200)
_HARD_DELETE_ROUTE = (_HARD_DELETE, "approvals", "request_hard_delete", "requested_by", 202)
_RELEASE_ROUTE = (_RELEASE, "approvals", "request_release", "requested_by", 202)

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


@pytest.mark.parametrize(
    ("path", "service", "method", "actor_kwarg", "status", "body"), _ACTOR_CASES)
def test_the_caller_is_recorded_whoever_the_body_names(
    client: TestClient, lifecycle_svc: Any, approvals: Any, path: str, service: str,
    method: str, actor_kwarg: str, status: int, body: dict[str, Any] | None,
) -> None:
    svc = {"lifecycle": lifecycle_svc, "approvals": approvals}[service]

    response = client.post(path, json=body, headers=_as(_CALLER))

    assert response.status_code == status, response.text
    call = getattr(svc, method)
    call.assert_awaited_once()
    assert call.await_args.kwargs[actor_kwarg] == _CALLER
    assert call.await_args.kwargs["tenant_id"] == _TENANT


def test_a_witness_the_caller_names_approves_nothing(
    client: TestClient, lifecycle_svc: Any, approvals: Any,
) -> None:
    response = client.post(_HARD_DELETE, headers=_as(_CALLER),
                           json={"destroyed_by": _CALLER, "witness_user_id": _OTHER_USER})

    assert response.status_code == 202, response.text
    assert response.json()["destroyed"] is False
    assert approvals.request_hard_delete.await_args.kwargs["requested_by"] == _CALLER
    approvals.approve.assert_not_awaited()
    lifecycle_svc.hard_delete.assert_not_awaited()


@pytest.mark.parametrize(("path", "method", "actor_kwarg"), [
    pytest.param(_APPROVE, "approve", "approved_by", id="approve"),
    pytest.param(_REJECT, "reject", "rejected_by", id="reject"),
])
def test_the_caller_is_who_approves_or_rejects(
    client: TestClient, approvals: Any, path: str, method: str, actor_kwarg: str,
) -> None:
    response = client.post(path, headers=_as(_OTHER_USER))

    assert response.status_code == 200, response.text
    call = getattr(approvals, method)
    call.assert_awaited_once()
    assert call.await_args.kwargs[actor_kwarg] == _OTHER_USER
    kwargs = call.await_args.kwargs
    assert (kwargs["approval_id"], kwargs["tenant_id"]) == (_APR, _TENANT)


@pytest.mark.parametrize(("path", "body"), [
    pytest.param(_RESTORE, None, id="restore"),
    pytest.param(_HARD_DELETE, {"destroyed_by": _OTHER_USER}, id="hard-delete"),
    pytest.param(_RELEASE, {"released_by": _OTHER_USER}, id="release"),
    pytest.param(_APPROVE, None, id="approve"),
    pytest.param(_REJECT, None, id="reject"),
])
def test_a_call_without_a_user_is_refused_not_recorded_as_whoever_it_names(
    client: TestClient, lifecycle_svc: Any, approvals: Any,
    path: str, body: dict[str, Any] | None,
) -> None:
    # What a service-account token brings: a tenant and no user.
    response = client.post(path, json=body, headers={"X-Tenant-Id": _TENANT, "X-Actor": "SERVICE"})

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "FOUNDATION.LIFECYCLE.POLICY.PERMISSION_DENIED"
    for call in (lifecycle_svc.restore, lifecycle_svc.hard_delete, approvals.request_hard_delete,
                 approvals.request_release, approvals.approve, approvals.reject):
        call.assert_not_awaited()


def test_list_approval_requests_hands_the_filters_to_the_service(
    client: TestClient, approvals: Any,
) -> None:
    approvals.list_requests.return_value = (
        [make_approval_request(approval_id=_APR, tenant_id=_TENANT, requested_by=_CALLER)], None)

    response = client.get(_APPROVALS, headers={"X-Tenant-Id": _TENANT}, params={
        "filter.status": "PENDING", "filter.operation": "HARD_DELETE", "limit": "10"})

    assert response.status_code == 200, response.text
    assert [r["id"] for r in response.json()["items"]] == [_APR]
    kwargs = approvals.list_requests.await_args.kwargs
    assert (kwargs["tenant_id"], kwargs["status"], kwargs["operation"], kwargs["limit"]) == (
        _TENANT, "PENDING", "HARD_DELETE", 10)


@pytest.mark.parametrize("params", [
    pytest.param({"filter.status": "OPEN"}, id="status"),
    pytest.param({"filter.operation": "RESTORE"}, id="operation"),
])
def test_list_approval_requests_refuses_an_unknown_filter_value(
    client: TestClient, approvals: Any, params: dict[str, str],
) -> None:
    response = client.get(_APPROVALS, headers={"X-Tenant-Id": _TENANT}, params=params)

    assert response.status_code == 422
    approvals.list_requests.assert_not_awaited()


def test_the_openapi_marks_the_body_actor_fields_deprecated_and_no_body_required() -> None:
    spec = create_app().openapi()
    schemas = spec["components"]["schemas"]

    for path, model, fields in [
        (_RESTORE, "RestoreRequest", {"restored_by"}),
        (_HARD_DELETE, "HardDeleteRequest", {"destroyed_by", "witness_user_id"}),
        (_RELEASE, "ReleaseLegalHoldRequest", {"released_by"}),
    ]:
        template = path.replace(_BIN, "{bin_id}").replace(_HOLD, "{hold_id}")
        assert not spec["paths"][template]["post"]["requestBody"].get("required"), path
        assert "required" not in schemas[model], model
        assert set(schemas[model]["properties"]) == fields
        assert all(schemas[model]["properties"][f].get("deprecated") for f in fields), model


def test_the_openapi_answers_hard_delete_and_release_with_202_until_approved() -> None:
    paths = create_app().openapi()["paths"]

    for template in ("/api/lifecycle/v1/recycle-bin/{bin_id}:hard-delete",
                     "/api/lifecycle/v1/legal-holds/{hold_id}:release"):
        assert set(paths[template]["post"]["responses"]) >= {"200", "202"}, template


# -- Four-eyes end to end: the real services over one fake session, one request per step --

@pytest.fixture
def flow(fake_session: Any) -> TestClient:
    app = create_app()

    async def _fake_db() -> AsyncIterator[Any]:
        yield fake_session  # what one request writes, the next one finds

    app.dependency_overrides[dependencies.db_session] = _fake_db
    return TestClient(app)


def test_a_hard_delete_waits_for_a_second_user_who_is_recorded_as_witness(
    flow: TestClient, fake_session: Any,
) -> None:
    rt = make_resource_type(requires_cert=True)
    entry = make_recycle_bin_entry(bin_id=_BIN, tenant_id=_TENANT, resource_type_id=rt.id)
    fake_session.put(rt)
    fake_session.put(entry)

    asked = flow.post(_HARD_DELETE, headers=_as(_CALLER))

    assert asked.status_code == 202, asked.text
    assert asked.json()["destroyed"] is False
    req = asked.json()["approval_request"]
    assert (req["operation"], req["target_id"], req["status"], req["requested_by"]) == (
        "HARD_DELETE", _BIN, "PENDING", _CALLER)
    assert entry.hard_deleted_at is None  # unapproved, nothing is destroyed
    approve = f"{_APPROVALS}/{req['id']}/approve"

    own = flow.post(approve, headers=_as(_CALLER))

    assert own.status_code == 403
    assert own.json()["code"] == "FOUNDATION.LIFECYCLE.POLICY.SELF_APPROVAL_FORBIDDEN"
    assert entry.hard_deleted_at is None

    approved = flow.post(approve, headers=_as(_OTHER_USER))

    assert approved.status_code == 200, approved.text
    assert (approved.json()["status"], approved.json()["decided_by"]) == ("APPROVED", _OTHER_USER)
    assert entry.hard_deleted_at is not None
    (cert,) = (obj for obj in fake_session.added if isinstance(obj, DestructionCertificate))
    assert (cert.destroyed_by, cert.witness_user_id) == (_CALLER, _OTHER_USER)

    again = flow.post(approve, headers=_as(_OTHER_USER))
    shown = flow.get(f"{_APPROVALS}/{req['id']}", headers=_as(_CALLER))
    asked_again = flow.post(_HARD_DELETE, headers=_as(_CALLER))

    assert again.status_code == 409
    assert again.json()["code"] == "FOUNDATION.LIFECYCLE.STATE.APPROVAL_NOT_PENDING"
    assert shown.json()["status"] == "APPROVED"
    assert (asked_again.status_code, asked_again.json()) == (200, {"destroyed": True})


def test_a_release_waits_for_a_second_user(flow: TestClient, fake_session: Any) -> None:
    hold = make_legal_hold(hold_id=_HOLD, tenant_id=_TENANT)
    fake_session.put(hold)

    asked = flow.post(_RELEASE, json={"released_by": _OTHER_USER}, headers=_as(_CALLER))

    assert asked.status_code == 202, asked.text
    assert asked.json()["released"] is False
    req = asked.json()["approval_request"]
    assert (req["operation"], req["target_id"], req["requested_by"]) == (
        "RELEASE_LEGAL_HOLD", _HOLD, _CALLER)
    assert hold.released_at is None  # unapproved, the hold stays

    approved = flow.post(f"{_APPROVALS}/{req['id']}/approve", headers=_as(_OTHER_USER))
    asked_again = flow.post(_RELEASE, headers=_as(_CALLER))

    assert approved.status_code == 200, approved.text
    assert (hold.released_at is not None, hold.released_by) == (True, _CALLER)
    assert (asked_again.status_code, asked_again.json()) == (200, {"released": True})


def test_a_rejected_hard_delete_destroys_nothing(flow: TestClient, fake_session: Any) -> None:
    entry = make_recycle_bin_entry(bin_id=_BIN, tenant_id=_TENANT)
    fake_session.put(entry)
    req = flow.post(_HARD_DELETE, headers=_as(_CALLER)).json()["approval_request"]

    rejected = flow.post(f"{_APPROVALS}/{req['id']}/reject", headers=_as(_OTHER_USER))
    approved = flow.post(f"{_APPROVALS}/{req['id']}/approve", headers=_as(_OTHER_USER))

    assert (rejected.status_code, rejected.json()["status"]) == (200, "REJECTED")
    assert approved.status_code == 409
    assert entry.hard_deleted_at is None


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
