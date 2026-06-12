"""HTTP-facing tests for the mounted DLP SDK-compatible API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from foundation_dlp.api.dependencies import db_session, dlp_service
from foundation_dlp.domain.models import Classification, DLPRule
from foundation_dlp.main import create_app

TENANT_ID = "tnt_01J0000000000000000000TNT1"
USER_ID = "usr_01J0000000000000000000USR1"


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _FakeSession:
    def __init__(self) -> None:
        self.added: list[Any] = []
        self.flush_calls = 0

    async def scalars(self, _stmt: Any) -> _Rows:
        return _Rows([
            DLPRule(
                id="rule_1",
                tenant_id=TENANT_ID,
                name="id-card",
                rule_type="KEYWORD",
                pattern='["身份证"]',
                min_sensitivity="L3",
                enabled=True,
            )
        ])

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flush_calls += 1


class _FakeDLPService:
    async def get_sensitivity(self, *_args: Any, **kwargs: Any) -> Classification:
        return Classification(
            id="cls_existing",
            tenant_id=kwargs["tenant_id"],
            resource_type=kwargs["resource_type"],
            resource_id=kwargs["resource_id"],
            sensitivity="L3",
            tags=["pii"],
            reason=None,
            tagged_by=USER_ID,
            downgradable=True,
        )

    async def check_read(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "allowed": kwargs["user_clearance"] >= "L3",
            "sensitivity": "L3",
            "reason": None,
        }

    async def check_download(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "allowed": kwargs["user_clearance"] >= "L3",
            "sensitivity": "L3",
            "reason": None,
        }

    async def scan_content(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "hits": [{"rule_id": "rule_1", "sensitivity": "L3"}],
            "max_sensitivity": "L3",
            "content_type": kwargs["resource_type"],
        }

    async def tag_resource(self, *_args: Any, **kwargs: Any) -> Classification:
        return Classification(
            id="cls_1",
            tenant_id=kwargs["tenant_id"],
            resource_type=kwargs["resource_type"],
            resource_id=kwargs["resource_id"],
            sensitivity=kwargs["sensitivity"],
            tags=[],
            reason=kwargs["reason"],
            tagged_by=kwargs["tagged_by"],
            downgradable=True,
        )


def _client() -> TestClient:
    app = create_app()

    async def fake_db_session() -> AsyncIterator[_FakeSession]:
        yield _FakeSession()

    app.dependency_overrides[db_session] = fake_db_session
    app.dependency_overrides[dlp_service] = _FakeDLPService
    return TestClient(app, raise_server_exceptions=False)


def _headers() -> dict[str, str]:
    return {"X-Tenant-Id": TENANT_ID, "X-User-Id": USER_ID}


def test_healthz_returns_request_id() -> None:
    response = _client().get("/api/dlp/v1/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "OK"
    assert response.headers["X-Request-Id"].startswith("req_")


def test_invalid_tenant_header_returns_problem() -> None:
    response = _client().post(
        "/api/dlp/v1/check-download",
        json={"file_id": "file_1", "sensitivity": "L3"},
        headers={"X-Tenant-Id": "bad"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "FOUNDATION.DLP.INPUT.INVALID_FORMAT"


def test_check_download_uses_context_user() -> None:
    response = _client().post(
        "/api/dlp/v1/check-download",
        json={"file_id": "file_1", "sensitivity": "L4"},
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_core_classification_endpoints_are_mounted() -> None:
    client = _client()

    tag_response = client.post(
        "/api/dlp/v1/core/classification:tag",
        json={
            "resource_type": "document",
            "resource_id": "doc_1",
            "sensitivity": "L4",
            "tags": ["secret"],
        },
        headers=_headers(),
    )
    get_response = client.get(
        "/api/dlp/v1/core/classification:get",
        params={"resource_type": "document", "resource_id": "doc_1"},
        headers=_headers(),
    )

    assert tag_response.status_code == 201
    assert tag_response.json()["tagged"] is True
    assert get_response.status_code == 200
    assert get_response.json()["sensitivity"] == "L3"


def test_core_read_check_endpoint_is_mounted() -> None:
    response = _client().post(
        "/api/dlp/v1/core/check:read",
        json={
            "user_id": USER_ID,
            "user_clearance": "L2",
            "resource_type": "document",
            "resource_id": "doc_1",
        },
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_scan_content_maps_sdk_shape() -> None:
    response = _client().post(
        "/api/dlp/v1/scan",
        json={"content": "身份证", "content_type": "text/plain"},
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["max_sensitivity"] == "L3"
    assert response.json()["content_type"] == "text/plain"


def test_classify_file_returns_sdk_response() -> None:
    response = _client().post(
        "/api/dlp/v1/classify",
        json={"file_id": "file_1", "sensitivity": "L4", "reason": "contains secrets"},
        headers=_headers(),
    )

    assert response.status_code == 201
    assert response.json()["classified"] is True
    assert response.json()["sensitivity"] == "L4"


def test_sensitive_words_read_and_create() -> None:
    client = _client()

    list_response = client.get("/api/dlp/v1/sensitive-words", headers=_headers())
    create_response = client.post(
        "/api/dlp/v1/sensitive-words",
        json={"word": "身份证", "category": "PII"},
        headers=_headers(),
    )

    assert list_response.status_code == 200
    assert list_response.json()["items"][0]["name"] == "id-card"
    assert create_response.status_code == 201
    assert create_response.json()["created"] is True


# --------------------------------------------------------------------------- governance reads


class _GovDLPService:
    """Records call kwargs and returns fixed governance payloads."""

    def __init__(self) -> None:
        self.calls: dict[str, dict[str, Any]] = {}

    async def list_events(self, _session: Any, **kwargs: Any) -> list[Any]:
        self.calls["list_events"] = kwargs
        from foundation_dlp.domain.models import DLPEvent

        return [
            DLPEvent(id=2, tenant_id=kwargs["tenant_id"], check_type="SCAN",
                     decision="QUARANTINE", user_id=USER_ID, resource_type="doc",
                     resource_id="d1", reason_code=None, detail='{"max_sensitivity": "L4"}',
                     occurred_at=datetime(2026, 6, 1, tzinfo=UTC), request_id="req_x"),
        ]

    async def list_classifications(self, _session: Any, **kwargs: Any) -> list[Any]:
        self.calls["list_classifications"] = kwargs
        return [
            Classification(id="cls_a", tenant_id=kwargs["tenant_id"], resource_type="doc",
                           resource_id="d1", sensitivity="L4", tags=["pii"], reason="r",
                           tagged_by=USER_ID, tagged_at=datetime(2026, 6, 1, tzinfo=UTC),
                           updated_at=datetime(2026, 6, 2, tzinfo=UTC), downgradable=False),
        ]

    async def stats(self, _session: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls["stats"] = kwargs
        return {"by_decision": {"ALLOW": 3}, "by_check_type": {"SCAN": 1},
                "by_sensitivity": {"L4": 2}, "total_events": 3}


def _gov_client() -> tuple[TestClient, _GovDLPService]:
    app = create_app()
    svc = _GovDLPService()

    async def fake_db_session() -> AsyncIterator[_FakeSession]:
        yield _FakeSession()

    app.dependency_overrides[db_session] = fake_db_session
    app.dependency_overrides[dlp_service] = lambda: svc
    return TestClient(app, raise_server_exceptions=False), svc


def test_events_endpoint_lists_and_passes_filters() -> None:
    client, svc = _gov_client()
    response = client.get(
        "/api/dlp/v1/core/events",
        params={"check_type": "SCAN", "decision": "QUARANTINE", "limit": 50},
        headers=_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["items"][0]["check_type"] == "SCAN"
    assert body["items"][0]["id"] == 2
    assert body["next_before"] is None  # fewer rows than limit
    assert svc.calls["list_events"]["tenant_id"] == TENANT_ID
    assert svc.calls["list_events"]["check_type"] == "SCAN"


def test_events_endpoint_rejects_oversized_limit() -> None:
    response = _gov_client()[0].get(
        "/api/dlp/v1/core/events", params={"limit": 999}, headers=_headers())
    assert response.status_code == 422


def test_classifications_endpoint_lists() -> None:
    client, svc = _gov_client()
    response = client.get(
        "/api/dlp/v1/core/classifications",
        params={"sensitivity": "L4"},
        headers=_headers(),
    )

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["sensitivity"] == "L4"
    assert item["downgradable"] is False
    assert svc.calls["list_classifications"]["sensitivity"] == "L4"


def test_stats_endpoint_returns_aggregates() -> None:
    response = _gov_client()[0].get("/api/dlp/v1/core/stats", headers=_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["by_decision"] == {"ALLOW": 3}
    assert body["by_sensitivity"] == {"L4": 2}
    assert body["total_events"] == 3
