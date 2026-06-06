"""HTTP-facing tests for the mounted DLP SDK-compatible API."""

from __future__ import annotations

from collections.abc import AsyncIterator
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
