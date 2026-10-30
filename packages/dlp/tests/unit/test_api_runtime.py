"""HTTP-facing tests for the mounted DLP SDK-compatible API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from foundation_dlp.api.dependencies import clearance_provider, db_session, dlp_service
from foundation_dlp.domain.models import Classification, DLPRule
from foundation_dlp.main import create_app
from foundation_dlp.services.clearance_provider import ClearanceProviderError

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
        return _Rows(
            [
                DLPRule(
                    id="rule_1",
                    tenant_id=TENANT_ID,
                    name="id-card",
                    rule_type="KEYWORD",
                    pattern='["身份证"]',
                    min_sensitivity="L3",
                    enabled=True,
                )
            ]
        )

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
            "user_id": kwargs["user_id"],
            "destination": kwargs["destination"],
        }

    async def scan_content(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "hits": [{"rule_id": "rule_1", "sensitivity": "L3"}],
            "max_sensitivity": "L3",
            "content_type": kwargs["resource_type"],
            "resource_id": kwargs["resource_id"],
            "classification_persisted": kwargs.get("persist_classification", True),
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


class _FakeClearanceProvider:
    def __init__(self, clearance: str = "L3", *, fail: bool = False) -> None:
        self.clearance = clearance
        self.fail = fail
        self.calls: list[dict[str, str]] = []

    async def get_clearance(self, **kwargs: str) -> str:
        self.calls.append(kwargs)
        if self.fail:
            raise ClearanceProviderError("identity unavailable")
        return self.clearance


def _client(*, provider: _FakeClearanceProvider | None = None) -> TestClient:
    app = create_app()
    provider = provider or _FakeClearanceProvider()

    async def fake_db_session() -> AsyncIterator[_FakeSession]:
        yield _FakeSession()

    app.dependency_overrides[db_session] = fake_db_session
    app.dependency_overrides[dlp_service] = _FakeDLPService
    app.dependency_overrides[clearance_provider] = lambda: provider
    return TestClient(app, raise_server_exceptions=False)


def _headers(*, actor: str = "USER") -> dict[str, str]:
    return {"X-Tenant-Id": TENANT_ID, "X-User-Id": USER_ID, "X-Actor": actor}


def test_healthz_returns_request_id() -> None:
    response = _client().get("/api/dlp/v1/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "OK"
    assert response.headers["X-Request-Id"].startswith("req_")


def test_invalid_tenant_header_returns_problem() -> None:
    response = _client().post(
        "/api/dlp/v1/check-download",
        json={"file_id": "file_1", "destination": "laptop"},
        headers={"X-Tenant-Id": "bad"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "FOUNDATION.DLP.INPUT.INVALID_FORMAT"


def test_invalid_user_header_returns_problem() -> None:
    response = _client().post(
        "/api/dlp/v1/check-download",
        json={"file_id": "file_1", "destination": "laptop"},
        headers={"X-Tenant-Id": TENANT_ID, "X-User-Id": "../../admin"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "FOUNDATION.DLP.INPUT.INVALID_FORMAT"


def test_check_download_uses_context_user() -> None:
    provider = _FakeClearanceProvider("L4")
    response = _client(provider=provider).post(
        "/api/dlp/v1/check-download",
        json={"file_id": "file_1", "destination": "usb"},
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True
    assert response.json()["user_id"] == USER_ID
    assert response.json()["destination"] == "usb"
    assert provider.calls[0]["user_id"] == USER_ID


def test_check_download_rejects_caller_supplied_sensitivity() -> None:
    response = _client().post(
        "/api/dlp/v1/check-download",
        json={"file_id": "file_1", "sensitivity": "L5"},
        headers=_headers(),
    )

    assert response.status_code == 422


def test_access_check_fails_closed_when_clearance_is_unavailable() -> None:
    response = _client(provider=_FakeClearanceProvider(fail=True)).post(
        "/api/dlp/v1/core/check:read",
        json={"resource_type": "document", "resource_id": "doc_1"},
        headers=_headers(),
    )

    assert response.status_code == 503
    assert response.json()["code"] == "FOUNDATION.DLP.DEPENDENCY.CLEARANCE_UNAVAILABLE"


def test_access_check_fails_closed_on_invalid_provider_clearance() -> None:
    response = _client(provider=_FakeClearanceProvider("L6")).post(
        "/api/dlp/v1/core/check:read",
        json={"resource_type": "document", "resource_id": "doc_1"},
        headers=_headers(),
    )

    assert response.status_code == 503
    assert response.json()["code"] == "FOUNDATION.DLP.DEPENDENCY.CLEARANCE_UNAVAILABLE"


def test_access_check_requires_context_user() -> None:
    response = _client().post(
        "/api/dlp/v1/core/check:read",
        json={"resource_type": "document", "resource_id": "doc_1"},
        headers={"X-Tenant-Id": TENANT_ID},
    )

    assert response.status_code == 401


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
        headers=_headers(actor="SERVICE"),
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
    response = _client(provider=_FakeClearanceProvider("L2")).post(
        "/api/dlp/v1/core/check:read",
        json={
            "resource_type": "document",
            "resource_id": "doc_1",
        },
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_core_read_rejects_caller_supplied_identity_fields() -> None:
    response = _client().post(
        "/api/dlp/v1/core/check:read",
        json={
            "user_id": "usr_01J0000000000000000000BAD1",
            "user_clearance": "L5",
            "resource_type": "document",
            "resource_id": "doc_1",
        },
        headers=_headers(),
    )

    assert response.status_code == 422


def test_scan_content_maps_sdk_shape() -> None:
    response = _client().post(
        "/api/dlp/v1/scan",
        json={"content": "身份证", "content_type": "text/plain"},
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["max_sensitivity"] == "L3"
    assert response.json()["content_type"] == "text/plain"
    assert response.json()["resource_id"] is None
    assert response.json()["classification_persisted"] is False


def test_core_scan_uses_real_resource_identity_for_classification() -> None:
    response = _client().post(
        "/api/dlp/v1/core/scan",
        json={
            "content": "身份证",
            "resource_type": "document",
            "resource_id": "doc_1",
        },
        headers=_headers(actor="SERVICE"),
    )

    assert response.status_code == 200
    assert response.json()["resource_id"] == "doc_1"
    assert response.json()["classification_persisted"] is True


def test_core_scan_user_actor_gets_verdict_without_persisting_classification() -> None:
    # A non-management caller may scan, but the scan must never write the
    # resource's classification label (which drives check:read/check:download).
    response = _client().post(
        "/api/dlp/v1/core/scan",
        json={
            "content": "身份证",
            "resource_type": "document",
            "resource_id": "doc_1",
        },
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["max_sensitivity"] == "L3"
    assert response.json()["resource_id"] == "doc_1"
    assert response.json()["classification_persisted"] is False


def test_core_scan_accepts_sandbox_worker_tool_call_shape() -> None:
    # Regression: the agent worker's PreToolUse hook (direct, or via the
    # tool-broker which strips X-Actor) sends only a bearer + X-Tenant-Id.  This
    # was a 403 DLP_DENIED, so every tool-call scan silently failed open.
    response = _client().post(
        "/api/dlp/v1/core/scan",
        json={
            "content": '{"command":"echo 身份证"}',
            "resource_type": "tool_call",
            "resource_id": "Bash:toolu_1",
        },
        headers={"Authorization": "Bearer sandbox-token", "X-Tenant-Id": TENANT_ID},
    )

    assert response.status_code == 200
    assert response.json()["max_sensitivity"] == "L3"
    assert response.json()["classification_persisted"] is False


def test_core_scan_spoofed_admin_header_cannot_persist_classification() -> None:
    # ADMIN is never accepted from a header (it downgrades to USER), so it must
    # not unlock label persistence either.
    response = _client().post(
        "/api/dlp/v1/core/scan",
        json={"content": "身份证", "resource_type": "document", "resource_id": "doc_1"},
        headers=_headers(actor="ADMIN"),
    )

    assert response.status_code == 200
    assert response.json()["classification_persisted"] is False


def test_core_scan_requires_tenant_context() -> None:
    response = _client().post(
        "/api/dlp/v1/core/scan",
        json={"content": "身份证", "resource_type": "document", "resource_id": "doc_1"},
    )

    assert response.status_code == 401


def test_classify_file_returns_sdk_response() -> None:
    response = _client().post(
        "/api/dlp/v1/classify",
        json={"file_id": "file_1", "sensitivity": "L4", "reason": "contains secrets"},
        headers=_headers(actor="SERVICE"),
    )

    assert response.status_code == 201
    assert response.json()["classified"] is True
    assert response.json()["sensitivity"] == "L4"


def test_sensitive_words_read_and_create() -> None:
    client = _client()

    list_response = client.get("/api/dlp/v1/sensitive-words", headers=_headers(actor="SERVICE"))
    create_response = client.post(
        "/api/dlp/v1/sensitive-words",
        json={"word": "身份证", "category": "PII"},
        headers=_headers(actor="SERVICE"),
    )

    assert list_response.status_code == 200
    assert list_response.json()["items"][0]["name"] == "id-card"
    assert create_response.status_code == 201
    assert create_response.json()["created"] is True


def test_management_endpoints_reject_user_actor() -> None:
    client = _client()

    classify = client.post(
        "/api/dlp/v1/classify",
        json={"file_id": "file_1", "sensitivity": "L4"},
        headers=_headers(),
    )
    words = client.get("/api/dlp/v1/sensitive-words", headers=_headers())

    assert classify.status_code == 403
    assert words.status_code == 403


def test_classification_rejects_invalid_sensitivity() -> None:
    response = _client().post(
        "/api/dlp/v1/classify",
        json={"file_id": "file_1", "sensitivity": "L6"},
        headers=_headers(actor="SERVICE"),
    )

    assert response.status_code == 422


# --------------------------------------------------------------------------- governance reads


class _GovDLPService:
    """Records call kwargs and returns fixed governance payloads."""

    def __init__(self) -> None:
        self.calls: dict[str, dict[str, Any]] = {}

    async def list_events(self, _session: Any, **kwargs: Any) -> list[Any]:
        self.calls["list_events"] = kwargs
        from foundation_dlp.domain.models import DLPEvent

        return [
            DLPEvent(
                id=2,
                tenant_id=kwargs["tenant_id"],
                check_type="SCAN",
                decision="QUARANTINE",
                user_id=USER_ID,
                resource_type="doc",
                resource_id="d1",
                reason_code=None,
                detail='{"max_sensitivity": "L4"}',
                occurred_at=datetime(2026, 6, 1, tzinfo=UTC),
                request_id="req_x",
            ),
        ]

    async def list_classifications(self, _session: Any, **kwargs: Any) -> list[Any]:
        self.calls["list_classifications"] = kwargs
        return [
            Classification(
                id="cls_a",
                tenant_id=kwargs["tenant_id"],
                resource_type="doc",
                resource_id="d1",
                sensitivity="L4",
                tags=["pii"],
                reason="r",
                tagged_by=USER_ID,
                tagged_at=datetime(2026, 6, 1, tzinfo=UTC),
                updated_at=datetime(2026, 6, 2, tzinfo=UTC),
                downgradable=False,
            ),
        ]

    async def stats(self, _session: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls["stats"] = kwargs
        return {
            "by_decision": {"ALLOW": 3},
            "by_check_type": {"SCAN": 1},
            "by_sensitivity": {"L4": 2},
            "total_events": 3,
        }


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
        "/api/dlp/v1/core/events", params={"limit": 999}, headers=_headers()
    )
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
