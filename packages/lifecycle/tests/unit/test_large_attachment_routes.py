"""HTTP-level tests for the large-attachment subject-allows endpoints.

Covers the three new generalized subject-allows routes (design
``docs/large-attachment-subject-allows.md`` §3):

* ``GET    /large-attachment/subject-allows`` — scope-gated + {items:[]} shape.
* ``PUT    /large-attachment/subject-allows`` — USER/TEAM/ORG_UNIT upsert; 422
  on a garbage subject_type.
* ``DELETE /large-attachment/subject-allows/{subject_type}/{subject_id}`` — 200
  on hit, 404 when missing.

The routes are wired against a network-free fake ``LargeAttachmentService`` (via
``dependency_overrides``) so we exercise the HTTP layer — scope gating, request
parsing, status codes, response shape — without a DB or org service. The tenant
context is supplied through the ``X-Tenant-Id`` header consumed by
``TenantContextMiddleware``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi.testclient import TestClient

from foundation_lifecycle.api import dependencies
from foundation_lifecycle.main import create_app

_PREFIX = "/api/lifecycle/v1"
_ADMIN_HEADER = {"X-Foundation-Scopes": "large_attachment.admin"}
# Must match TENANT_ID_PATTERN (``tnt_`` + 26 Crockford base32 chars).
_TENANT_ID = "tnt_00000000000000000000000001"
_TENANT_HEADER = {"X-Tenant-Id": _TENANT_ID}


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #
class _Row:
    """Stand-in for ``SubjectLargeAttachmentAllow`` rows the service returns."""

    def __init__(
        self,
        *,
        subject_type: str,
        subject_id: str,
        allowed: bool,
        tenant_id: str = _TENANT_ID,
        row_id: str | None = None,
        updated_by: str | None = None,
    ) -> None:
        self.id = row_id or f"las_{subject_type.lower()}_{subject_id}"
        self.tenant_id = tenant_id
        self.subject_type = subject_type
        self.subject_id = subject_id
        self.allowed = allowed
        self.updated_at = None
        self.updated_by = updated_by


class _FakeService:
    """Network-free fake matching the real service surface the routes call.

    ``serialize_subject_allow`` reuses the real (static) serializer so the
    response shape assertions stay honest.
    """

    def __init__(self, *, rows: list[_Row] | None = None) -> None:
        self._rows = list(rows or [])
        self.delete_returns = True
        self.upsert_calls: list[dict[str, Any]] = []
        self.delete_calls: list[dict[str, Any]] = []

    async def list_subject_allows(
        self, session: Any, *, tenant_id: str
    ) -> list[_Row]:
        return list(self._rows)

    async def upsert_subject_allow(
        self,
        session: Any,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
        allowed: bool,
        actor: str,
    ) -> _Row:
        # Mirror the real service: guard the enum, raise ValueError otherwise.
        if subject_type not in {"USER", "TEAM", "ORG_UNIT"}:
            raise ValueError(f"invalid subject_type: {subject_type!r}")
        self.upsert_calls.append(
            {
                "tenant_id": tenant_id,
                "subject_type": subject_type,
                "subject_id": subject_id,
                "allowed": allowed,
                "actor": actor,
            }
        )
        return _Row(
            subject_type=subject_type,
            subject_id=subject_id,
            allowed=allowed,
            tenant_id=tenant_id,
            updated_by=actor,
        )

    async def delete_subject_allow(
        self, session: Any, *, tenant_id: str, subject_type: str, subject_id: str
    ) -> bool:
        self.delete_calls.append(
            {
                "tenant_id": tenant_id,
                "subject_type": subject_type,
                "subject_id": subject_id,
            }
        )
        return self.delete_returns

    @staticmethod
    def serialize_subject_allow(row: _Row) -> dict[str, Any]:
        from foundation_lifecycle.services.large_attachment_service import (
            LargeAttachmentService,
        )

        return LargeAttachmentService.serialize_subject_allow(row)  # type: ignore[arg-type]


def _client_with_service(svc: _FakeService) -> TestClient:
    app = create_app()

    async def _fake_session() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[dependencies.db_session] = _fake_session
    app.dependency_overrides[dependencies.large_attachment_service] = lambda: svc
    return TestClient(app, raise_server_exceptions=True)


# --------------------------------------------------------------------------- #
# GET /large-attachment/subject-allows                                        #
# --------------------------------------------------------------------------- #
def test_list_subject_allows_requires_scope() -> None:
    client = _client_with_service(_FakeService())
    resp = client.get(
        f"{_PREFIX}/large-attachment/subject-allows",
        headers=_TENANT_HEADER,
    )
    assert resp.status_code == 403


def test_list_subject_allows_returns_items_envelope() -> None:
    rows = [
        _Row(subject_type="USER", subject_id="usr_a", allowed=True),
        _Row(subject_type="TEAM", subject_id="tem_b", allowed=False),
        _Row(subject_type="ORG_UNIT", subject_id="oun_c", allowed=True),
    ]
    client = _client_with_service(_FakeService(rows=rows))
    resp = client.get(
        f"{_PREFIX}/large-attachment/subject-allows",
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert set(payload.keys()) == {"items"}
    items = payload["items"]
    assert len(items) == 3
    by_id = {it["subject_id"]: it for it in items}
    assert by_id["usr_a"]["subject_type"] == "USER"
    assert by_id["usr_a"]["allowed"] is True
    assert by_id["tem_b"]["subject_type"] == "TEAM"
    assert by_id["oun_c"]["subject_type"] == "ORG_UNIT"
    # Subject shape carries subject_type/subject_id (not the legacy user_id key).
    assert "user_id" not in items[0]


def test_list_subject_allows_empty_envelope() -> None:
    client = _client_with_service(_FakeService(rows=[]))
    resp = client.get(
        f"{_PREFIX}/large-attachment/subject-allows",
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"items": []}


# --------------------------------------------------------------------------- #
# PUT /large-attachment/subject-allows                                        #
# --------------------------------------------------------------------------- #
def test_put_subject_allow_requires_scope() -> None:
    client = _client_with_service(_FakeService())
    resp = client.put(
        f"{_PREFIX}/large-attachment/subject-allows",
        json={"subject_type": "USER", "subject_id": "usr_x", "allowed": True},
        headers=_TENANT_HEADER,
    )
    assert resp.status_code == 403


def test_put_subject_allow_user_happy_path() -> None:
    svc = _FakeService()
    client = _client_with_service(svc)
    resp = client.put(
        f"{_PREFIX}/large-attachment/subject-allows",
        json={"subject_type": "USER", "subject_id": "usr_x", "allowed": True},
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject_type"] == "USER"
    assert body["subject_id"] == "usr_x"
    assert body["allowed"] is True
    assert body["tenant_id"] == _TENANT_ID
    assert svc.upsert_calls[0]["subject_type"] == "USER"
    assert svc.upsert_calls[0]["tenant_id"] == _TENANT_ID


def test_put_subject_allow_team_happy_path() -> None:
    svc = _FakeService()
    client = _client_with_service(svc)
    resp = client.put(
        f"{_PREFIX}/large-attachment/subject-allows",
        json={"subject_type": "TEAM", "subject_id": "tem_eng", "allowed": True},
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject_type"] == "TEAM"
    assert body["subject_id"] == "tem_eng"


def test_put_subject_allow_org_unit_happy_path() -> None:
    svc = _FakeService()
    client = _client_with_service(svc)
    resp = client.put(
        f"{_PREFIX}/large-attachment/subject-allows",
        json={
            "subject_type": "ORG_UNIT",
            "subject_id": "oun_eng",
            "allowed": False,
        },
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject_type"] == "ORG_UNIT"
    assert body["subject_id"] == "oun_eng"
    assert body["allowed"] is False


def test_put_subject_allow_invalid_type_is_422() -> None:
    # Garbage subject_type is rejected by the pydantic Literal before the
    # service is ever consulted → FastAPI 422.
    svc = _FakeService()
    client = _client_with_service(svc)
    resp = client.put(
        f"{_PREFIX}/large-attachment/subject-allows",
        json={"subject_type": "ROLE", "subject_id": "rol_x", "allowed": True},
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 422, resp.text
    # The service guard was never reached.
    assert svc.upsert_calls == []


# --------------------------------------------------------------------------- #
# DELETE /large-attachment/subject-allows/{subject_type}/{subject_id}         #
# --------------------------------------------------------------------------- #
def test_delete_subject_allow_requires_scope() -> None:
    client = _client_with_service(_FakeService())
    resp = client.delete(
        f"{_PREFIX}/large-attachment/subject-allows/TEAM/tem_x",
        headers=_TENANT_HEADER,
    )
    assert resp.status_code == 403


def test_delete_subject_allow_missing_is_404() -> None:
    svc = _FakeService()
    svc.delete_returns = False
    client = _client_with_service(svc)
    resp = client.delete(
        f"{_PREFIX}/large-attachment/subject-allows/TEAM/tem_nope",
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 404, resp.text
    assert svc.delete_calls[0] == {
        "tenant_id": _TENANT_ID,
        "subject_type": "TEAM",
        "subject_id": "tem_nope",
    }


def test_delete_subject_allow_existing_returns_deleted_shape() -> None:
    svc = _FakeService()
    svc.delete_returns = True
    client = _client_with_service(svc)
    resp = client.delete(
        f"{_PREFIX}/large-attachment/subject-allows/ORG_UNIT/oun_eng",
        headers={**_TENANT_HEADER, **_ADMIN_HEADER},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "deleted": True,
        "subject_type": "ORG_UNIT",
        "subject_id": "oun_eng",
    }
