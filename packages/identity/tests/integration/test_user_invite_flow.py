"""End-to-end-ish: POST /users invites a user, mocks Keycloak, asserts side effects.

Marked `integration` because it exercises the full app stack (middleware →
router → service → audit publisher).  No real Postgres yet — DB session is
patched at the dependency layer so the unit harness can run it.

A future test in this file will use testcontainers-postgres to verify RLS.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from tests.conftest import make_invite_payload


@pytest.mark.integration
async def test_invite_user_happy_path(
    client: AsyncClient,
    tenant_headers: dict[str, str],
    mock_keycloak: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """POST /users with valid payload returns 201 + invokes KC + emits audit event.

    DB layer is patched to avoid requiring a real Postgres in this skeleton test.
    """
    payload = make_invite_payload()

    with patch("foundation_identity.api.dependencies.db_session") as db_dep:
        # Yield a stub session that captures `add` + supports `scalar`/`flush`.
        stub_session = AsyncMock()
        stub_session.scalar = AsyncMock(return_value=None)  # no existing user
        stub_session.flush = AsyncMock()
        stub_session.add = lambda obj: None

        async def _iter():  # noqa: ANN202
            yield stub_session

        db_dep.return_value = _iter()

        resp = await client.post(
            "/api/identity/v1/users",
            headers=tenant_headers,
            json=payload,
        )

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == payload["email"]
    assert body["status"] == "INVITED"
    assert body["tenant_id"] == tenant_headers["X-Tenant-Id"]
    assert body["id"].startswith("usr_")

    # Keycloak called
    mock_keycloak.create_user.assert_called_once()
    create_call = mock_keycloak.create_user.call_args
    assert create_call.kwargs["email"] == payload["email"]
    assert create_call.kwargs["attributes"]["tenant_id"] == [tenant_headers["X-Tenant-Id"]]

    # Audit emitted
    mock_audit.publish.assert_called_once()
    audit_call = mock_audit.publish.call_args
    assert audit_call.kwargs["event_type"] == "foundation.identity.user.invited"
    assert audit_call.kwargs["tenant_id"] == tenant_headers["X-Tenant-Id"]


@pytest.mark.integration
async def test_invite_user_invalid_email_returns_422(
    client: AsyncClient,
    tenant_headers: dict[str, str],
) -> None:
    resp = await client.post(
        "/api/identity/v1/users",
        headers=tenant_headers,
        json={"email": "not-an-email"},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["code"] == "FOUNDATION.IDENTITY.INPUT.VALIDATION_FAILED"
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert any("email" in err["field"] for err in body["errors"])
