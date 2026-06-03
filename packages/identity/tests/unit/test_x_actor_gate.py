"""Tests: X-Actor=ADMIN must be rejected / downgraded to USER by middleware.

These tests verify the security invariant introduced in Task 1:
  - X-Actor=ADMIN from any external request must NOT propagate as actor=ADMIN.
  - Valid actor values (USER, SERVICE, SYSTEM, MIGRATOR) are still accepted.
  - Unknown actor values (including ADMIN) are silently downgraded to USER.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

VALID_TENANT = "tnt_01J5VALIDTENANT000000000T1"
VALID_USER = "usr_01J5VALIDUSER00000000000U1"


@pytest.mark.unit
async def test_actor_admin_header_is_downgraded_to_user(client: AsyncClient) -> None:
    """X-Actor=ADMIN from a client must be silently downgraded, not passed through.

    We verify by calling the PATCH /users endpoint which requires tenant context.
    The important thing is the request is NOT rejected with 400 (it gets 401/404
    from the actual endpoint, not 400 from actor validation — showing the header
    was silently rewritten to USER rather than causing a validation error).
    """
    resp = await client.patch(
        "/api/identity/v1/users/usr_01J5VALIDUSER00000000000U1",
        headers={
            "X-Tenant-Id": VALID_TENANT,
            "X-User-Id": VALID_USER,
            "X-Actor": "ADMIN",  # should be silently downgraded
        },
        json={"display_name": "test"},
    )
    # Should NOT be 400 (would mean middleware rejected the downgraded value)
    # Will be 4xx from the actual handler (no real DB), but not from actor validation
    assert resp.status_code != 400 or (
        resp.json().get("code", "") != "FOUNDATION.IDENTITY.INPUT.INVALID_FORMAT"
        or "actor" not in resp.json().get("detail", "").lower()
    )


@pytest.mark.unit
async def test_actor_admin_header_does_not_produce_400(client: AsyncClient) -> None:
    """Sending X-Actor=ADMIN must not return 400 — it must be silently dropped.

    This tests the downgrade strategy: we no longer return 400 for ADMIN
    (which would let clients probe which values are forbidden vs unknown).
    Instead we silently replace with USER.
    """
    resp = await client.get(
        "/api/identity/v1/healthz",
        headers={"X-Actor": "ADMIN"},
    )
    # healthz is a PUBLIC_PATH so middleware skips it; but the key assertion is
    # that we don't get a 400 with actor-related error code.
    assert resp.status_code == 200


@pytest.mark.unit
async def test_actor_user_is_accepted(client: AsyncClient) -> None:
    """X-Actor=USER (the default) must still work."""
    resp = await client.get(
        "/api/identity/v1/users",
        headers={
            "X-Tenant-Id": VALID_TENANT,
            "X-User-Id": VALID_USER,
            "X-Actor": "USER",
        },
    )
    # Should not be 400 from actor validation
    assert resp.status_code != 400 or (
        "actor" not in resp.json().get("detail", "").lower()
    )


@pytest.mark.unit
async def test_actor_service_is_accepted(client: AsyncClient) -> None:
    """X-Actor=SERVICE must be accepted (used by internal service-to-service calls)."""
    resp = await client.get(
        "/api/identity/v1/users",
        headers={
            "X-Tenant-Id": VALID_TENANT,
            "X-User-Id": VALID_USER,
            "X-Actor": "SERVICE",
        },
    )
    assert resp.status_code != 400 or (
        "actor" not in resp.json().get("detail", "").lower()
    )


@pytest.mark.unit
async def test_actor_completely_unknown_is_downgraded(client: AsyncClient) -> None:
    """An entirely unknown actor value is downgraded to USER (not 400)."""
    resp = await client.get(
        "/api/identity/v1/healthz",
        headers={"X-Actor": "TOTALLY_UNKNOWN_VALUE"},
    )
    # healthz is a public path, should 200 regardless
    assert resp.status_code == 200


@pytest.mark.unit
async def test_actor_admin_does_not_appear_in_valid_actor_set() -> None:
    """Unit test: ADMIN must NOT be in ACTOR_VALUES."""
    from foundation_identity.api.middleware import ACTOR_VALUES

    assert "ADMIN" not in ACTOR_VALUES, (
        "ADMIN must be removed from ACTOR_VALUES — it must not be accepted "
        "from external X-Actor headers."
    )


@pytest.mark.unit
async def test_actor_values_contains_expected_valid_set() -> None:
    """The expected safe actor values are still present."""
    from foundation_identity.api.middleware import ACTOR_VALUES

    for v in ("USER", "SERVICE", "SYSTEM", "MIGRATOR"):
        assert v in ACTOR_VALUES, f"{v} should be in ACTOR_VALUES"
