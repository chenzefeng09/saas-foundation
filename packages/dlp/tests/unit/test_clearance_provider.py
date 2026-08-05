"""Tests for the identity-backed, fail-closed clearance provider."""

from __future__ import annotations

import httpx
import pytest

from foundation_dlp.services.clearance_provider import (
    ClearanceProviderError,
    IdentityClearanceProvider,
)

TENANT_ID = "tnt_01J0000000000000000000TNT1"
USER_ID = "usr_01J0000000000000000000USR1"
REQUEST_ID = "req_01J0000000000000000000REQ1"


async def test_identity_provider_forwards_trusted_context() -> None:
    captured: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured
        captured = request
        return httpx.Response(200, json={"id": USER_ID, "clearance": "L4"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = IdentityClearanceProvider(
            base_url="http://identity.test/api/identity/v1",
            client=client,
        )
        clearance = await provider.get_clearance(
            tenant_id=TENANT_ID,
            user_id=USER_ID,
            request_id=REQUEST_ID,
        )

    assert clearance == "L4"
    assert captured is not None
    assert str(captured.url) == f"http://identity.test/api/identity/v1/users/{USER_ID}"
    assert captured.headers["X-Tenant-Id"] == TENANT_ID
    assert captured.headers["X-Actor"] == "SERVICE"
    assert captured.headers["X-Request-Id"] == REQUEST_ID


@pytest.mark.parametrize(
    ("status", "payload"),
    [
        (503, {"detail": "down"}),
        (200, {"id": USER_ID}),
        (200, {"id": USER_ID, "clearance": "L6"}),
        (200, {"id": USER_ID, "clearance": 5}),
    ],
)
async def test_identity_provider_fails_closed_on_untrusted_response(
    status: int, payload: dict[str, object]
) -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(status, json=payload))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = IdentityClearanceProvider(base_url="http://identity.test", client=client)
        with pytest.raises(ClearanceProviderError):
            await provider.get_clearance(
                tenant_id=TENANT_ID,
                user_id=USER_ID,
                request_id=REQUEST_ID,
            )


async def test_identity_provider_fails_closed_on_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = IdentityClearanceProvider(base_url="http://identity.test", client=client)
        with pytest.raises(ClearanceProviderError):
            await provider.get_clearance(
                tenant_id=TENANT_ID,
                user_id=USER_ID,
                request_id=REQUEST_ID,
            )
