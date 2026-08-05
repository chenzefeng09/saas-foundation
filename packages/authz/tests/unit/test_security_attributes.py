"""Authoritative Identity/DLP security-attribute provider tests."""

from __future__ import annotations

import httpx
import pytest

from foundation_authz.adapters.security_attributes import (
    HttpSecurityAttributeProvider,
    SecurityAttributesUnavailable,
)

pytestmark = pytest.mark.unit

TENANT = "tnt_01J0000000000000000000TNT1"
USER = "usr_01J0000000000000000000USR1"


async def test_resolve_fetches_identity_and_dlp_with_service_context() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith(f"/users/{USER}"):
            return httpx.Response(200, json={"clearance": "L4"})
        assert request.url.path.endswith("/core/classification:get")
        assert request.url.params["resource_type"] == "document"
        assert request.url.params["resource_id"] == "doc_1"
        return httpx.Response(200, json={"sensitivity": "L3"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = HttpSecurityAttributeProvider(client=client)
        result = await provider.resolve(
            tenant_id=TENANT,
            user_id=USER,
            resource_type="document",
            resource_id="doc_1",
        )

    assert result.user_clearance == "L4"
    assert result.resource_sensitivity == "L3"
    assert len(requests) == 2
    for request in requests:
        assert request.headers["X-Tenant-Id"] == TENANT
        assert request.headers["X-Actor"] == "SERVICE"


async def test_collection_level_lookup_uses_tenant_as_dlp_resource_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(f"/users/{USER}"):
            return httpx.Response(200, json={"clearance": "L3"})
        assert request.url.params["resource_id"] == TENANT
        return httpx.Response(200, json={"sensitivity": "L3"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await HttpSecurityAttributeProvider(client=client).resolve(
            tenant_id=TENANT,
            user_id=USER,
            resource_type="tenant_settings",
            resource_id=None,
        )

    assert result.resource_sensitivity == "L3"


@pytest.mark.parametrize(
    ("identity_payload", "dlp_payload"),
    [
        ({}, {"sensitivity": "L2"}),
        ({"clearance": "L6"}, {"sensitivity": "L2"}),
        ({"clearance": "L3"}, {"sensitivity": 4}),
    ],
)
async def test_missing_or_invalid_level_fails_closed(
    identity_payload: dict[str, object],
    dlp_payload: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = (
            identity_payload
            if request.url.path.endswith(f"/users/{USER}")
            else dlp_payload
        )
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = HttpSecurityAttributeProvider(client=client)
        with pytest.raises(SecurityAttributesUnavailable):
            await provider.resolve(
                tenant_id=TENANT,
                user_id=USER,
                resource_type="document",
                resource_id="doc_1",
            )


async def test_dependency_non_200_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(f"/users/{USER}"):
            return httpx.Response(503, text="unavailable")
        return httpx.Response(200, json={"sensitivity": "L2"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = HttpSecurityAttributeProvider(client=client)
        with pytest.raises(SecurityAttributesUnavailable, match="identity returned HTTP 503"):
            await provider.resolve(
                tenant_id=TENANT,
                user_id=USER,
                resource_type="document",
                resource_id="doc_1",
            )


async def test_dependency_transport_error_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(f"/users/{USER}"):
            raise httpx.ConnectError("identity offline", request=request)
        return httpx.Response(200, json={"sensitivity": "L2"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = HttpSecurityAttributeProvider(client=client)
        with pytest.raises(SecurityAttributesUnavailable, match="identity is unreachable"):
            await provider.resolve(
                tenant_id=TENANT,
                user_id=USER,
                resource_type="document",
                resource_id="doc_1",
            )
