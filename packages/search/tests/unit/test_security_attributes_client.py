from __future__ import annotations

import httpx
import pytest

from foundation_search.adapters.security_attributes_client import SecurityAttributesClient
from foundation_search.errors import SECURITY_ATTRIBUTES_UNAVAILABLE, FoundationError

TENANT = "tnt_AAAAAAAAAAAAAAAAAAAAAAAAA1"
USER = "usr_AAAAAAAAAAAAAAAAAAAAAAAAA1"


@pytest.mark.asyncio
async def test_reads_authoritative_clearance_and_forwards_tenant() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith(f"/users/{USER}")
        assert request.headers["X-Tenant-Id"] == TENANT
        assert request.headers["X-Actor"] == "SERVICE"
        return httpx.Response(200, json={"clearance": "L4"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = SecurityAttributesClient(client=http)
        assert await client.get_user_clearance(tenant_id=TENANT, user_id=USER) == "L4"


@pytest.mark.asyncio
async def test_reads_authoritative_resource_sensitivity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["resource_type"] == "document"
        assert request.url.params["resource_id"] == "doc_1"
        return httpx.Response(200, json={"sensitivity": "L5"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = SecurityAttributesClient(client=http)
        level = await client.get_resource_sensitivity(
            tenant_id=TENANT,
            resource_type="document",
            resource_id="doc_1",
        )
        assert level == "L5"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "payload"),
    [(503, {"detail": "down"}), (200, {"clearance": "L9"}), (200, {})],
)
async def test_invalid_or_unavailable_attributes_fail_closed(
    status: int,
    payload: dict[str, str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = SecurityAttributesClient(client=http)
        with pytest.raises(FoundationError) as exc_info:
            await client.get_user_clearance(tenant_id=TENANT, user_id=USER)
        assert exc_info.value.error_code == SECURITY_ATTRIBUTES_UNAVAILABLE
