"""Authoritative identity and DLP attributes used by search filtering.

Search must never accept a caller-supplied clearance or resource sensitivity.
Both values are resolved server-side and any lookup/shape failure is fail-closed.
"""

from __future__ import annotations

from typing import Any

import httpx

from foundation_search.config import get_settings
from foundation_search.errors import (
    SECURITY_ATTRIBUTES_UNAVAILABLE,
    FoundationError,
)
from foundation_search.observability import get_logger

log = get_logger(__name__)

LEVEL_RANK: dict[str, int] = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
_TIMEOUT = httpx.Timeout(connect=1.0, read=2.0, write=2.0, pool=1.0)


class SecurityAttributesClient:
    """Resolve security labels from their systems of record."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self._identity_base = settings.identity_url.rstrip("/")
        self._dlp_base = settings.dlp_url.rstrip("/")
        self._injected = client

    def _client(self) -> httpx.AsyncClient:
        if self._injected is not None:
            return self._injected
        return httpx.AsyncClient(
            timeout=_TIMEOUT,
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    @staticmethod
    def _headers(tenant_id: str) -> dict[str, str]:
        return {
            "X-Tenant-Id": tenant_id,
            "X-Actor": "SERVICE",
        }

    async def get_user_clearance(self, *, tenant_id: str, user_id: str) -> str:
        body = await self._get_json(
            f"{self._identity_base}/users/{user_id}",
            tenant_id=tenant_id,
            attribute="clearance",
        )
        return self._parse_level(body.get("clearance"), source="identity.clearance")

    async def get_resource_sensitivity(
        self,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
    ) -> str:
        body = await self._get_json(
            f"{self._dlp_base}/core/classification:get",
            tenant_id=tenant_id,
            attribute="sensitivity",
            params={"resource_type": resource_type, "resource_id": resource_id},
        )
        return self._parse_level(body.get("sensitivity"), source="dlp.sensitivity")

    async def _get_json(
        self,
        url: str,
        *,
        tenant_id: str,
        attribute: str,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        client = self._client()
        try:
            try:
                response = await client.get(
                    url,
                    params=params,
                    headers=self._headers(tenant_id),
                )
            except (httpx.TimeoutException, httpx.HTTPError) as exc:
                raise FoundationError(
                    SECURITY_ATTRIBUTES_UNAVAILABLE,
                    detail=f"Authoritative {attribute} lookup failed",
                ) from exc
        finally:
            if self._injected is None:
                await client.aclose()

        if response.status_code != 200:
            log.warning(
                "security_attributes.bad_status",
                attribute=attribute,
                status=response.status_code,
            )
            raise FoundationError(
                SECURITY_ATTRIBUTES_UNAVAILABLE,
                detail=f"Authoritative {attribute} lookup returned {response.status_code}",
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise FoundationError(
                SECURITY_ATTRIBUTES_UNAVAILABLE,
                detail=f"Authoritative {attribute} lookup returned invalid JSON",
            ) from exc
        if not isinstance(body, dict):
            raise FoundationError(
                SECURITY_ATTRIBUTES_UNAVAILABLE,
                detail=f"Authoritative {attribute} lookup returned an invalid payload",
            )
        return body

    @staticmethod
    def _parse_level(value: Any, *, source: str) -> str:
        if isinstance(value, str) and value in LEVEL_RANK:
            return value
        raise FoundationError(
            SECURITY_ATTRIBUTES_UNAVAILABLE,
            detail=f"{source} is missing or outside L1-L5",
        )


_singleton: SecurityAttributesClient | None = None


def get_security_attributes_client() -> SecurityAttributesClient:
    global _singleton
    if _singleton is None:
        _singleton = SecurityAttributesClient()
    return _singleton


def _reset_singleton_for_tests(client: SecurityAttributesClient | None = None) -> None:
    global _singleton
    _singleton = client
