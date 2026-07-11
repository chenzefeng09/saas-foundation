"""Authoritative user-clearance and resource-sensitivity lookup.

Authorization callers are deliberately not allowed to submit either attribute:
clearance comes from Identity and sensitivity comes from DLP.  Any transport,
status, payload, or level-validation failure is surfaced to ``CheckService``,
which turns it into a fail-closed deny decision.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, Protocol, cast

import httpx

from foundation_authz.config import get_settings
from foundation_authz.observability import get_logger

log = get_logger(__name__)

SecurityLevel = Literal["L1", "L2", "L3", "L4", "L5"]
SECURITY_LEVEL_RANK: dict[SecurityLevel, int] = {
    "L1": 1,
    "L2": 2,
    "L3": 3,
    "L4": 4,
    "L5": 5,
}


@dataclass(frozen=True, slots=True)
class SecurityAttributes:
    user_clearance: SecurityLevel
    resource_sensitivity: SecurityLevel


class SecurityAttributesUnavailable(RuntimeError):
    """An authoritative attribute could not be obtained or validated."""


class SecurityAttributeProvider(Protocol):
    async def resolve(
        self,
        *,
        tenant_id: str,
        user_id: str,
        resource_type: str,
        resource_id: str | None,
    ) -> SecurityAttributes: ...


class HttpSecurityAttributeProvider:
    """Resolve security attributes from the Identity and DLP HTTP APIs."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self._identity_base = str(settings.identity_url).rstrip("/")
        self._dlp_base = str(settings.dlp_url).rstrip("/")
        self._timeout = settings.security_attribute_timeout_seconds
        self._injected_client = client

    def _new_client(self) -> httpx.AsyncClient:
        if self._injected_client is not None:
            return self._injected_client
        return httpx.AsyncClient(
            timeout=self._timeout,
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    async def resolve(
        self,
        *,
        tenant_id: str,
        user_id: str,
        resource_type: str,
        resource_id: str | None,
    ) -> SecurityAttributes:
        """Fetch both attributes concurrently; never derive them from request context.

        Collection-level checks have no concrete resource ID.  They are looked up
        under the tenant ID, allowing DLP to classify that collection explicitly
        while retaining DLP's centrally configured default when no classification
        exists.
        """
        headers = {
            "X-Tenant-Id": tenant_id,
            "X-Actor": "SERVICE",
        }
        client = self._new_client()
        try:
            results = await asyncio.gather(
                self._fetch_level(
                    client,
                    url=f"{self._identity_base}/users/{user_id}",
                    field="clearance",
                    source="identity",
                    headers=headers,
                ),
                self._fetch_level(
                    client,
                    url=f"{self._dlp_base}/core/classification:get",
                    field="sensitivity",
                    source="dlp",
                    headers=headers,
                    params={
                        "resource_type": resource_type,
                        "resource_id": resource_id or tenant_id,
                    },
                ),
                return_exceptions=True,
            )
        finally:
            if self._injected_client is None:
                await client.aclose()

        for result in results:
            if isinstance(result, BaseException):
                if isinstance(result, SecurityAttributesUnavailable):
                    raise result
                raise SecurityAttributesUnavailable(
                    "Unexpected security attribute provider failure"
                ) from result

        return SecurityAttributes(
            user_clearance=cast(SecurityLevel, results[0]),
            resource_sensitivity=cast(SecurityLevel, results[1]),
        )

    @staticmethod
    async def _fetch_level(
        client: httpx.AsyncClient,
        *,
        url: str,
        field: str,
        source: str,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
    ) -> SecurityLevel:
        try:
            response = await client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            log.warning("security_attributes.unreachable", source=source, error=str(exc))
            raise SecurityAttributesUnavailable(f"{source} is unreachable") from exc

        if response.status_code != 200:
            log.warning(
                "security_attributes.bad_status",
                source=source,
                status=response.status_code,
            )
            raise SecurityAttributesUnavailable(
                f"{source} returned HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise SecurityAttributesUnavailable(f"{source} returned non-JSON data") from exc

        value = payload.get(field) if isinstance(payload, dict) else None
        if value not in SECURITY_LEVEL_RANK:
            log.warning(
                "security_attributes.invalid_level",
                source=source,
                field=field,
            )
            raise SecurityAttributesUnavailable(
                f"{source} returned an invalid {field}"
            )
        return cast(SecurityLevel, value)


_singleton: HttpSecurityAttributeProvider | None = None


def get_security_attribute_provider() -> HttpSecurityAttributeProvider:
    global _singleton
    if _singleton is None:
        _singleton = HttpSecurityAttributeProvider()
    return _singleton
