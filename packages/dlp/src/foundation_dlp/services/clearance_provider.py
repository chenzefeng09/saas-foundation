"""Authoritative user-clearance resolution.

DLP must never accept a caller-supplied clearance.  The identity service owns
that attribute, and any lookup or payload-integrity failure is represented as a
provider error so the API layer can fail closed.
"""

from __future__ import annotations

from typing import Protocol, cast

import httpx

from foundation_dlp.config import get_settings
from foundation_dlp.domain.models import SensitivityLevel
from foundation_dlp.observability import get_logger

log = get_logger(__name__)

_LEVELS = frozenset({"L1", "L2", "L3", "L4", "L5"})


class ClearanceProviderError(RuntimeError):
    """Identity clearance could not be resolved authoritatively."""


class ClearanceProvider(Protocol):
    """Boundary implemented by the authority used to resolve user clearance."""

    async def get_clearance(
        self, *, tenant_id: str, user_id: str, request_id: str
    ) -> SensitivityLevel: ...


class IdentityClearanceProvider:
    """Resolve clearance from identity ``GET /users/{user_id}``.

    A client may be injected for deterministic tests.  Production calls use a
    no-retry, short-timeout client because policy checks must fail closed rather
    than hide identity outages behind a long request.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        settings = get_settings()
        self._base_url = (base_url or str(settings.identity_url)).rstrip("/")
        self._timeout_seconds = timeout_seconds or settings.identity_timeout_seconds
        self._injected_client = client

    def _client(self) -> httpx.AsyncClient:
        if self._injected_client is not None:
            return self._injected_client
        return httpx.AsyncClient(
            timeout=self._timeout_seconds,
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    async def get_clearance(
        self, *, tenant_id: str, user_id: str, request_id: str
    ) -> SensitivityLevel:
        client = self._client()
        url = f"{self._base_url}/users/{user_id}"
        try:
            try:
                response = await client.get(
                    url,
                    headers={
                        "Accept": "application/json",
                        "X-Tenant-Id": tenant_id,
                        "X-Actor": "SERVICE",
                        "X-Request-Id": request_id,
                    },
                )
            except httpx.HTTPError as exc:
                log.warning(
                    "clearance.identity_unreachable",
                    tenant_id=tenant_id,
                    user_id=user_id,
                    error=str(exc),
                )
                raise ClearanceProviderError("identity service is unavailable") from exc
        finally:
            if self._injected_client is None:
                await client.aclose()

        if response.status_code != 200:
            log.warning(
                "clearance.identity_bad_status",
                tenant_id=tenant_id,
                user_id=user_id,
                status=response.status_code,
            )
            raise ClearanceProviderError(
                f"identity returned unexpected status {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise ClearanceProviderError("identity returned a non-JSON response") from exc
        if not isinstance(payload, dict):
            raise ClearanceProviderError("identity returned an invalid user payload")

        clearance = payload.get("clearance")
        if not isinstance(clearance, str) or clearance not in _LEVELS:
            raise ClearanceProviderError("identity returned an invalid clearance")
        return cast(SensitivityLevel, clearance)
