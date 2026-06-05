"""Authz service client — calls /list-accessible-ids.

Follows the same per-call httpx pattern as opa_client.py in authz package.
fail-close: any error → (ids=[], complete=False, all_in_tenant=False)
so callers apply the narrowest possible ACL filter.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from foundation_search.config import get_settings
from foundation_search.observability import get_logger

log = get_logger(__name__)

_TIMEOUT = httpx.Timeout(connect=1.0, read=5.0, write=2.0, pool=1.0)


@dataclass(frozen=True, slots=True)
class AccessibleIds:
    ids: list[str]
    complete: bool
    all_in_tenant: bool


# Sentinel: fail-close result — narrowest possible, forces per-user ACL only
_FAIL_CLOSE = AccessibleIds(ids=[], complete=False, all_in_tenant=False)


class AuthzClient:
    """Minimal HTTP client for foundation-authz /list-accessible-ids.

    Always fail-close: any connectivity or non-200 response returns _FAIL_CLOSE
    (empty team ids, complete=False) so the query layer applies the most
    restrictive ACL filter rather than widening access.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self._base = settings.authz_url.rstrip("/")
        self._injected = client

    def _client(self) -> httpx.AsyncClient:
        if self._injected is not None:
            return self._injected
        return httpx.AsyncClient(timeout=_TIMEOUT, transport=httpx.AsyncHTTPTransport(retries=0))

    async def list_accessible_ids(
        self,
        *,
        tenant_id: str,
        user_id: str,
        resource_type: str,
        action: str = "search.read",
        max: int = 10000,
    ) -> AccessibleIds:
        """Call authz /list-accessible-ids.

        Returns AccessibleIds on success.
        Returns _FAIL_CLOSE (complete=False, all_in_tenant=False, ids=[]) on
        any failure — caller must apply the most restrictive ACL filter.
        """
        url = f"{self._base}/list-accessible-ids"
        payload = {
            "user_id": user_id,
            "resource_type": resource_type,
            "action": action,
            "max": max,
        }
        client = self._client()
        try:
            try:
                resp = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-Tenant-Id": tenant_id,
                    },
                )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as e:
                log.warning("authz_client.unreachable", error=str(e), url=url, user_id=user_id)
                return _FAIL_CLOSE
        finally:
            if self._injected is None:
                await client.aclose()

        if resp.status_code != 200:
            log.warning(
                "authz_client.bad_status",
                status=resp.status_code,
                body=resp.text[:200],
                user_id=user_id,
            )
            return _FAIL_CLOSE

        try:
            body = resp.json()
        except ValueError as e:
            log.warning("authz_client.non_json", error=str(e))
            return _FAIL_CLOSE

        return AccessibleIds(
            ids=body.get("ids", []),
            complete=bool(body.get("complete", False)),
            all_in_tenant=bool(body.get("all_in_tenant", False)),
        )


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_singleton: AuthzClient | None = None


def get_authz_client() -> AuthzClient:
    global _singleton
    if _singleton is None:
        _singleton = AuthzClient()
    return _singleton


def _reset_singleton_for_tests(client: AuthzClient | None = None) -> None:
    """Test helper — inject a mock client or reset to None."""
    global _singleton
    _singleton = client
