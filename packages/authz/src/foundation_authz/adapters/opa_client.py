"""OPA HTTP client.

Calls OPA's data API: POST {opa_url}{decision_path}
Body: { "input": { ... policy input contract ... } }
OPA returns: { "result": { "allow": bool, "deny_reason": "...", ... } }

Sidecar deploy: 127.0.0.1:8181 per-pod. The `localhost vs 127.0.0.1`
trap learned from the identity ↔ KC fight applies here too — always
use 127.0.0.1 for loopback in dev.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from foundation_authz.config import get_settings
from foundation_authz.errors import (
    OPA_DECISION_ERROR,
    OPA_TIMEOUT,
    OPA_UNAVAILABLE,
    FoundationError,
)
from foundation_authz.observability import get_logger

log = get_logger(__name__)


def _decision_url(base: str, path: str) -> str:
    """Join OPA base/path while tolerating a base already ending in ``/v1``."""
    normalized_base = base.rstrip("/")
    normalized_path = "/" + path.lstrip("/")
    if normalized_base.endswith("/v1") and normalized_path.startswith("/v1/"):
        normalized_path = normalized_path[3:]
    return f"{normalized_base}{normalized_path}"


@dataclass(frozen=True, slots=True)
class OpaDecision:
    allow: bool
    deny_reason: str | None = None
    matched_policy: str | None = None
    raw: dict[str, Any] | None = None


class OpaClient:
    """Single-call OPA query client. Same per-call fresh-client pattern as KC adapter."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self._base = str(settings.opa_url).rstrip("/")
        self._path = settings.opa_decision_path
        self._url = _decision_url(self._base, self._path)
        self._timeout = settings.opa_timeout_seconds
        self._injected_client = client
        self._fail_open = settings.opa_unavailable_behaviour == "FAIL_OPEN"

    def _new_client(self) -> httpx.AsyncClient:
        if self._injected_client is not None:
            return self._injected_client
        return httpx.AsyncClient(
            timeout=self._timeout,
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    async def evaluate(self, opa_input: dict[str, Any]) -> OpaDecision:
        """Run policy against OPA. On unavailability honour the configured behaviour."""
        url = self._url
        client = self._new_client()
        try:
            try:
                resp = await client.post(url, json={"input": opa_input})
            except httpx.TimeoutException as e:
                if self._fail_open:
                    log.warning("opa.timeout.fail_open", error=str(e))
                    return OpaDecision(allow=True, deny_reason="opa_timeout_fail_open")
                raise FoundationError(OPA_TIMEOUT, detail=str(e)) from e
            except httpx.HTTPError as e:
                if self._fail_open:
                    log.warning("opa.unreachable.fail_open", error=str(e))
                    return OpaDecision(allow=True, deny_reason="opa_unavailable_fail_open")
                raise FoundationError(OPA_UNAVAILABLE, detail=str(e)) from e
        finally:
            if self._injected_client is None:
                await client.aclose()

        if resp.status_code != 200:
            log.warning("opa.bad_status", status=resp.status_code, body=resp.text[:300])
            raise FoundationError(
                OPA_DECISION_ERROR,
                detail=f"OPA returned {resp.status_code}: {resp.text[:200]}",
            )

        try:
            body = resp.json()
        except ValueError as e:
            raise FoundationError(OPA_DECISION_ERROR, detail=f"OPA non-JSON: {e}") from e

        # OPA returns { "result": <value> } when the rule produces a value;
        # if undefined it omits "result". Our policy returns a bool or an object.
        result = body.get("result")
        if isinstance(result, bool):
            return OpaDecision(allow=result, raw=body)
        if isinstance(result, dict):
            return OpaDecision(
                allow=bool(result.get("allow", False)),
                deny_reason=result.get("deny_reason"),
                matched_policy=result.get("matched_policy"),
                raw=body,
            )
        # Undefined → default deny per OPA convention
        return OpaDecision(allow=False, deny_reason="opa_undefined", raw=body)


_singleton: OpaClient | None = None


def get_opa_client() -> OpaClient:
    global _singleton
    if _singleton is None:
        _singleton = OpaClient()
    return _singleton
