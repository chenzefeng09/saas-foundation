"""Have-I-Been-Pwned gateway — k-anonymity breach lookup.

Queries ``https://api.pwnedpasswords.com/range/{prefix}`` with the first 5
hex chars of the password's SHA-1.  The endpoint returns ``SUFFIX:COUNT``
lines covering every full hash that shares the prefix; we look up our own
suffix locally.  The full password never leaves the service.

Dev / unit tests use the offline implementation, which always reports "not
breached" so test passwords like ``correct horse battery staple`` don't fail
suddenly because HIBP got an update.  Production deployments override the
FastAPI dependency to enable real lookups.
"""

from __future__ import annotations

import hashlib

import httpx

from foundation_identity.errors import KEYCLOAK_UNAVAILABLE, FoundationError
from foundation_identity.observability import get_logger

log = get_logger(__name__)

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_DEFAULT_TIMEOUT_SECONDS = 3.0


class HibpGateway:
    """Default offline implementation: always reports zero breaches."""

    async def breach_count(self, password: str) -> int:
        """Return the number of times ``password`` appears in known breaches.

        The offline default returns 0 so dev / CI test runs don't depend on a
        live HIBP service.  Production overrides this with :class:`OnlineHibpGateway`.
        """
        return 0


class OnlineHibpGateway(HibpGateway):
    """Real HIBP lookups via the k-anonymity range API."""

    def __init__(self, timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout_seconds

    async def breach_count(self, password: str) -> int:
        # HIBP's range API mandates SHA-1 with a 5-char prefix (k-anonymity);
        # not used for confidentiality, so weak-hash warnings don't apply.
        sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(_HIBP_RANGE_URL.format(prefix=prefix))
        except httpx.HTTPError as exc:
            # Fail-open: HIBP outage must not block password changes.  Log a
            # warning so operators notice if it's persistent.
            log.warning("hibp.unavailable", error=str(exc))
            raise FoundationError(KEYCLOAK_UNAVAILABLE, detail="HIBP unavailable") from exc
        if resp.status_code != 200:
            log.warning("hibp.unexpected_status", status=resp.status_code)
            return 0
        for line in resp.text.splitlines():
            if ":" not in line:
                continue
            line_suffix, _, count_str = line.partition(":")
            if line_suffix.strip() == suffix:
                try:
                    return int(count_str.strip())
                except ValueError:
                    return 1
        return 0


_singleton: HibpGateway | None = None


def get_hibp_gateway() -> HibpGateway:
    """Module-level singleton; tests override via FastAPI dependency_overrides."""
    global _singleton
    if _singleton is None:
        _singleton = HibpGateway()
    return _singleton
