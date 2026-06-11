"""Redis cache adapter — short-lived keys for the identity service.

The ONLY place ``redis`` is imported (per the adapters package contract).
Used for state that is fast-changing, self-expiring, and does NOT belong in
Postgres:

* MFA challenges (``mfa:challenge:{id}``),
* rotated refresh-token blacklist for reuse detection
  (``refresh_token:used:{jti}``), and
* revoked access/refresh tokens (``token:revoked:{jti}``).

**Fail-secure**: every operation that cannot reach Redis raises
:class:`FoundationError(REDIS_UNAVAILABLE)` rather than returning a falsy
default.  Callers that gate a security decision on the cache (reuse detection,
blacklist checks) therefore *refuse* the operation when the cache is down
instead of silently letting a possibly-replayed token through.

Why a module-level connection pool (vs. fresh client per call like the
Keycloak adapters)?  ``redis.asyncio`` multiplexes over a pool that is
robust to the macOS/Docker keep-alive issue that bites httpx; reusing it is
both correct and the library's intended usage.
"""

from __future__ import annotations

import redis.asyncio as redis
from redis.exceptions import RedisError

from foundation_identity.config import get_settings
from foundation_identity.errors import REDIS_UNAVAILABLE, FoundationError
from foundation_identity.observability import get_logger

log = get_logger(__name__)


class RedisCacheAdapter:
    """Async Redis client for short-lived, self-expiring identity state."""

    def __init__(self) -> None:
        settings = get_settings()
        # decode_responses=True → str in/out, matching the adapter's contract.
        self._client: redis.Redis = redis.from_url(  # type: ignore[no-untyped-call]
            str(settings.redis_dsn),
            decode_responses=True,
        )

    async def set(
        self, key: str, value: str, ttl_seconds: int | None = None
    ) -> None:
        """Set ``key`` to ``value`` with an optional TTL (seconds)."""
        try:
            await self._client.set(key, value, ex=ttl_seconds)
        except RedisError as exc:
            raise self._unavailable("set", exc) from exc

    async def get(self, key: str) -> str | None:
        """Return the value at ``key``, or ``None`` if it does not exist."""
        try:
            value: str | None = await self._client.get(key)
            return value
        except RedisError as exc:
            raise self._unavailable("get", exc) from exc

    async def delete(self, key: str) -> None:
        """Delete ``key`` (no-op if absent)."""
        try:
            await self._client.delete(key)
        except RedisError as exc:
            raise self._unavailable("delete", exc) from exc

    async def exists(self, key: str) -> bool:
        """Return whether ``key`` currently exists."""
        try:
            return bool(await self._client.exists(key))
        except RedisError as exc:
            raise self._unavailable("exists", exc) from exc

    async def set_if_absent(
        self, key: str, value: str, ttl_seconds: int
    ) -> bool:
        """Atomically set ``key`` only if it does not exist (``SET NX EX``).

        Returns ``True`` if the key was set (it was absent), ``False`` if it
        already existed.  This is the core primitive for reuse detection and
        blacklist de-duplication: a ``False`` return means "we have seen this
        token/jti before".
        """
        try:
            # redis-py returns True on success, None when NX fails.
            result = await self._client.set(key, value, nx=True, ex=ttl_seconds)
            return result is True
        except RedisError as exc:
            raise self._unavailable("set_if_absent", exc) from exc

    @staticmethod
    def _unavailable(op: str, exc: RedisError) -> FoundationError:
        log.warning(f"redis.{op}.unavailable", error=str(exc))
        return FoundationError(REDIS_UNAVAILABLE, detail=f"{op}: {exc}")


_singleton: RedisCacheAdapter | None = None


def get_redis_cache() -> RedisCacheAdapter:
    """Module-level singleton; tests override via FastAPI dependency_overrides."""
    global _singleton
    if _singleton is None:
        _singleton = RedisCacheAdapter()
    return _singleton
