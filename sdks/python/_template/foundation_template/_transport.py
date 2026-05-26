"""HTTP transport layer.

Responsibilities (do not push into Resource classes):
  - Inject Authorization, X-Tenant-Id, X-User-Id, X-Request-Id headers from context
  - Parse application/problem+json error responses into FoundationError subclasses
  - Apply retry policy
  - Emit OTel spans (one per request)
  - Honor Idempotency-Key on POST/PUT/PATCH
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from foundation_template._context import current_context
from foundation_template._retry import DEFAULT_RETRY, RetryPolicy
from foundation_template.errors import FoundationError, from_problem

logger = logging.getLogger(__name__)


class Transport:
    """Thin httpx wrapper. One per Client. Sync + async."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = 30.0,
        retry: RetryPolicy = DEFAULT_RETRY,
        user_agent: str = "foundation-sdk-python",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._retry = retry
        self._user_agent = user_agent
        self._sync = httpx.Client(base_url=self._base_url, timeout=timeout)
        self._async: httpx.AsyncClient | None = None  # lazy
        self._timeout = timeout

    # ------- public API -------

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        attempt = 0
        while True:
            try:
                return self._do_sync(method, path, json=json, params=params,
                                     idempotency_key=idempotency_key)
            except Exception as exc:
                if not self._retry.should_retry(exc, attempt):
                    raise
                delay = self._retry.delay_for(attempt, exc)
                logger.warning("Retrying", extra={"attempt": attempt + 1, "delay": delay})
                time.sleep(delay)
                attempt += 1

    async def request_async(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if self._async is None:
            self._async = httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout)
        attempt = 0
        while True:
            try:
                return await self._do_async(method, path, json=json, params=params,
                                            idempotency_key=idempotency_key)
            except Exception as exc:
                if not self._retry.should_retry(exc, attempt):
                    raise
                delay = self._retry.delay_for(attempt, exc)
                logger.warning("Retrying", extra={"attempt": attempt + 1, "delay": delay})
                await asyncio.sleep(delay)
                attempt += 1

    def close(self) -> None:
        self._sync.close()

    async def aclose(self) -> None:
        if self._async is not None:
            await self._async.aclose()

    # ------- internals -------

    def _headers(self, idempotency_key: str | None) -> dict[str, str]:
        ctx = current_context()
        headers = {
            "Authorization": f"Bearer {self._api_token}",
            "X-Tenant-Id": ctx.tenant_id,
            "X-Request-Id": ctx.request_id,
            "User-Agent": self._user_agent,
            "Accept": "application/json, application/problem+json",
            "Accept-Language": ctx.locale,
        }
        if ctx.user_id:
            headers["X-User-Id"] = ctx.user_id
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        # TODO: inject OTel traceparent header here
        return headers

    def _do_sync(
        self,
        method: str,
        path: str,
        *,
        json: Any | None,
        params: dict[str, Any] | None,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        resp = self._sync.request(
            method=method,
            url=path,
            json=json,
            params=params,
            headers=self._headers(idempotency_key),
        )
        return self._handle_response(resp)

    async def _do_async(
        self,
        method: str,
        path: str,
        *,
        json: Any | None,
        params: dict[str, Any] | None,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        assert self._async is not None
        resp = await self._async.request(
            method=method,
            url=path,
            json=json,
            params=params,
            headers=self._headers(idempotency_key),
        )
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(resp: httpx.Response) -> dict[str, Any]:
        if 200 <= resp.status_code < 300:
            if resp.status_code == 204 or not resp.content:
                return {}
            return resp.json()
        # Error path
        ctype = resp.headers.get("content-type", "")
        if "problem+json" in ctype or "application/json" in ctype:
            try:
                body = resp.json()
            except ValueError:
                body = {}
        else:
            body = {"detail": resp.text[:500]}
        raise from_problem(resp.status_code, body)
