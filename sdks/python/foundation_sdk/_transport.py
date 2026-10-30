"""HTTP transport layer — injects auth headers and context, parses errors."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar

import httpx

from foundation_sdk._context import current_context
from foundation_sdk._retry import DEFAULT_RETRY, RetryPolicy
from foundation_sdk._version import __version__
from foundation_sdk.errors import FoundationError, from_problem

logger = logging.getLogger(__name__)
_T = TypeVar("_T")


class Transport:
    """Thin httpx wrapper. One per Client. Sync + async."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = 30.0,
        retry: RetryPolicy = DEFAULT_RETRY,
        user_agent: str = f"foundation-sdk-python/{__version__}",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._retry = retry
        self._user_agent = user_agent
        self._sync = httpx.Client(base_url=self._base_url, timeout=timeout)
        self._async: httpx.AsyncClient | None = None
        self._timeout = timeout

    def request(
        self, method: str, path: str, *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._retrying(method, path, json=json, params=params,
                              parse=self._handle_response)

    def request_text(
        self, method: str, path: str, *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> str:
        """``request`` for routes that answer with a file (CSV, NDJSON) instead of JSON."""
        return self._retrying(method, path, json=json, params=params,
                              parse=self._handle_text)

    def _retrying(self, method: str, path: str, *, json: Any | None,
                  params: dict[str, Any] | None, parse: Callable[[httpx.Response], _T]) -> _T:
        attempt = 0
        while True:
            try:
                return parse(self._do_sync(method, path, json=json, params=params))
            except Exception as exc:
                if not self._retry.should_retry(exc, attempt):
                    raise
                delay = self._retry.delay_for(attempt, exc)
                logger.warning("Retrying", extra={"attempt": attempt + 1, "delay": delay})
                time.sleep(delay)
                attempt += 1

    async def request_async(
        self, method: str, path: str, *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self._retrying_async(method, path, json=json, params=params,
                                          parse=self._handle_response)

    async def request_text_async(
        self, method: str, path: str, *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> str:
        return await self._retrying_async(method, path, json=json, params=params,
                                          parse=self._handle_text)

    async def _retrying_async(self, method: str, path: str, *, json: Any | None,
                              params: dict[str, Any] | None,
                              parse: Callable[[httpx.Response], _T]) -> _T:
        if self._async is None:
            self._async = httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout)
        attempt = 0
        while True:
            try:
                return parse(await self._do_async(method, path, json=json, params=params))
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

    def _headers(self) -> dict[str, str]:
        ctx = current_context()
        headers = {
            "Authorization": f"Bearer {self._api_token}",
            "X-Tenant-Id": ctx.tenant_id,
            "X-Request-Id": ctx.request_id,
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        if ctx.user_id:
            headers["X-User-Id"] = ctx.user_id
        return headers

    def _do_sync(self, method: str, path: str, *,
                  json: Any | None, params: dict[str, Any] | None) -> httpx.Response:
        return self._sync.request(method=method, url=path, json=json,
                                  params=params, headers=self._headers())

    async def _do_async(self, method: str, path: str, *,
                         json: Any | None, params: dict[str, Any] | None) -> httpx.Response:
        assert self._async is not None
        return await self._async.request(method=method, url=path, json=json,
                                         params=params, headers=self._headers())

    @classmethod
    def _handle_response(cls, resp: httpx.Response) -> dict[str, Any]:
        cls._raise_for_problem(resp)
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    @classmethod
    def _handle_text(cls, resp: httpx.Response) -> str:
        cls._raise_for_problem(resp)
        return resp.text

    @staticmethod
    def _raise_for_problem(resp: httpx.Response) -> None:
        if 200 <= resp.status_code < 300:
            return
        try:
            body = resp.json()
        except ValueError:
            body = {"detail": resp.text[:500]}
        raise from_problem(resp.status_code, body)
