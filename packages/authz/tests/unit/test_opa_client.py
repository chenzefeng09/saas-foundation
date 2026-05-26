"""OPA HTTP client tests — respx-mocked transport.

Covers:
  - bool result
  - dict result with deny_reason / matched_policy
  - undefined result (no `result` key)
  - non-200 status → OPA_DECISION_ERROR
  - non-JSON body → OPA_DECISION_ERROR
  - timeout — fail_close raises OPA_TIMEOUT, fail_open returns allow
  - connect error — fail_close raises OPA_UNAVAILABLE, fail_open returns allow
"""

from __future__ import annotations

import httpx
import pytest
import respx

from foundation_authz.adapters.opa_client import OpaClient, OpaDecision
from foundation_authz.config import get_settings
from foundation_authz.errors import (
    OPA_DECISION_ERROR,
    OPA_TIMEOUT,
    OPA_UNAVAILABLE,
    FoundationError,
)


pytestmark = pytest.mark.unit


def _opa_url() -> str:
    settings = get_settings()
    return f"{str(settings.opa_url).rstrip('/')}{settings.opa_decision_path}"


def _build_client(*, transport: httpx.AsyncBaseTransport, fail_open: bool = False) -> OpaClient:
    client = httpx.AsyncClient(transport=transport, timeout=1.0)
    opa = OpaClient(client=client)
    if fail_open:
        opa._fail_open = True  # type: ignore[attr-defined]
    else:
        opa._fail_open = False  # type: ignore[attr-defined]
    return opa


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

@respx.mock
async def test_bool_result_allow() -> None:
    respx.post(_opa_url()).respond(200, json={"result": True})
    opa = _build_client(transport=httpx.AsyncHTTPTransport())

    decision = await opa.evaluate({"action": "x"})
    assert isinstance(decision, OpaDecision)
    assert decision.allow is True
    assert decision.deny_reason is None


@respx.mock
async def test_bool_result_deny() -> None:
    respx.post(_opa_url()).respond(200, json={"result": False})
    opa = _build_client(transport=httpx.AsyncHTTPTransport())

    decision = await opa.evaluate({"action": "x"})
    assert decision.allow is False


@respx.mock
async def test_dict_result_with_metadata() -> None:
    respx.post(_opa_url()).respond(
        200,
        json={
            "result": {
                "allow": False,
                "deny_reason": "mfa_required",
                "matched_policy": "billing.refund.mfa",
            }
        },
    )
    opa = _build_client(transport=httpx.AsyncHTTPTransport())

    decision = await opa.evaluate({"action": "x"})
    assert decision.allow is False
    assert decision.deny_reason == "mfa_required"
    assert decision.matched_policy == "billing.refund.mfa"


@respx.mock
async def test_undefined_result_is_default_deny() -> None:
    respx.post(_opa_url()).respond(200, json={})  # no `result`
    opa = _build_client(transport=httpx.AsyncHTTPTransport())

    decision = await opa.evaluate({"action": "x"})
    assert decision.allow is False
    assert decision.deny_reason == "opa_undefined"


# ---------------------------------------------------------------------------
# Error responses
# ---------------------------------------------------------------------------

@respx.mock
async def test_non_200_raises_decision_error() -> None:
    respx.post(_opa_url()).respond(500, text="boom")
    opa = _build_client(transport=httpx.AsyncHTTPTransport())

    with pytest.raises(FoundationError) as ei:
        await opa.evaluate({"action": "x"})
    assert ei.value.error_code is OPA_DECISION_ERROR


@respx.mock
async def test_non_json_raises_decision_error() -> None:
    respx.post(_opa_url()).respond(
        200, headers={"content-type": "application/json"}, text="not-json"
    )
    opa = _build_client(transport=httpx.AsyncHTTPTransport())

    with pytest.raises(FoundationError) as ei:
        await opa.evaluate({"action": "x"})
    assert ei.value.error_code is OPA_DECISION_ERROR


# ---------------------------------------------------------------------------
# Timeout / unreachable behaviour
# ---------------------------------------------------------------------------

class _TimeoutTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("forced timeout", request=request)


class _UnreachableTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)


async def test_timeout_fail_close_raises_opa_timeout() -> None:
    opa = _build_client(transport=_TimeoutTransport(), fail_open=False)

    with pytest.raises(FoundationError) as ei:
        await opa.evaluate({"action": "x"})
    assert ei.value.error_code is OPA_TIMEOUT


async def test_timeout_fail_open_returns_allow() -> None:
    opa = _build_client(transport=_TimeoutTransport(), fail_open=True)

    decision = await opa.evaluate({"action": "x"})
    assert decision.allow is True
    assert decision.deny_reason == "opa_timeout_fail_open"


async def test_unreachable_fail_close_raises_opa_unavailable() -> None:
    opa = _build_client(transport=_UnreachableTransport(), fail_open=False)

    with pytest.raises(FoundationError) as ei:
        await opa.evaluate({"action": "x"})
    assert ei.value.error_code is OPA_UNAVAILABLE


async def test_unreachable_fail_open_returns_allow() -> None:
    opa = _build_client(transport=_UnreachableTransport(), fail_open=True)

    decision = await opa.evaluate({"action": "x"})
    assert decision.allow is True
    assert decision.deny_reason == "opa_unavailable_fail_open"


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------

@respx.mock
async def test_evaluate_wraps_input_in_input_key() -> None:
    route = respx.post(_opa_url()).respond(200, json={"result": True})
    opa = _build_client(transport=httpx.AsyncHTTPTransport())

    await opa.evaluate({"action": "billing.invoice.read", "user": {"id": "u"}})

    assert route.called
    sent_body = route.calls.last.request.read().decode()
    assert '"input"' in sent_body
    assert '"action": "billing.invoice.read"' in sent_body
