"""Unit tests for LLMGatewayService.probe_endpoint — new capabilities.

Covers: context_window_32k, context_window_value, parallel_tool_calls.
All tests use a monkeypatched httpx.AsyncClient, so no real LLM endpoint
is needed.  These tests are self-contained and only import foundation_llm_gateway.
"""

from __future__ import annotations

import httpx
import pytest

from foundation_llm_gateway.services.llm_gateway_service import (
    LLMGatewayService,
    ProviderKind,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_models_resp(models: list[dict]) -> httpx.Response:
    return httpx.Response(200, json={"data": models})


def _make_chat_resp(tool_calls: list[dict] | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={"choices": [{"message": {
            "role": "assistant",
            "content": None if tool_calls else "hi",
            "tool_calls": tool_calls,
        }}]},
        headers={"content-type": "application/json"},
    )


def _make_stream_resp() -> httpx.Response:
    return httpx.Response(200, json={}, headers={"content-type": "text/event-stream"})


def _make_parallel_resp(tool_calls: list[dict]) -> httpx.Response:
    return httpx.Response(
        200,
        json={"choices": [{"message": {
            "role": "assistant",
            "content": None,
            "tool_calls": tool_calls,
        }}]},
    )


def _build_fake_client(responses: list[httpx.Response]):
    """Return a fake AsyncClient class that pops from ``responses``."""

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kw):
            return responses.pop(0)

        async def post(self, url, **kw):
            return responses.pop(0)

    return _FakeClient


# ─── Tests ───────────────────────────────────────────────────────────────────

@pytest.fixture
def svc() -> LLMGatewayService:
    return LLMGatewayService()


async def test_probe_context_window_32k_true(svc, monkeypatch):
    """context_window_32k=True when model reports context_length >= 32768."""
    responses = [
        _make_models_resp([{"id": "big-model", "context_length": 65536}]),
        _make_chat_resp(),
        _make_stream_resp(),
        _make_parallel_resp([
            {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            {"id": "tc2", "function": {"name": "tool_beta", "arguments": "{}"}},
        ]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["context_window_32k"] is True
    assert result["context_window_value"] == "65536"


async def test_probe_context_window_32k_exact_boundary(svc, monkeypatch):
    """context_window_32k=True at exactly 32768 (boundary inclusive)."""
    responses = [
        _make_models_resp([{"id": "m", "context_length": 32768}]),
        _make_chat_resp(),
        _make_stream_resp(),
        _make_parallel_resp([
            {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            {"id": "tc2", "function": {"name": "tool_beta", "arguments": "{}"}},
        ]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["context_window_32k"] is True
    assert result["context_window_value"] == "32768"


async def test_probe_context_window_32k_false(svc, monkeypatch):
    """context_window_32k=False when model reports < 32768."""
    responses = [
        _make_models_resp([{"id": "tiny", "context_length": 4096}]),
        _make_chat_resp(),
        _make_stream_resp(),
        _make_parallel_resp([
            {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
        ]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["context_window_32k"] is False
    assert result["context_window_value"] == "4096"


async def test_probe_context_window_uses_max_tokens_field(svc, monkeypatch):
    """Falls back to max_tokens field when context_length is absent."""
    responses = [
        _make_models_resp([{"id": "m", "max_tokens": 131072}]),
        _make_chat_resp(),
        _make_stream_resp(),
        _make_parallel_resp([
            {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            {"id": "tc2", "function": {"name": "tool_beta", "arguments": "{}"}},
        ]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["context_window_32k"] is True
    assert result["context_window_value"] == "131072"


async def test_probe_context_window_unknown_when_no_field(svc, monkeypatch):
    """context_window_32k='unknown' when no context field present on any model."""
    responses = [
        _make_models_resp([{"id": "mystery"}]),
        _make_chat_resp(),
        _make_stream_resp(),
        _make_parallel_resp([]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["context_window_32k"] == "unknown"
    assert result["context_window_value"] == "unknown"


async def test_probe_parallel_tool_calls_true(svc, monkeypatch):
    """parallel_tool_calls=True when 2+ tool_calls in one assistant message."""
    responses = [
        _make_models_resp([{"id": "m", "context_length": 128000}]),
        _make_chat_resp([{"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}}]),
        _make_stream_resp(),
        _make_parallel_resp([
            {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            {"id": "tc2", "function": {"name": "tool_beta",  "arguments": "{}"}},
        ]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["parallel_tool_calls"] is True


async def test_probe_parallel_tool_calls_false_single(svc, monkeypatch):
    """parallel_tool_calls=False when only one tool_call is returned."""
    responses = [
        _make_models_resp([{"id": "m"}]),
        _make_chat_resp(),
        _make_stream_resp(),
        _make_parallel_resp([
            {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
        ]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["parallel_tool_calls"] is False


async def test_probe_parallel_tool_calls_false_empty(svc, monkeypatch):
    """parallel_tool_calls=False when tool_calls is empty list."""
    responses = [
        _make_models_resp([{"id": "m"}]),
        _make_chat_resp(),
        _make_stream_resp(),
        _make_parallel_resp([]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert result["parallel_tool_calls"] is False


async def test_probe_result_has_all_required_keys(svc, monkeypatch):
    """Result dict always includes every expected capability key."""
    responses = [
        _make_models_resp([{"id": "m", "context_length": 32768}]),
        _make_chat_resp([{"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}}]),
        _make_stream_resp(),
        _make_parallel_resp([
            {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            {"id": "tc2", "function": {"name": "tool_beta",  "arguments": "{}"}},
        ]),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _build_fake_client(responses))
    result = await svc.probe_endpoint("http://fake", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    required = {
        "list_models", "model_count",
        "function_calling", "streaming",
        "context_window_32k", "context_window_value",
        "parallel_tool_calls",
    }
    missing = required - result.keys()
    assert not missing, f"Result missing keys: {missing}"


async def test_probe_context_window_unknown_when_list_models_fails(svc, monkeypatch):
    """context_window='unknown' when GET /v1/models errors out."""

    class _ErrorClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kw):
            raise httpx.ConnectError("connection refused")

        async def post(self, url, **kw):
            return httpx.Response(400, json={"error": "bad request"})

    monkeypatch.setattr(httpx, "AsyncClient", _ErrorClient)
    result = await svc.probe_endpoint("http://unreachable", "sk-x", ProviderKind.OPENAI_COMPATIBLE)

    assert "FAILED" in str(result["list_models"])
    assert result["context_window_32k"] == "unknown"
    assert result["context_window_value"] == "unknown"
