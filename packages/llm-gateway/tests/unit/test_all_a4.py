"""LLM Gateway service tests: model pricing and the provider capability probe.

Compliance, billing and API-platform service tests live in those packages'
own suites (each package runs in its own venv, so they cannot import here).
"""

import pytest
from foundation_llm_gateway.services.llm_gateway_service import LLMGatewayService, MODEL_PRICING


class TestLLMGateway:
    @pytest.fixture
    def svc(self): return LLMGatewayService()

    def test_model_pricing_has_entries(self):
        assert "claude-sonnet-4-20250514" in MODEL_PRICING
        assert "deepseek-v3" in MODEL_PRICING
        # (prompt_price, completion_price) per 1M tokens
        assert MODEL_PRICING["claude-sonnet-4-20250514"] == (3.00, 15.00)

    @pytest.mark.skip(reason="Proxy env issue in sandbox — probe works in real deployment")
    async def test_probe_endpoint_unreachable(self, svc):
        result = await svc.probe_endpoint("http://localhost:19999", "fake-key", "openai_compatible")
        assert "list_models" in result
        assert "FAILED" in str(result["list_models"])

    # ── new probe tests (mock httpx) ────────────────────────────────────────

    async def test_probe_context_window_32k(self, svc, monkeypatch):
        """context_window_32k is True when a model reports context_length >= 32768."""
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import ProviderKind

        _models_resp = httpx.Response(200, json={
            "data": [
                {"id": "test-model", "context_length": 65536},
            ]
        })
        _chat_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "hi", "tool_calls": None}}]
        }, headers={"content-type": "application/json"})
        _stream_resp = httpx.Response(200, json={}, headers={"content-type": "text/event-stream"})
        _parallel_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
                {"id": "tc2", "function": {"name": "tool_beta",  "arguments": "{}"}},
            ]}}]
        })

        _responses: list = [_models_resp, _chat_resp, _stream_resp, _parallel_resp]

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return None
            async def get(self, url, **kw): return _responses.pop(0)
            async def post(self, url, **kw): return _responses.pop(0)

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await svc.probe_endpoint("http://fake-llm", "sk-fake", ProviderKind.OPENAI_COMPATIBLE)

        assert result["list_models"] is True
        assert result["model_count"] == "1"
        assert result["context_window_value"] == "65536"
        assert result["context_window_32k"] is True

    async def test_probe_context_window_below_32k(self, svc, monkeypatch):
        """context_window_32k is False when all models report < 32768 tokens."""
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import ProviderKind

        _models_resp = httpx.Response(200, json={
            "data": [{"id": "tiny-model", "context_length": 4096}]
        })
        _chat_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "ok", "tool_calls": None}}]
        }, headers={"content-type": "application/json"})
        _stream_resp = httpx.Response(200, json={}, headers={"content-type": "text/event-stream"})
        _parallel_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            ]}}]
        })
        _responses = [_models_resp, _chat_resp, _stream_resp, _parallel_resp]

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return None
            async def get(self, url, **kw): return _responses.pop(0)
            async def post(self, url, **kw): return _responses.pop(0)

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await svc.probe_endpoint("http://fake-llm", "sk-fake", ProviderKind.OPENAI_COMPATIBLE)

        assert result["context_window_32k"] is False
        assert result["context_window_value"] == "4096"

    async def test_probe_context_window_unknown_when_field_absent(self, svc, monkeypatch):
        """context_window_32k is 'unknown' when model objects lack context fields."""
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import ProviderKind

        _models_resp = httpx.Response(200, json={"data": [{"id": "mystery-model"}]})
        _chat_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "ok", "tool_calls": None}}]
        }, headers={"content-type": "application/json"})
        _stream_resp = httpx.Response(200, json={}, headers={"content-type": "text/event-stream"})
        _parallel_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": []}}]
        })
        _responses = [_models_resp, _chat_resp, _stream_resp, _parallel_resp]

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return None
            async def get(self, url, **kw): return _responses.pop(0)
            async def post(self, url, **kw): return _responses.pop(0)

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await svc.probe_endpoint("http://fake-llm", "sk-fake", ProviderKind.OPENAI_COMPATIBLE)

        assert result["context_window_32k"] == "unknown"
        assert result["context_window_value"] == "unknown"

    async def test_probe_parallel_tool_calls_true(self, svc, monkeypatch):
        """parallel_tool_calls is True when 2+ tool_calls returned in one message."""
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import ProviderKind

        _models_resp = httpx.Response(200, json={"data": [{"id": "m", "context_length": 128000}]})
        _chat_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            ]}}]
        }, headers={"content-type": "application/json"})
        _stream_resp = httpx.Response(200, json={}, headers={"content-type": "text/event-stream"})
        _parallel_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
                {"id": "tc2", "function": {"name": "tool_beta",  "arguments": "{}"}},
            ]}}]
        })
        _responses = [_models_resp, _chat_resp, _stream_resp, _parallel_resp]

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return None
            async def get(self, url, **kw): return _responses.pop(0)
            async def post(self, url, **kw): return _responses.pop(0)

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await svc.probe_endpoint("http://fake-llm", "sk-fake", ProviderKind.OPENAI_COMPATIBLE)

        assert result["parallel_tool_calls"] is True

    async def test_probe_parallel_tool_calls_false(self, svc, monkeypatch):
        """parallel_tool_calls is False when only one tool_call is returned."""
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import ProviderKind

        _models_resp = httpx.Response(200, json={"data": [{"id": "m"}]})
        _chat_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": []}}]
        }, headers={"content-type": "application/json"})
        _stream_resp = httpx.Response(200, json={}, headers={"content-type": "text/event-stream"})
        _parallel_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
            ]}}]
        })
        _responses = [_models_resp, _chat_resp, _stream_resp, _parallel_resp]

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return None
            async def get(self, url, **kw): return _responses.pop(0)
            async def post(self, url, **kw): return _responses.pop(0)

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await svc.probe_endpoint("http://fake-llm", "sk-fake", ProviderKind.OPENAI_COMPATIBLE)

        assert result["parallel_tool_calls"] is False

    async def test_probe_all_capabilities_present(self, svc, monkeypatch):
        """Result dict always contains all expected capability keys."""
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import ProviderKind

        _models_resp = httpx.Response(200, json={"data": [{"id": "m", "context_length": 32768}]})
        _chat_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "hi", "tool_calls": None}}]
        }, headers={"content-type": "application/json"})
        _stream_resp = httpx.Response(200, json={}, headers={"content-type": "text/event-stream"})
        _parallel_resp = httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "function": {"name": "tool_alpha", "arguments": "{}"}},
                {"id": "tc2", "function": {"name": "tool_beta",  "arguments": "{}"}},
            ]}}]
        })
        _responses = [_models_resp, _chat_resp, _stream_resp, _parallel_resp]

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return None
            async def get(self, url, **kw): return _responses.pop(0)
            async def post(self, url, **kw): return _responses.pop(0)

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await svc.probe_endpoint("http://fake-llm", "sk-fake", ProviderKind.OPENAI_COMPATIBLE)

        required_keys = {
            "list_models", "model_count",
            "function_calling", "streaming",
            "context_window_32k", "context_window_value",
            "parallel_tool_calls",
        }
        assert required_keys.issubset(result.keys()), f"Missing keys: {required_keys - result.keys()}"
        assert result["context_window_32k"] is True  # exactly 32768
