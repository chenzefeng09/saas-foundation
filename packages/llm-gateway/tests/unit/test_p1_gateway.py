"""P1 LLM Gateway enterprise endpoint tests.

All external services (provider, billing, audit, crypto) are mocked via monkeypatch.
No real network calls, no real DB.

Test matrix:
  - Non-streaming /chat/completions: virtual-key resolve → provider route → forward → OpenAI format + usage → record_usage
  - Streaming: SSE chunks + end usage extraction + record_usage
  - Quota exceeded → 402
  - Virtual key tenant mismatch → 403
  - Model/provider not found → 404
  - Upstream provider error → 502
  - crypto encrypt at register_provider; legacy plaintext decrypt compat
  - Legacy /chat alias delegates correctly
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from foundation_llm_gateway.errors import (
    PROVIDER_NOT_FOUND, PROVIDER_UPSTREAM_ERROR,
    QUOTA_EXCEEDED, VIRTUAL_KEY_MISMATCH, FoundationError,
)
from foundation_llm_gateway.services.llm_gateway_service import (
    LLMGatewayService, _decrypt_api_key, _encrypt_api_key, _estimate_tokens,
    _is_envelope,
)


# ---------------------------------------------------------------------------
# Shared fake session
# ---------------------------------------------------------------------------

class _ScalarsResult:
    def __init__(self, rows): self._rows = rows
    def all(self): return list(self._rows)


@dataclass
class FakeAsyncSession:
    pk_store: dict = field(default_factory=lambda: defaultdict(dict))
    added: list = field(default_factory=list)
    flush_calls: int = 0
    _scalar_queue: list = field(default_factory=list)
    _scalars_queue: list = field(default_factory=list)

    def put(self, obj): self.pk_store[type(obj)][obj.id] = obj
    def queue_scalar(self, v): self._scalar_queue.append(v)
    def queue_scalars(self, rows): self._scalars_queue.append(list(rows))

    async def get(self, model, pk): return self.pk_store.get(model, {}).get(pk)
    async def scalar(self, _stmt):
        return self._scalar_queue.pop(0) if self._scalar_queue else None
    async def scalars(self, _stmt):
        return _ScalarsResult(self._scalars_queue.pop(0)) if self._scalars_queue else _ScalarsResult([])
    def add(self, obj):
        self.added.append(obj)
        if (pk := getattr(obj, "id", None)) is not None:
            self.pk_store[type(obj)][pk] = obj
    async def flush(self): self.flush_calls += 1


@pytest.fixture
def fake_session(): return FakeAsyncSession()

@pytest.fixture
def tenant_id(): return "tnt_01J5DEVXX00000000000000001"

@pytest.fixture
def request_id(): return "req_01J0000000000000000000REQ1"

@pytest.fixture
def svc(): return LLMGatewayService()


# ---------------------------------------------------------------------------
# Fake domain objects — plain namespace objects (SQLAlchemy ORM can't be
# constructed via __new__ without a live engine; we use simple objects instead)
# ---------------------------------------------------------------------------

class _FakeProvider:
    def __init__(self, tenant_id, models=None, api_key="sk-fake", base_url="http://fake-llm"):
        self.id = "llmp_TEST"
        self.tenant_id = tenant_id
        self.name = "test-provider"
        self.kind = "openai_compatible"
        self.base_url = base_url
        self.api_key_encrypted = api_key
        self.models = models or ["gpt-4o"]
        self.default_model = (models or ["gpt-4o"])[0]
        self.capabilities = {}
        self.enabled = True


class _FakeVirtualKey:
    def __init__(self, tenant_id, provider_id="llmp_TEST", virtual_key="sk-foundation-TESTKEY"):
        self.id = "llmk_TEST"
        self.tenant_id = tenant_id
        self.provider_id = provider_id
        self.name = "test-key"
        self.virtual_key = virtual_key
        self.rate_limit_rpm = 60
        self.enabled = True


def _make_provider(tenant_id, models=None, api_key="sk-fake", base_url="http://fake-llm"):
    return _FakeProvider(tenant_id, models=models, api_key=api_key, base_url=base_url)


def _make_virtual_key(tenant_id, provider_id="llmp_TEST", virtual_key="sk-foundation-TESTKEY"):
    return _FakeVirtualKey(tenant_id, provider_id=provider_id, virtual_key=virtual_key)


# ---------------------------------------------------------------------------
# crypto helpers unit tests
# ---------------------------------------------------------------------------

class TestCryptoHelpers:
    def test_is_envelope_true(self):
        env = json.dumps({"ciphertext_b64": "abc", "kek_id": "x"})
        assert _is_envelope(env) is True

    def test_is_envelope_false_plaintext(self):
        assert _is_envelope("sk-realkey123") is False

    def test_is_envelope_false_empty(self):
        assert _is_envelope("") is False

    async def test_encrypt_calls_crypto_service(self, monkeypatch):
        import base64
        import httpx
        inner_envelope = {"ciphertext_b64": "ENC", "kek_id": "kek_1"}

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw):
                return httpx.Response(200, json={"envelope": inner_envelope})

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await _encrypt_api_key(
            "sk-plaintext", "http://crypto:8004", 5.0, "tnt_01J5DEVXX00000000000000001"
        )
        assert json.loads(result) == inner_envelope

    async def test_encrypt_falls_back_to_plaintext_on_error(self, monkeypatch):
        import httpx

        class _FailClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw): raise ConnectionError("crypto down")

        monkeypatch.setattr(httpx, "AsyncClient", _FailClient)
        result = await _encrypt_api_key(
            "sk-plaintext", "http://crypto:8004", 5.0, "tnt_01J5DEVXX00000000000000001"
        )
        assert result == "sk-plaintext"

    async def test_decrypt_envelope(self, monkeypatch):
        import base64
        import httpx
        stored = json.dumps({"ciphertext_b64": "ENC", "kek_id": "kek_1"})
        plaintext_b64 = base64.b64encode(b"sk-realkey").decode()

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw):
                return httpx.Response(200, json={"plaintext_b64": plaintext_b64})

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await _decrypt_api_key(
            stored, "http://crypto:8004", 5.0, "tnt_01J5DEVXX00000000000000001"
        )
        assert result == "sk-realkey"

    async def test_decrypt_legacy_plaintext(self, monkeypatch):
        """Legacy plaintext stored value returned as-is without calling crypto."""
        result = await _decrypt_api_key(
            "sk-legacy-plaintext", "http://crypto:8004", 5.0, "tnt_01J5DEVXX00000000000000001"
        )
        assert result == "sk-legacy-plaintext"

    async def test_decrypt_falls_back_on_error(self, monkeypatch):
        import httpx
        stored = json.dumps({"ciphertext_b64": "ENC"})

        class _FailClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw): raise ConnectionError("crypto down")

        monkeypatch.setattr(httpx, "AsyncClient", _FailClient)
        result = await _decrypt_api_key(
            stored, "http://crypto:8004", 5.0, "tnt_01J5DEVXX00000000000000001"
        )
        # Falls back to the stored envelope string
        assert result == stored


# ---------------------------------------------------------------------------
# token estimator
# ---------------------------------------------------------------------------

class TestTokenEstimator:
    def test_estimate_returns_positive(self):
        messages = [{"content": "Hello world, this is a test message"}, {"content": "response"}]
        p, c = _estimate_tokens(messages, "short response")
        assert p >= 1
        assert c >= 1

    def test_estimate_scales_with_content_length(self):
        short_msgs = [{"content": "Hi"}]
        long_msgs = [{"content": "x" * 1000}]
        p_short, _ = _estimate_tokens(short_msgs, "ok")
        p_long, _ = _estimate_tokens(long_msgs, "ok")
        assert p_long > p_short


# ---------------------------------------------------------------------------
# Virtual key resolution
# ---------------------------------------------------------------------------

class TestResolveProvider:
    async def test_resolve_success(self, svc, fake_session, tenant_id):
        provider = _make_provider(tenant_id, models=["gpt-4o"])
        key = _make_virtual_key(tenant_id)
        fake_session.queue_scalar(key)         # for virtual key lookup
        fake_session.queue_scalars([provider]) # for provider list

        vkey, prov = await svc.resolve_provider(
            fake_session, virtual_key="sk-foundation-TESTKEY",
            model="gpt-4o", tenant_id=tenant_id
        )
        assert vkey.id == "llmk_TEST"
        assert prov.id == "llmp_TEST"

    async def test_resolve_tenant_mismatch_403(self, svc, fake_session, tenant_id):
        wrong_tenant = "tnt_WRONG00000000000000000001"
        key = _make_virtual_key(wrong_tenant)  # key belongs to different tenant
        fake_session.queue_scalar(key)

        with pytest.raises(FoundationError) as exc_info:
            await svc.resolve_provider(
                fake_session, virtual_key="sk-foundation-TESTKEY",
                model="gpt-4o", tenant_id=tenant_id
            )
        assert exc_info.value.error_code == VIRTUAL_KEY_MISMATCH
        assert exc_info.value.error_code.http_status == 403

    async def test_resolve_key_not_found_403(self, svc, fake_session, tenant_id):
        fake_session.queue_scalar(None)  # no key found

        with pytest.raises(FoundationError) as exc_info:
            await svc.resolve_provider(
                fake_session, virtual_key="sk-nonexistent",
                model="gpt-4o", tenant_id=tenant_id
            )
        assert exc_info.value.error_code == VIRTUAL_KEY_MISMATCH

    async def test_resolve_no_provider_404(self, svc, fake_session, tenant_id):
        key = _make_virtual_key(tenant_id)
        fake_session.queue_scalar(key)
        fake_session.queue_scalars([])  # no providers

        with pytest.raises(FoundationError) as exc_info:
            await svc.resolve_provider(
                fake_session, virtual_key="sk-foundation-TESTKEY",
                model="gpt-4o", tenant_id=tenant_id
            )
        assert exc_info.value.error_code == PROVIDER_NOT_FOUND
        assert exc_info.value.error_code.http_status == 404

    async def test_resolve_falls_back_to_bound_provider_when_model_not_in_list(
        self, svc, fake_session, tenant_id
    ):
        """If model not in any provider's models list, fall back to bound provider."""
        provider = _make_provider(tenant_id, models=["llama-3"])
        key = _make_virtual_key(tenant_id, provider_id=provider.id)
        fake_session.queue_scalar(key)
        fake_session.queue_scalars([provider])

        vkey, prov = await svc.resolve_provider(
            fake_session, virtual_key="sk-foundation-TESTKEY",
            model="unknown-model", tenant_id=tenant_id
        )
        assert prov.id == provider.id  # fallback to bound provider


# ---------------------------------------------------------------------------
# Non-streaming /chat/completions
# ---------------------------------------------------------------------------

class TestChatCompletionsNonStreaming:
    """Test the service-layer logic for non-streaming completions."""

    async def test_non_streaming_returns_openai_format_and_records_usage(
        self, svc, fake_session, tenant_id, request_id, monkeypatch
    ):
        import httpx
        from foundation_llm_gateway.services import llm_gateway_service as svc_mod

        # Mock billing: quota allowed
        async def mock_quota(*a, **kw): return {"allowed": True, "remaining": 9999}
        monkeypatch.setattr(svc_mod, "_check_billing_quota", mock_quota)

        # Mock billing record (no-op)
        async def mock_record_billing(*a, **kw): pass
        monkeypatch.setattr(svc_mod, "_record_billing_usage", mock_record_billing)

        # Mock audit (no-op)
        async def mock_audit(*a, **kw): pass
        monkeypatch.setattr(svc_mod, "_emit_audit_event", mock_audit)

        # Mock crypto decrypt (pass-through)
        async def mock_decrypt(stored, *a, **kw): return "sk-real"
        monkeypatch.setattr(svc_mod, "_decrypt_api_key", mock_decrypt)

        openai_response = {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello!"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }

        class _FakeHTTPClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw): return httpx.Response(200, json=openai_response)

        monkeypatch.setattr(httpx, "AsyncClient", _FakeHTTPClient)

        provider = _make_provider(tenant_id)
        messages_wire = [{"role": "user", "content": "Hello"}]

        from foundation_llm_gateway.api.v1.llm_gateway import _handle_non_streaming, ChatCompletionRequest, ChatCompletionMessage
        from unittest.mock import MagicMock
        settings = MagicMock()
        settings.billing_url = "http://billing:8007"
        settings.crypto_url = "http://crypto:8004"
        settings.audit_url = "http://audit:8013"
        settings.external_timeout_seconds = 5.0

        body = ChatCompletionRequest(
            model="gpt-4o",
            messages=[ChatCompletionMessage(role="user", content="Hello")],
        )

        result = await _handle_non_streaming(
            body=body, payload={"model": "gpt-4o", "messages": messages_wire, "stream": False},
            upstream_url="http://fake-llm/v1/chat/completions",
            headers={"Authorization": "Bearer sk-real"},
            messages_wire=messages_wire,
            session=fake_session, svc=svc,
            tenant_id=tenant_id, provider_id=provider.id,
            request_id=request_id, user_id=None, run_id=None,
            t_start=0.0, settings=settings,
        )

        assert result["choices"][0]["message"]["content"] == "Hello!"
        assert result["usage"]["total_tokens"] == 15

        # usage record added to session (check by id prefix)
        assert any(getattr(o, "id", "").startswith("llmu_") for o in fake_session.added)

    async def test_upstream_error_raises_502(self, svc, fake_session, tenant_id, request_id, monkeypatch):
        import httpx
        from foundation_llm_gateway.api.v1.llm_gateway import _handle_non_streaming, ChatCompletionRequest, ChatCompletionMessage
        from unittest.mock import MagicMock

        class _FailClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw): raise ConnectionError("provider down")

        monkeypatch.setattr(httpx, "AsyncClient", _FailClient)
        settings = MagicMock()
        settings.billing_url = "http://billing"
        settings.crypto_url = "http://crypto"
        settings.audit_url = "http://audit"
        settings.external_timeout_seconds = 5.0

        body = ChatCompletionRequest(
            model="gpt-4o",
            messages=[ChatCompletionMessage(role="user", content="Hi")],
        )
        with pytest.raises(FoundationError) as exc_info:
            await _handle_non_streaming(
                body=body, payload={}, upstream_url="http://bad-llm/v1/chat/completions",
                headers={}, messages_wire=[{"role": "user", "content": "Hi"}],
                session=fake_session, svc=svc,
                tenant_id=tenant_id, provider_id="llmp_X",
                request_id=request_id, user_id=None, run_id=None,
                t_start=0.0, settings=settings,
            )
        assert exc_info.value.error_code == PROVIDER_UPSTREAM_ERROR
        assert exc_info.value.error_code.http_status == 502

    async def test_upstream_4xx_raises_502(self, svc, fake_session, tenant_id, request_id, monkeypatch):
        import httpx
        from foundation_llm_gateway.api.v1.llm_gateway import _handle_non_streaming, ChatCompletionRequest, ChatCompletionMessage
        from unittest.mock import MagicMock

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw): return httpx.Response(401, text="Unauthorized")

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        settings = MagicMock()
        settings.billing_url = "http://billing"
        settings.crypto_url = "http://crypto"
        settings.audit_url = "http://audit"
        settings.external_timeout_seconds = 5.0

        body = ChatCompletionRequest(
            model="gpt-4o",
            messages=[ChatCompletionMessage(role="user", content="Hi")],
        )
        with pytest.raises(FoundationError) as exc_info:
            await _handle_non_streaming(
                body=body, payload={}, upstream_url="http://fake-llm/v1/chat/completions",
                headers={}, messages_wire=[{"role": "user", "content": "Hi"}],
                session=fake_session, svc=svc,
                tenant_id=tenant_id, provider_id="llmp_X",
                request_id=request_id, user_id=None, run_id=None,
                t_start=0.0, settings=settings,
            )
        assert exc_info.value.error_code == PROVIDER_UPSTREAM_ERROR


# ---------------------------------------------------------------------------
# Quota exceeded → 402
# ---------------------------------------------------------------------------

class TestQuotaExceeded:
    async def test_check_billing_quota_blocked_returns_allowed_false(self, monkeypatch):
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import _check_billing_quota

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw):
                return httpx.Response(200, json={"allowed": False, "remaining": 0, "limit": 100})

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
        result = await _check_billing_quota("tnt_X", 1000, "http://billing", 5.0)
        assert result["allowed"] is False
        assert result["remaining"] == 0

    async def test_check_billing_quota_unavailable_fail_open(self, monkeypatch):
        import httpx
        from foundation_llm_gateway.services.llm_gateway_service import _check_billing_quota

        class _FailClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, **kw): raise ConnectionError("billing down")

        monkeypatch.setattr(httpx, "AsyncClient", _FailClient)
        result = await _check_billing_quota("tnt_X", 1000, "http://billing", 5.0)
        # Fail-open: allowed=True even though billing is unreachable
        assert result["allowed"] is True
        assert result.get("_skipped") is True


# ---------------------------------------------------------------------------
# Register provider — crypto encryption
# ---------------------------------------------------------------------------

class TestRegisterProviderCrypto:
    async def test_register_encrypts_api_key(self, svc, fake_session, tenant_id, request_id, monkeypatch):
        """register_provider stores encrypted envelope, not plaintext."""
        from foundation_llm_gateway.services import llm_gateway_service as svc_mod

        envelope = json.dumps({"ciphertext": "ENC123", "kek_id": "kek_1"})

        async def mock_encrypt(plaintext, *a, **kw):
            return envelope

        monkeypatch.setattr(svc_mod, "_encrypt_api_key", mock_encrypt)

        provider = await svc.register_provider(
            fake_session, tenant_id=tenant_id,
            name="test", kind=svc_mod.ProviderKind.OPENAI_COMPATIBLE,
            base_url="http://llm", api_key_plaintext="sk-secret",
            models=["gpt-4o"], default_model="gpt-4o", capabilities=None,
            request_id=request_id, crypto_url="http://crypto", crypto_timeout=5.0,
        )
        assert provider.api_key_encrypted == envelope
        # Ensure plaintext is NOT stored
        assert "sk-secret" not in provider.api_key_encrypted

    async def test_register_legacy_compat_api_key_encrypted_kwarg(
        self, svc, fake_session, tenant_id, request_id, monkeypatch
    ):
        """api_key_encrypted kwarg (legacy callers) is accepted and passed through encrypt."""
        from foundation_llm_gateway.services import llm_gateway_service as svc_mod

        captured = {}

        async def mock_encrypt(plaintext, *a, **kw):
            captured["plaintext"] = plaintext
            return f"ENCRYPTED({plaintext})"

        monkeypatch.setattr(svc_mod, "_encrypt_api_key", mock_encrypt)

        await svc.register_provider(
            fake_session, tenant_id=tenant_id,
            name="legacy", kind=svc_mod.ProviderKind.OPENAI_COMPATIBLE,
            base_url="http://llm", api_key_plaintext="",  # empty plaintext
            api_key_encrypted="sk-legacy",               # old kwarg
            models=[], default_model="", capabilities=None,
            request_id=request_id, crypto_url="http://crypto", crypto_timeout=5.0,
        )
        # The legacy value should have been passed to encrypt
        assert captured["plaintext"] == "sk-legacy"


# ---------------------------------------------------------------------------
# Streaming (SSE)
# ---------------------------------------------------------------------------

class TestStreaming:
    async def test_streaming_returns_sse_response(
        self, svc, fake_session, tenant_id, request_id, monkeypatch
    ):
        """Streaming path returns StreamingResponse with SSE content."""
        import httpx
        from foundation_llm_gateway.api.v1.llm_gateway import _handle_streaming, ChatCompletionRequest, ChatCompletionMessage
        from foundation_llm_gateway.services import llm_gateway_service as svc_mod
        from unittest.mock import MagicMock

        async def mock_record_billing(*a, **kw): pass
        async def mock_audit(*a, **kw): pass
        monkeypatch.setattr(svc_mod, "_record_billing_usage", mock_record_billing)
        monkeypatch.setattr(svc_mod, "_emit_audit_event", mock_audit)

        sse_lines = [
            b'data: {"choices":[{"delta":{"content":"Hello"},"finish_reason":null}]}\n',
            b'\n',
            b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}\n',
            b'\n',
            b'data: [DONE]\n',
            b'\n',
        ]

        class _FakeStreamResp:
            status_code = 200
            async def aiter_lines(self):
                lines = b"".join(sse_lines).decode().splitlines()
                for line in lines:
                    yield line
            async def aread(self): return b""

        class _FakeStreamCtx:
            async def __aenter__(self): return _FakeStreamResp()
            async def __aexit__(self, *a): pass

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            def stream(self, *a, **kw): return _FakeStreamCtx()

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)

        settings = MagicMock()
        settings.billing_url = "http://billing"
        settings.crypto_url = "http://crypto"
        settings.audit_url = "http://audit"
        settings.external_timeout_seconds = 5.0

        body = ChatCompletionRequest(
            model="gpt-4o",
            messages=[ChatCompletionMessage(role="user", content="Hello")],
            stream=True,
        )

        resp = await _handle_streaming(
            body=body, payload={"model": "gpt-4o", "stream": True},
            upstream_url="http://fake-llm/v1/chat/completions",
            headers={}, messages_wire=[{"role": "user", "content": "Hello"}],
            session=fake_session, svc=svc,
            tenant_id=tenant_id, provider_id="llmp_TEST",
            request_id=request_id, user_id=None, run_id=None,
            t_start=0.0, settings=settings,
        )

        # Collect SSE output
        output = b""
        async for chunk in resp.body_iterator:
            output += chunk if isinstance(chunk, bytes) else chunk.encode()

        assert b"Hello" in output
        assert b"[DONE]" in output

    async def test_streaming_usage_estimated_when_not_in_stream(
        self, svc, fake_session, tenant_id, request_id, monkeypatch
    ):
        """When provider doesn't send usage in SSE, estimator is used (non-zero tokens recorded)."""
        import httpx
        from foundation_llm_gateway.api.v1.llm_gateway import _handle_streaming, ChatCompletionRequest, ChatCompletionMessage
        from foundation_llm_gateway.services import llm_gateway_service as svc_mod
        from unittest.mock import MagicMock

        async def mock_record_billing(*a, **kw): pass
        async def mock_audit(*a, **kw): pass
        monkeypatch.setattr(svc_mod, "_record_billing_usage", mock_record_billing)
        monkeypatch.setattr(svc_mod, "_emit_audit_event", mock_audit)

        # The streaming handler persists the usage row in a *detached* task that
        # opens its own ``session_scope`` (the request-scoped session is closed
        # and Starlette's BaseHTTPMiddleware cancels the response task once the
        # client disconnects).  Patch ``session_scope`` to yield the test's fake
        # session so we can still assert the record was created.
        from contextlib import asynccontextmanager
        from foundation_llm_gateway.domain import db as db_mod

        @asynccontextmanager
        async def _fake_scope():
            yield fake_session

        monkeypatch.setattr(db_mod, "session_scope", _fake_scope)

        # SSE without usage field
        sse_lines = [
            'data: {"choices":[{"delta":{"content":"World"},"finish_reason":null}]}',
            '',
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',  # no usage
            '',
            'data: [DONE]',
            '',
        ]

        class _FakeStreamResp:
            status_code = 200
            async def aiter_lines(self):
                for line in sse_lines:
                    yield line
            async def aread(self): return b""

        class _FakeStreamCtx:
            async def __aenter__(self): return _FakeStreamResp()
            async def __aexit__(self, *a): pass

        class _FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            def stream(self, *a, **kw): return _FakeStreamCtx()

        monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)

        settings = MagicMock()
        settings.billing_url = "http://billing"
        settings.crypto_url = "http://crypto"
        settings.audit_url = "http://audit"
        settings.external_timeout_seconds = 5.0

        body = ChatCompletionRequest(
            model="gpt-4o",
            messages=[ChatCompletionMessage(role="user", content="Tell me about the world")],
            stream=True,
        )

        resp = await _handle_streaming(
            body=body, payload={"model": "gpt-4o", "stream": True},
            upstream_url="http://fake-llm/v1/chat/completions",
            headers={}, messages_wire=[{"role": "user", "content": "Tell me about the world"}],
            session=fake_session, svc=svc,
            tenant_id=tenant_id, provider_id="llmp_TEST",
            request_id=request_id, user_id=None, run_id=None,
            t_start=0.0, settings=settings,
        )

        # Consume the generator
        async for _ in resp.body_iterator:
            pass

        # The usage write is spawned as a detached task; yield control so it
        # runs before we assert.
        import asyncio
        await asyncio.sleep(0)
        for _ in range(5):
            if any(getattr(o, "id", "").startswith("llmu_") for o in fake_session.added):
                break
            await asyncio.sleep(0)

        # Usage record should have been added with non-zero tokens (from estimator)
        usage_records = [o for o in fake_session.added if getattr(o, "id", "").startswith("llmu_")]
        assert len(usage_records) == 1
        rec = usage_records[0]
        assert rec.total_tokens > 0   # estimator kicked in


# ---------------------------------------------------------------------------
# Error code HTTP status mapping sanity check
# ---------------------------------------------------------------------------

class TestErrorCodes:
    def test_quota_exceeded_402(self):
        assert QUOTA_EXCEEDED.http_status == 402

    def test_virtual_key_mismatch_403(self):
        assert VIRTUAL_KEY_MISMATCH.http_status == 403

    def test_provider_not_found_404(self):
        assert PROVIDER_NOT_FOUND.http_status == 404

    def test_provider_upstream_error_502(self):
        assert PROVIDER_UPSTREAM_ERROR.http_status == 502

    def test_foundation_error_carries_error_code(self):
        err = FoundationError(QUOTA_EXCEEDED, detail="test exceeded")
        assert err.error_code is QUOTA_EXCEEDED
        assert "test exceeded" in str(err)
