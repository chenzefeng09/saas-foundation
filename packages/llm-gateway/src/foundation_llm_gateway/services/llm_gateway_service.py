"""LLM Gateway — enterprise proxy with tenant isolation, virtual keys, quota, audit.

Capabilities:
  - Provider registry: register external model endpoints (Claude API, Bedrock, vLLM, etc.)
  - Tenant virtual keys: per-tenant API keys that map to underlying provider keys
  - Capability probing: test endpoint for function calling, streaming, context window
  - Token usage tracking: per-tenant, per-model token counting for billing
  - Quota enforcement: pre-call check (fail-close on exceed), billing integration (fail-open on service unavailable)
  - Audit: metadata-level events (no prompt plaintext stored) emitted async after each call
  - crypto: api_key stored as envelope JSON; legacy plaintext tolerated for migration
  - Failover: primary → fallback provider routing
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import httpx
import ulid
from sqlalchemy import func as sa_func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_llm_gateway.domain.models import (
    LLMProvider, LLMTenantKey, LLMUsageRecord, Outbox,
    LLMTenantDefaultModel, LLMUserModelPreference,
)
from foundation_llm_gateway.observability import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Crypto helpers — envelope encrypt/decrypt via foundation crypto service
# ---------------------------------------------------------------------------

def _is_envelope(value: str) -> bool:
    """Return True if value looks like a crypto envelope JSON (has 'ciphertext_b64' key)."""
    try:
        obj = json.loads(value)
        return isinstance(obj, dict) and "ciphertext_b64" in obj
    except (json.JSONDecodeError, TypeError):
        return False


async def _encrypt_api_key(plaintext: str, crypto_url: str, timeout: float, tenant_id: str) -> str:
    """Encrypt plaintext api_key via the foundation crypto service.

    Returns the inner envelope JSON string to store in the DB.
    Falls back to plaintext on crypto service failure (logs a warning) so that
    provider registration is never blocked by crypto unavailability.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.post(
                f"{crypto_url}/api/crypto/v1/encrypt",
                headers={"X-Tenant-Id": tenant_id, "X-Actor": "SERVICE"},
                json={
                    "key_label": "default",
                    "plaintext_b64": base64.b64encode(plaintext.encode()).decode(),
                },
            )
            if resp.status_code == 200:
                envelope = resp.json()["envelope"]
                return json.dumps(envelope)
            else:
                log.warning("crypto.encrypt_non_200", status=resp.status_code,
                            body=resp.text[:300], fallback="plaintext")
    except Exception as exc:
        log.warning("crypto.encrypt_failed", error=str(exc), fallback="plaintext")
    # Graceful degradation: store as-is (migration compatibility)
    return plaintext


async def _decrypt_api_key(stored: str, crypto_url: str, timeout: float, tenant_id: str) -> str:
    """Decrypt a stored api_key envelope.

    Migration-compatible: if the stored value is NOT an envelope JSON, return
    it as-is (legacy plaintext stored before crypto integration).
    """
    if not _is_envelope(stored):
        # Legacy plaintext — tolerate until migrated
        log.debug("crypto.legacy_plaintext_key", note="not an envelope; using as-is")
        return stored
    try:
        envelope = json.loads(stored)
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.post(
                f"{crypto_url}/api/crypto/v1/decrypt",
                headers={"X-Tenant-Id": tenant_id, "X-Actor": "SERVICE"},
                json={"envelope": envelope},
            )
            if resp.status_code == 200:
                b64 = resp.json().get("plaintext_b64")
                if b64:
                    return base64.b64decode(b64).decode()
            else:
                log.warning("crypto.decrypt_non_200", status=resp.status_code,
                            body=resp.text[:300], fallback="stored_value")
    except Exception as exc:
        log.warning("crypto.decrypt_failed", error=str(exc), fallback="stored_value")
    # Fall back to raw stored value — worst case the upstream call will 401
    return stored


# ---------------------------------------------------------------------------
# Billing quota helpers (fail-open on unavailability)
# ---------------------------------------------------------------------------

async def _check_billing_quota(
    tenant_id: str, tokens_estimate: int,
    billing_url: str, timeout: float,
) -> dict[str, Any]:
    """Call billing quota check for llm_tokens dimension.

    Returns {allowed, remaining, limit} or {allowed: True, _skipped: True}
    when billing service is unreachable (fail-open to avoid blocking agents).
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.post(
                f"{billing_url}/api/billing/v1/quota/check",
                json={"dimension": "llm_tokens", "requested": tokens_estimate},
                headers={"X-Tenant-Id": tenant_id, "X-Actor": "SERVICE"},
            )
            if resp.status_code == 200:
                return resp.json()
            log.warning("billing.quota_check_non200", status=resp.status_code, tenant_id=tenant_id)
    except Exception as exc:
        # IMPORTANT: billing service unreachable → fail-open, log alert
        log.warning("billing.quota_check_unreachable", error=str(exc), tenant_id=tenant_id,
                    alert="BILLING_UNAVAILABLE_FAIL_OPEN")
    return {"allowed": True, "_skipped": True}


async def _record_billing_usage(
    tenant_id: str, tokens: int,
    billing_url: str, timeout: float,
) -> None:
    """Record llm_tokens usage in billing service. Best-effort, never raises."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            await c.post(
                f"{billing_url}/api/billing/v1/quota/usage",
                json={"dimension": "llm_tokens", "amount": float(tokens), "description": "llm_gateway"},
                headers={"X-Tenant-Id": tenant_id, "X-Actor": "SERVICE"},
            )
    except Exception as exc:
        log.warning("billing.record_usage_failed", error=str(exc), tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Audit helper (async, non-blocking, metadata-only)
# ---------------------------------------------------------------------------

async def _emit_audit_event(
    *, tenant_id: str, user_id: str | None, run_id: str | None,
    model: str, prompt_tokens: int, completion_tokens: int,
    finish_reason: str | None, latency_ms: float,
    audit_url: str, timeout: float,
    prompt_cache_hit_tokens: int = 0, prompt_cache_miss_tokens: int = 0,
) -> None:
    """Fire-and-forget audit event. Stores hashes of content, not plaintext (PII protection)."""
    try:
        # The audit service's AuditEvent schema is strict (``extra="forbid"``)
        # and requires event_id / occurred_at / service / actor_kind / payload.
        # An earlier shape (actor / metadata / user_id) was rejected with 422,
        # which silently dropped every LLM audit event.  Build the conforming
        # envelope here so chat completions are actually recorded.
        body = {
            "event_id": f"evt_{ulid.new()!s}",
            "schema_version": 1,
            "occurred_at": datetime.now(UTC).isoformat(),
            "tenant_id": tenant_id,
            "service": "llm-gateway",
            "event_type": "foundation.llm_gateway.chat.completion",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "actor_kind": "SERVICE_ACCOUNT",
            "actor_user_id": user_id,
            "resource_type": "llm_run",
            "resource_id": run_id,
            "payload": {
                "model": model,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "prompt_cache_hit_tokens": prompt_cache_hit_tokens,
                "prompt_cache_miss_tokens": prompt_cache_miss_tokens,
                "finish_reason": finish_reason,
                "latency_ms": round(latency_ms, 1),
                # Prompt/response content stored as hash only (PII protection)
                "prompt_sha256": None,
                "response_sha256": None,
            },
        }
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.post(
                f"{audit_url}/api/audit/v1/events",
                json=body,
                # NOTE: the audit middleware's X-Actor allow-list is
                # {USER, SERVICE, SYSTEM, MIGRATOR, ADMIN} — it does NOT accept
                # SERVICE_ACCOUNT (that value is only valid for the body's
                # ``actor_kind`` field).  Send "SERVICE" in the header.
                headers={"X-Tenant-Id": tenant_id, "X-Actor": "SERVICE"},
            )
            if resp.status_code >= 400:
                log.warning("audit.emit_non2xx", status=resp.status_code,
                            body=resp.text[:200], tenant_id=tenant_id)
    except Exception as exc:
        log.warning("audit.emit_failed", error=str(exc), tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Token estimator fallback (when provider doesn't return usage in stream)
# ---------------------------------------------------------------------------

def _estimate_tokens(messages: list[dict], response_text: str) -> tuple[int, int]:
    """Rough token estimator: ~4 chars per token. Used when provider omits usage in SSE."""
    prompt_chars = sum(len(str(m.get("content") or "")) for m in messages)
    prompt_est = max(1, prompt_chars // 4)
    completion_est = max(1, len(response_text) // 4)
    return prompt_est, completion_est


class ProviderKind(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"
    VLLM = "vllm"
    OLLAMA = "ollama"
    BEDROCK = "bedrock"
    AZURE = "azure"
    ZHIPU = "zhipu"
    DEEPSEEK = "deepseek"
    MOONSHOT = "moonshot"
    MINIMAX = "minimax"
    ALIYUN = "aliyun"
    BAIDU = "baidu"
    TENCENT = "tencent"
    SGLANG = "sglang"
    LLAMACPP = "llamacpp"


REQUIRED_CAPABILITIES = {
    "function_calling": "Agent tool use requires function calling support",
    "streaming": "Frontend requires token-by-token streaming",
    "context_window_32k": "Complex tasks require at least 32K context window",
}


class LLMGatewayService:
    """Central LLM routing and management."""

    # ------------------------------------------------------------------ Providers

    async def register_provider(
        self, session: AsyncSession, *, tenant_id: str,
        name: str, kind: ProviderKind, base_url: str,
        api_key_plaintext: str,          # caller passes plaintext; we encrypt here
        models: list[str],
        default_model: str, capabilities: dict[str, bool] | None,
        request_id: str,
        crypto_url: str = "http://127.0.0.1:8004",
        crypto_timeout: float = 5.0,
        # Legacy kwarg kept for backward compat with existing callers that pass api_key_encrypted
        api_key_encrypted: str | None = None,
    ) -> LLMProvider:
        """Register an external LLM provider endpoint.

        api_key_plaintext is encrypted via the crypto service before storage.
        If crypto_url is unreachable the plaintext is stored with a warning
        (graceful degradation — logs CRYPTO_UNAVAILABLE_FALLBACK).

        Backward-compat: if api_key_plaintext is empty but api_key_encrypted is
        provided, the api_key_encrypted value is used as-is (supports callers
        that pre-encrypt or pass the legacy field name).
        """
        raw_key = api_key_plaintext or api_key_encrypted or ""
        stored_key = await _encrypt_api_key(raw_key, crypto_url, crypto_timeout, tenant_id)

        provider = LLMProvider(
            id=f"llmp_{ulid.new()!s}",
            tenant_id=tenant_id,
            name=name,
            kind=kind.value,
            base_url=base_url,
            api_key_encrypted=stored_key,
            models=models,
            default_model=default_model,
            capabilities=capabilities or {},
            enabled=True,
        )
        session.add(provider)
        self._emit(session, tenant_id, "foundation.llm_gateway.provider.registered",
                   {"provider": name, "models": models}, request_id)
        await session.flush()
        return provider

    async def update_provider(
        self, session: AsyncSession, *, provider_id: str, tenant_id: str,
        enabled: bool | None = None, name: str | None = None,
        models: list[str] | None = None, default_model: str | None = None,
        capabilities: dict[str, Any] | None = None,
        request_id: str,
    ) -> LLMProvider:
        """Update mutable fields of an existing provider.

        ``capabilities`` is treated as a SHALLOW merge-patch (not a wholesale
        replace): each top-level key in the incoming dict is merged into the
        provider's existing ``capabilities``. A value of ``None`` DELETES that
        key (the convention for removing a capability, e.g.
        ``{"cache_metric_unreliable": None}``); any other value sets/overwrites
        it. Top-level keys not present in the incoming dict are left untouched
        — so a patch touching only ``affinity_mode`` preserves
        ``model_type_map``/``model_settings`` and vice versa.
        """
        provider = await session.scalar(
            select(LLMProvider).where(
                LLMProvider.id == provider_id,
                LLMProvider.tenant_id == tenant_id,
            ).limit(1)
        )
        if provider is None:
            from foundation_llm_gateway.errors import PROVIDER_NOT_FOUND, FoundationError
            raise FoundationError(PROVIDER_NOT_FOUND, detail=f"Provider {provider_id!r} not found")
        if enabled is not None:
            provider.enabled = enabled
        if name is not None:
            provider.name = name
        if models is not None:
            provider.models = models
        if default_model is not None:
            provider.default_model = default_model
        if capabilities is not None:
            # Shallow merge-patch into a NEW dict so SQLAlchemy flags the JSONB
            # column dirty (in-place mutation may go undetected without
            # MutableDict). None value => delete the key.
            merged = dict(provider.capabilities or {})
            for key, value in capabilities.items():
                if value is None:
                    merged.pop(key, None)
                else:
                    merged[key] = value
            provider.capabilities = merged
        self._emit(session, tenant_id, "foundation.llm_gateway.provider.updated",
                   {"provider": provider.name, "provider_id": provider_id}, request_id)
        await session.flush()
        return provider

    async def delete_provider(
        self, session: AsyncSession, *, provider_id: str, tenant_id: str,
        request_id: str,
    ) -> None:
        """Hard-delete a provider."""
        provider = await session.scalar(
            select(LLMProvider).where(
                LLMProvider.id == provider_id,
                LLMProvider.tenant_id == tenant_id,
            ).limit(1)
        )
        if provider is None:
            from foundation_llm_gateway.errors import PROVIDER_NOT_FOUND, FoundationError
            raise FoundationError(PROVIDER_NOT_FOUND, detail=f"Provider {provider_id!r} not found")
        self._emit(session, tenant_id, "foundation.llm_gateway.provider.deleted",
                   {"provider": provider.name, "provider_id": provider_id}, request_id)
        await session.delete(provider)
        await session.flush()

    # ------------------------------------------------------------------ Virtual Key → Provider

    async def resolve_provider(
        self, session: AsyncSession, *, virtual_key: str, model: str, tenant_id: str,
    ) -> tuple[LLMTenantKey, LLMProvider]:
        """Resolve a virtual key + model to (tenant_key, provider).

        Resolution order:
          1. Lookup LLMTenantKey by virtual_key (must be enabled).
          2. Verify key.tenant_id == tenant_id (403 on mismatch).
          3. Find provider: prefer provider whose models list contains `model`;
             fall back to the provider bound to the virtual key.
          4. If no enabled provider found → 404.

        Raises:
          FoundationError(VIRTUAL_KEY_MISMATCH) if tenant mismatch.
          FoundationError(PROVIDER_NOT_FOUND) if no usable provider.
        """
        from foundation_llm_gateway.errors import VIRTUAL_KEY_MISMATCH, PROVIDER_NOT_FOUND, FoundationError

        # Step 1: look up the virtual key
        key_row = await session.scalar(
            select(LLMTenantKey).where(
                LLMTenantKey.virtual_key == virtual_key,
                LLMTenantKey.enabled.is_(True),
            ).limit(1)
        )
        if key_row is None:
            raise FoundationError(VIRTUAL_KEY_MISMATCH, detail="Virtual key not found or disabled")

        # Step 2: tenant cross-check (security boundary)
        if key_row.tenant_id != tenant_id:
            log.warning("virtual_key.tenant_mismatch",
                        key_tenant=key_row.tenant_id, ctx_tenant=tenant_id)
            raise FoundationError(VIRTUAL_KEY_MISMATCH,
                detail="Virtual key tenant does not match request tenant")

        # Step 3a: find provider that supports this model
        providers = list((await session.scalars(
            select(LLMProvider).where(
                LLMProvider.tenant_id == tenant_id,
                LLMProvider.enabled.is_(True),
            )
        )).all())

        model_matched = [p for p in providers if p.models and model in p.models]
        bound = next((p for p in providers if p.id == key_row.provider_id), None)

        if model_matched:
            provider = model_matched[0]
        elif bound:
            # Fallback: use the provider the virtual key is bound to
            log.info("resolve_provider.model_fallback",
                     model=model, provider_id=bound.id, reason="model_not_in_any_provider_list")
            provider = bound
        else:
            raise FoundationError(PROVIDER_NOT_FOUND,
                detail=f"No enabled provider found for model={model!r} in tenant={tenant_id!r}")

        return key_row, provider

    async def probe_endpoint(
        self, base_url: str, api_key: str, kind: ProviderKind,
    ) -> dict[str, Any]:
        """Test an endpoint for capabilities. Returns compatibility report.

        Probed capabilities:
          list_models          — GET /v1/models returns 200
          model_count          — number of models advertised
          function_calling     — /v1/chat/completions accepts tools parameter
          streaming            — response Content-Type is text/event-stream
          context_window_32k   — reported context_length / max_tokens >= 32768
          context_window_value — raw context_length value found (int or "unknown")
          parallel_tool_calls  — single request triggers multiple tool_call entries
        """
        import httpx
        results: dict[str, bool | str] = {}
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=15.0) as c:
            # 1. List models — also used to probe context_window
            model_id = "test"  # default fallback model name
            try:
                r = await c.get(f"{base_url}/v1/models", headers=headers)
                results["list_models"] = r.status_code == 200
                if r.status_code == 200:
                    model_list = r.json().get("data", [])
                    results["model_count"] = str(len(model_list))
                    # Pick the first real model id for subsequent chat calls
                    if model_list:
                        model_id = model_list[0].get("id", model_id)
                        results["model_list"] = [m.get("id") for m in model_list if m.get("id")]

                    # --- context_window probe ---
                    # Many OpenAI-compatible providers embed context_length or
                    # max_tokens fields in the model object.  We walk all models
                    # and take the maximum value found.
                    ctx_values: list[int] = []
                    for m in model_list:
                        for field in ("context_length", "context_window", "max_tokens"):
                            raw = m.get(field)
                            if isinstance(raw, int) and raw > 0:
                                ctx_values.append(raw)
                                break
                    if ctx_values:
                        max_ctx = max(ctx_values)
                        results["context_window_value"] = str(max_ctx)
                        results["context_window_32k"] = max_ctx >= 32768
                    else:
                        results["context_window_value"] = "unknown"
                        results["context_window_32k"] = "unknown"
            except Exception as e:
                results["list_models"] = f"FAILED: {e}"
                results["context_window_value"] = "unknown"
                results["context_window_32k"] = "unknown"

            # 2. Function calling
            try:
                body: dict[str, Any] = {
                    "model": model_id,
                    "messages": [{"role": "user", "content": "Hello"}],
                    "tools": [{"type": "function", "function": {"name": "test", "parameters": {"type": "object", "properties": {}}}}],
                    "max_tokens": 10,
                }
                r = await c.post(f"{base_url}/v1/chat/completions", headers=headers, json=body)
                results["function_calling"] = r.status_code == 200
            except Exception as e:
                results["function_calling"] = f"FAILED: {e}"

            # 3. Streaming
            try:
                stream_body = {**body, "stream": True}
                r = await c.post(f"{base_url}/v1/chat/completions", headers=headers, json=stream_body)
                results["streaming"] = r.status_code == 200 and "text/event-stream" in r.headers.get("content-type", "")
            except Exception as e:
                results["streaming"] = f"FAILED: {e}"

            # 4. Parallel tool calls — send two tools and see if response contains
            #    multiple tool_call entries in one assistant message.
            try:
                parallel_body: dict[str, Any] = {
                    "model": model_id,
                    "messages": [
                        {"role": "user", "content": "Call both tools simultaneously."}
                    ],
                    "tools": [
                        {"type": "function", "function": {
                            "name": "tool_alpha",
                            "description": "First tool",
                            "parameters": {"type": "object", "properties": {}},
                        }},
                        {"type": "function", "function": {
                            "name": "tool_beta",
                            "description": "Second tool",
                            "parameters": {"type": "object", "properties": {}},
                        }},
                    ],
                    "tool_choice": "auto",
                    "max_tokens": 64,
                }
                r = await c.post(f"{base_url}/v1/chat/completions", headers=headers, json=parallel_body)
                if r.status_code == 200:
                    data = r.json()
                    choices = data.get("choices", [])
                    tool_calls = []
                    if choices:
                        msg = choices[0].get("message", {})
                        tool_calls = msg.get("tool_calls") or []
                    # Parallel if the model returned 2+ tool calls in one turn
                    results["parallel_tool_calls"] = len(tool_calls) >= 2
                else:
                    results["parallel_tool_calls"] = False
            except Exception as e:
                results["parallel_tool_calls"] = f"FAILED: {e}"

        return results

    # ------------------------------------------------------------------ Tenant Keys

    async def create_tenant_key(
        self, session: AsyncSession, *, tenant_id: str,
        provider_id: str, name: str, rate_limit_rpm: int,
        request_id: str,
    ) -> LLMTenantKey:
        """Create a virtual API key for a tenant → maps to provider."""
        key = LLMTenantKey(
            id=f"llmk_{ulid.new()!s}",
            tenant_id=tenant_id,
            provider_id=provider_id,
            name=name,
            virtual_key=f"sk-foundation-{ulid.new()!s}",
            rate_limit_rpm=rate_limit_rpm,
            enabled=True,
        )
        session.add(key)
        await session.flush()
        return key

    # ------------------------------------------------------------------ Usage

    async def record_usage(
        self, session: AsyncSession, *, tenant_id: str,
        provider_id: str, model: str, prompt_tokens: int,
        completion_tokens: int, total_tokens: int,
        request_id: str, cost_usd: float = 0.0, latency_ms: float = 0.0,
        prompt_cache_hit_tokens: int = 0, prompt_cache_miss_tokens: int = 0,
    ) -> LLMUsageRecord:
        record = LLMUsageRecord(
            id=f"llmu_{ulid.new()!s}",
            tenant_id=tenant_id,
            provider_id=provider_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            prompt_cache_hit_tokens=prompt_cache_hit_tokens,
            prompt_cache_miss_tokens=prompt_cache_miss_tokens,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            request_id=request_id,
        )
        session.add(record)
        return record

    async def get_tenant_usage(
        self, session: AsyncSession, *, tenant_id: str, days: int = 30,
    ) -> dict[str, Any]:
        """Aggregate token usage for a tenant over N days."""
        from sqlalchemy import func as sa_func
        cutoff = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        from datetime import timedelta
        cutoff = cutoff - timedelta(days=days)

        stmt = (
            select(
                LLMUsageRecord.model,
                sa_func.sum(LLMUsageRecord.total_tokens).label("tokens"),
                sa_func.sum(LLMUsageRecord.cost_usd).label("cost"),
            )
            .where(
                LLMUsageRecord.tenant_id == tenant_id,
                LLMUsageRecord.recorded_at >= cutoff,
            )
            .group_by(LLMUsageRecord.model)
        )
        rows = (await session.execute(stmt)).all()
        return {
            "period_days": days,
            "by_model": [{"model": r.model, "tokens": int(r.tokens or 0), "cost_usd": float(r.cost or 0)} for r in rows],
            "total_tokens": sum(int(r.tokens or 0) for r in rows),
            "total_cost_usd": sum(float(r.cost or 0) for r in rows),
        }

    # -------------------------------------------------------- Default Model Resolution

    async def resolve_default(
        self, session: AsyncSession, *,
        tenant_id: str, user_id: str | None, purpose: str,
    ) -> dict | None:
        """Resolve effective default model for a given purpose.

        Fallback chain:
        1. user_model_preference (if user_id provided)
        2. tenant_default_model
        3. system fallback (first enabled provider's first model for the purpose)

        Returns: {"model_id": str, "provider_id": str, "source": "user"|"tenant"|"system"} or None
        """
        # --- 1. User preference ---
        if user_id:
            user_pref = await session.scalar(
                select(LLMUserModelPreference).where(
                    LLMUserModelPreference.tenant_id == tenant_id,
                    LLMUserModelPreference.user_id == user_id,
                    LLMUserModelPreference.purpose == purpose,
                ).limit(1)
            )
            if user_pref:
                if await self._validate_provider_model(session, tenant_id, user_pref.provider_id, user_pref.model_id):
                    return {"model_id": user_pref.model_id, "provider_id": user_pref.provider_id, "source": "user"}
                log.info("resolve_default.user_pref_stale",
                         tenant_id=tenant_id, user_id=user_id, purpose=purpose,
                         note="provider/model no longer valid; falling through")

        # --- 2. Tenant default ---
        tenant_default = await session.scalar(
            select(LLMTenantDefaultModel).where(
                LLMTenantDefaultModel.tenant_id == tenant_id,
                LLMTenantDefaultModel.purpose == purpose,
            ).limit(1)
        )
        if tenant_default:
            if await self._validate_provider_model(session, tenant_id, tenant_default.provider_id, tenant_default.model_id):
                return {"model_id": tenant_default.model_id, "provider_id": tenant_default.provider_id, "source": "tenant"}
            log.info("resolve_default.tenant_default_stale",
                     tenant_id=tenant_id, purpose=purpose,
                     note="provider/model no longer valid; falling through to system")

        # --- 3. System fallback: first enabled provider that has a model for this purpose ---
        providers = list((await session.scalars(
            select(LLMProvider).where(
                LLMProvider.tenant_id == tenant_id,
                LLMProvider.enabled.is_(True),
            ).order_by(LLMProvider.created_at)
        )).all())

        for provider in providers:
            model_type_map = (provider.capabilities or {}).get("model_type_map", {})
            candidate_models = model_type_map.get(purpose) or []
            # Also try "text_<purpose>" key for backward compat (e.g. "text_embedding")
            if not candidate_models:
                candidate_models = model_type_map.get(f"text_{purpose}") or []
            # Filter to models actually in the provider's models list
            provider_models = provider.models or []
            valid = [m for m in candidate_models if m in provider_models]
            if valid:
                return {"model_id": valid[0], "provider_id": provider.id, "source": "system"}
            # For purpose "llm" we never fall back to an arbitrary provider model
            # (it could be an embedding/rerank/etc model). Only pick from the
            # provider's declared "llm" model list; if it has none, skip this provider.
            if purpose == "llm":
                llm_models = model_type_map.get("llm") or []
                llm_valid = [m for m in llm_models if not provider_models or m in provider_models]
                if llm_valid:
                    return {"model_id": llm_valid[0], "provider_id": provider.id, "source": "system"}

        return None

    @staticmethod
    def _provider_known_models(provider: LLMProvider) -> set[str]:
        """Collect every model_id a provider declares.

        Union of the top-level ``models`` list and every per-type list inside
        ``capabilities.model_type_map`` (e.g. {"llm": [...], "text_embedding": [...]}).
        """
        known: set[str] = set(provider.models or [])
        model_type_map = (provider.capabilities or {}).get("model_type_map", {}) or {}
        for models in model_type_map.values():
            if isinstance(models, list):
                known.update(models)
        return known

    async def _validate_provider_model(
        self, session: AsyncSession, tenant_id: str, provider_id: str, model_id: str,
    ) -> bool:
        """Return True if provider is enabled and model_id is one of its declared models.

        A model is valid only if it appears in the provider's known model set
        (top-level ``models`` ∪ ``capabilities.model_type_map`` lists). If the
        provider declares no models at all, no model_id is valid.
        """
        provider = await session.scalar(
            select(LLMProvider).where(
                LLMProvider.id == provider_id,
                LLMProvider.tenant_id == tenant_id,
            ).limit(1)
        )
        if provider is None or not provider.enabled:
            return False
        return model_id in self._provider_known_models(provider)

    async def _validate_write_target(
        self, session: AsyncSession, *,
        tenant_id: str, provider_id: str, model_id: str,
    ) -> None:
        """Validate a default/preference write target.

        The provider must belong to this tenant, be enabled, and the model_id
        must be one of the provider's declared models. Raises VALIDATION_FAILED
        otherwise (API layer maps this to 422).
        """
        from foundation_llm_gateway.errors import VALIDATION_FAILED, FoundationError
        if not await self._validate_provider_model(session, tenant_id, provider_id, model_id):
            raise FoundationError(
                VALIDATION_FAILED,
                detail=(
                    f"provider_id={provider_id!r} / model_id={model_id!r} is not a "
                    "valid enabled provider+model for this tenant."
                ),
            )

    async def upsert_tenant_default(
        self, session: AsyncSession, *,
        tenant_id: str, purpose: str, model_id: str,
        provider_id: str, created_by: str | None = None,
    ) -> LLMTenantDefaultModel:
        """Upsert one tenant default (concurrency-safe via ON CONFLICT)."""
        await self._validate_write_target(
            session, tenant_id=tenant_id, provider_id=provider_id, model_id=model_id,
        )
        set_on_update: dict[str, Any] = {
            "model_id": model_id,
            "provider_id": provider_id,
            "updated_at": sa_func.now(),
        }
        if created_by is not None:
            set_on_update["created_by"] = created_by
        stmt = (
            pg_insert(LLMTenantDefaultModel)
            .values(
                id=f"ttdm_{ulid.new()!s}",
                tenant_id=tenant_id,
                purpose=purpose,
                model_id=model_id,
                provider_id=provider_id,
                created_by=created_by,
            )
            .on_conflict_do_update(
                constraint="uq_tenant_default_purpose",
                set_=set_on_update,
            )
            .returning(LLMTenantDefaultModel)
        )
        row = (
            await session.scalars(stmt, execution_options={"populate_existing": True})
        ).one()
        await session.flush()
        return row

    async def list_tenant_defaults(
        self, session: AsyncSession, *, tenant_id: str,
    ) -> list[LLMTenantDefaultModel]:
        """List all tenant defaults."""
        rows = list((await session.scalars(
            select(LLMTenantDefaultModel).where(
                LLMTenantDefaultModel.tenant_id == tenant_id,
            ).order_by(LLMTenantDefaultModel.purpose)
        )).all())
        return rows

    async def upsert_user_preference(
        self, session: AsyncSession, *,
        tenant_id: str, user_id: str, purpose: str,
        model_id: str, provider_id: str,
    ) -> LLMUserModelPreference:
        """Upsert one user preference (concurrency-safe via ON CONFLICT)."""
        await self._validate_write_target(
            session, tenant_id=tenant_id, provider_id=provider_id, model_id=model_id,
        )
        stmt = (
            pg_insert(LLMUserModelPreference)
            .values(
                id=f"ump_{ulid.new()!s}",
                tenant_id=tenant_id,
                user_id=user_id,
                purpose=purpose,
                model_id=model_id,
                provider_id=provider_id,
            )
            .on_conflict_do_update(
                constraint="uq_user_pref_purpose",
                set_={
                    "model_id": model_id,
                    "provider_id": provider_id,
                    "updated_at": sa_func.now(),
                },
            )
            .returning(LLMUserModelPreference)
        )
        row = (
            await session.scalars(stmt, execution_options={"populate_existing": True})
        ).one()
        await session.flush()
        return row

    async def list_user_preferences(
        self, session: AsyncSession, *,
        tenant_id: str, user_id: str,
    ) -> list[LLMUserModelPreference]:
        """List all preferences for a user."""
        rows = list((await session.scalars(
            select(LLMUserModelPreference).where(
                LLMUserModelPreference.tenant_id == tenant_id,
                LLMUserModelPreference.user_id == user_id,
            ).order_by(LLMUserModelPreference.purpose)
        )).all())
        return rows

    async def delete_user_preference(
        self, session: AsyncSession, *,
        tenant_id: str, user_id: str, purpose: str,
    ) -> bool:
        """Delete a user preference, returning True if deleted."""
        existing = await session.scalar(
            select(LLMUserModelPreference).where(
                LLMUserModelPreference.tenant_id == tenant_id,
                LLMUserModelPreference.user_id == user_id,
                LLMUserModelPreference.purpose == purpose,
            ).limit(1)
        )
        if existing is None:
            return False
        await session.delete(existing)
        await session.flush()
        return True

    def _emit(self, session, tenant_id, event_type, payload, request_id):
        session.add(Outbox(tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("provider", ""), payload=payload, request_id=request_id))


# Pricing per 1M tokens (approximate)
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-sonnet-4-20250514": (3.00, 15.00),
    "claude-opus-4-20250514": (15.00, 75.00),
    "gpt-4o": (2.50, 10.00),
    "deepseek-v3": (0.27, 1.10),
    "qwen3-32b": (0.0, 0.0),
}
