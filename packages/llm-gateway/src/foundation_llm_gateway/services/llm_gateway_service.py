"""LLM Gateway — LiteLLM proxy wrapper with tenant isolation.

Capabilities:
  - Provider registry: register external model endpoints (Claude API, Bedrock, vLLM, etc.)
  - Tenant virtual keys: per-tenant API keys that map to underlying provider keys
  - Capability probing: test endpoint for function calling, streaming, context window
  - Token usage tracking: per-tenant, per-model token counting for billing
  - Failover: primary → fallback provider routing
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_llm_gateway.domain.models import (
    LLMProvider, LLMTenantKey, LLMUsageRecord, Outbox,
)
from foundation_llm_gateway.observability import get_logger

log = get_logger(__name__)


class ProviderKind(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"
    VLLM = "vllm"
    OLLAMA = "ollama"
    BEDROCK = "bedrock"
    AZURE = "azure"


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
        api_key_encrypted: str, models: list[str],
        default_model: str, capabilities: dict[str, bool] | None,
        request_id: str,
    ) -> LLMProvider:
        """Register an external LLM provider endpoint."""
        provider = LLMProvider(
            id=f"llmp_{ulid.new()!s}",
            tenant_id=tenant_id,
            name=name,
            kind=kind.value,
            base_url=base_url,
            api_key_encrypted=api_key_encrypted,
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

    async def probe_endpoint(
        self, base_url: str, api_key: str, kind: ProviderKind,
    ) -> dict[str, Any]:
        """Test an endpoint for capabilities. Returns compatibility report."""
        import httpx
        results: dict[str, bool | str] = {}
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=15.0) as c:
            # 1. List models
            try:
                r = await c.get(f"{base_url}/v1/models", headers=headers)
                results["list_models"] = r.status_code == 200
                if r.status_code == 200:
                    model_list = r.json().get("data", [])
                    results["model_count"] = str(len(model_list))
            except Exception as e:
                results["list_models"] = f"FAILED: {e}"

            # 2. Function calling
            try:
                body = {
                    "model": "test",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "tools": [{"type": "function", "function": {"name": "test", "parameters": {}}}],
                    "max_tokens": 10,
                }
                r = await c.post(f"{base_url}/v1/chat/completions", headers=headers, json=body)
                results["function_calling"] = r.status_code == 200
            except Exception as e:
                results["function_calling"] = f"FAILED: {e}"

            # 3. Streaming
            try:
                body["stream"] = True
                r = await c.post(f"{base_url}/v1/chat/completions", headers=headers, json=body)
                results["streaming"] = r.status_code == 200 and "text/event-stream" in r.headers.get("content-type", "")
            except Exception as e:
                results["streaming"] = f"FAILED: {e}"

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
    ) -> LLMUsageRecord:
        record = LLMUsageRecord(
            id=f"llmu_{ulid.new()!s}",
            tenant_id=tenant_id,
            provider_id=provider_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
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
