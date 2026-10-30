"""LLM Gateway API endpoints — probe, providers, pricing, tenant-keys, chat.

P1 enterprise additions:
  - POST /chat/completions  — OpenAI-compatible, virtual-key auth, SSE streaming, quota, audit
  - POST /chat              — legacy alias (non-streaming simplified, kept for knowledge-ingest compat)
  - POST /tenant-keys       — create virtual key
  - GET  /tenant-keys       — list tenant virtual keys (internal scope)
  - POST /providers         — now encrypts api_key via crypto service before storage
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, Header, Path, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_llm_gateway.api.dependencies import (
    current_context, current_request_id, db_session, llm_gateway_service,
)
from foundation_llm_gateway.config import get_settings
from foundation_llm_gateway.domain.base import FoundationContext
from foundation_llm_gateway.errors import (
    PERMISSION_DENIED,
    PROVIDER_NOT_FOUND,
    PROVIDER_UPSTREAM_ERROR,
    QUOTA_EXCEEDED, VALIDATION_FAILED, VIRTUAL_KEY_MISMATCH, VIRTUAL_KEY_REQUIRED, FoundationError,
)
from foundation_llm_gateway.observability import get_logger
from foundation_llm_gateway.services.cache_usage import normalize_usage
from foundation_llm_gateway.services.llm_gateway_service import (
    LLMGatewayService, MODEL_PRICING, ProviderKind,
    _check_billing_quota, _decrypt_api_key, _emit_audit_event,
    _estimate_tokens, _record_billing_usage,
)

log = get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class ProbeRequest(BaseModel):
    url: str
    api_key: str
    provider_type: str = "openai_compatible"


@router.post("/probe", tags=["llm-gateway"])
async def probe_endpoint(
    body: ProbeRequest,
    ctx: FoundationContext = Depends(current_context),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    try:
        kind = ProviderKind(body.provider_type)
    except ValueError:
        kind = ProviderKind.OPENAI_COMPATIBLE
    result = await svc.probe_endpoint(body.url, body.api_key, kind)
    return {"url": body.url, "provider_type": body.provider_type, "results": result}


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

class RegisterProviderRequest(BaseModel):
    name: str
    api_base: str
    api_key: str          # plaintext — will be encrypted before storage
    provider_type: str
    models: list[str] = []
    model_type_map: dict[str, list[str]] = Field(default_factory=dict)  # {"llm": ["gpt-4o"], "text_embedding": ["text-embedding-3-small"]}
    model_settings: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # Free-form capability overrides merged into the provider's capabilities
    # JSONB. Used to configure multi-engine cache normalization + affinity:
    #   cache_format            — override the kind-derived cache shape
    #                             ("deepseek" | "openai_nested" | "llamacpp")
    #   affinity_mode           — "none" (default) | "external_lb" | ... ; when
    #                             not "none" the gateway forwards X-Session-Id
    #   cache_metric_unreliable — bool; surfaced for caller-side warnings
    capabilities_extra: dict[str, Any] = Field(default_factory=dict)


@router.get("/providers", tags=["llm-gateway"])
async def list_providers(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_llm_gateway.domain.models import LLMProvider
    rows = list((await session.scalars(
        select(LLMProvider).where(
            LLMProvider.tenant_id == ctx.tenant_id,
        )
    )).all())
    return {"items": [{
        "id": r.id, "name": r.name, "kind": r.kind,
        "base_url": r.base_url,
        "models": r.models, "default_model": r.default_model,
        "capabilities": r.capabilities,
        "enabled": r.enabled, "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]}


@router.post("/providers", status_code=201, tags=["llm-gateway"])
async def register_provider(
    body: RegisterProviderRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    settings = get_settings()
    try:
        kind = ProviderKind(body.provider_type)
    except ValueError:
        kind = ProviderKind.OPENAI_COMPATIBLE
    capabilities = {"model_type_map": body.model_type_map, "model_settings": body.model_settings}
    # Merge operator-supplied capability overrides (cache_format, affinity_mode,
    # cache_metric_unreliable, ...). Explicit keys take precedence over defaults.
    capabilities.update(body.capabilities_extra)
    provider = await svc.register_provider(
        session, tenant_id=ctx.tenant_id,
        name=body.name, kind=kind,
        base_url=body.api_base,
        api_key_plaintext=body.api_key,   # encrypted inside register_provider
        models=body.models,
        default_model=body.models[0] if body.models else "",
        capabilities=capabilities,
        request_id=request_id,
        crypto_url=settings.crypto_url,
        crypto_timeout=settings.external_timeout_seconds,
    )
    return {"id": provider.id, "name": provider.name, "kind": provider.kind, "models": provider.models}


class UpdateProviderRequest(BaseModel):
    enabled: bool | None = None
    name: str | None = None
    models: list[str] | None = None
    default_model: str | None = None
    model_type_map: dict[str, list[str]] | None = None
    model_settings: dict[str, dict[str, Any]] | None = None
    capabilities_extra: dict[str, Any] | None = None


@router.patch("/providers/{pid}", tags=["llm-gateway"])
async def update_provider(
    pid: str,
    body: UpdateProviderRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    capabilities = None
    if (
        body.model_type_map is not None
        or body.model_settings is not None
        or body.capabilities_extra is not None
    ):
        capabilities = {}
        if body.model_type_map is not None:
            capabilities["model_type_map"] = body.model_type_map
        if body.model_settings is not None:
            capabilities["model_settings"] = body.model_settings
        # Operator overrides (cache_format / affinity_mode / cache_metric_unreliable).
        # This partial dict is a merge-patch: the service merges these top-level
        # keys into the provider's existing capabilities. A null value here
        # (capabilities_extra: {"key": null}) flows through and deletes that key.
        if body.capabilities_extra is not None:
            capabilities.update(body.capabilities_extra)
    provider = await svc.update_provider(
        session, provider_id=pid, tenant_id=ctx.tenant_id,
        enabled=body.enabled, name=body.name,
        models=body.models, default_model=body.default_model,
        capabilities=capabilities,
        request_id=request_id,
    )
    return {"id": provider.id, "name": provider.name, "kind": provider.kind,
            "models": provider.models, "enabled": provider.enabled}


@router.delete("/providers/{pid}", tags=["llm-gateway"])
async def delete_provider(
    pid: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    await svc.delete_provider(
        session, provider_id=pid, tenant_id=ctx.tenant_id,
        request_id=request_id,
    )
    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

@router.get("/pricing", tags=["llm-gateway"])
async def get_model_pricing(
    ctx: FoundationContext = Depends(current_context),
) -> dict[str, Any]:
    return {
        "pricing": [
            {"model": model, "input_per_1m_usd": inp, "output_per_1m_usd": out}
            for model, (inp, out) in MODEL_PRICING.items()
        ]
    }


# ---------------------------------------------------------------------------
# Tenant Keys
# ---------------------------------------------------------------------------

class CreateTenantKeyRequest(BaseModel):
    provider_id: str
    name: str
    rate_limit_rpm: int = 60


class MintEphemeralKeyRequest(BaseModel):
    """Mint a short-lived, run-scoped virtual key.

    The scheduler calls this once per run instead of handing the sandbox the
    long-lived tenant key. ``ttl_seconds`` is derived from the sandbox timeout
    (+ grace) so the key expires at/after the run; the gateway clamps it to a
    sane window. ``provider_id`` is optional — when omitted the gateway binds
    the key to the tenant's oldest enabled provider.
    """
    # Bounded by the llm_tenant_key.run_id column (String(64)): a longer value
    # used to reach the INSERT and fail there as a 500.
    run_id: str = Field(min_length=1, max_length=64)
    ttl_seconds: int
    provider_id: str | None = None
    rate_limit_rpm: int = 60


class RevokeRunKeysRequest(BaseModel):
    run_id: str


@router.post("/tenant-keys", status_code=201, tags=["llm-gateway"])
async def create_tenant_key(
    body: CreateTenantKeyRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    key = await svc.create_tenant_key(
        session, tenant_id=ctx.tenant_id,
        provider_id=body.provider_id,
        name=body.name,
        rate_limit_rpm=body.rate_limit_rpm,
        request_id=request_id,
    )
    return {
        "id": key.id,
        "virtual_key": key.virtual_key,
        "provider_id": key.provider_id,
        "name": key.name,
        "rate_limit_rpm": key.rate_limit_rpm,
        "enabled": key.enabled,
    }


@router.get("/tenant-keys", tags=["llm-gateway"])
async def list_tenant_keys(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """List the tenant's long-lived virtual keys (internal scope for scheduler lookup).

    Callers take the first key (the scheduler's fallback when it cannot mint a
    run key, the BFF canvas), so only keys that still work are listed, oldest
    first.  Run-scoped ephemeral keys never are: each belongs to one sandbox,
    and most of them have expired.
    """
    from sqlalchemy import func, or_, select
    from foundation_llm_gateway.domain.models import LLMTenantKey
    rows = list((await session.scalars(
        select(LLMTenantKey).where(
            LLMTenantKey.tenant_id == ctx.tenant_id,
            LLMTenantKey.enabled.is_(True),
            LLMTenantKey.ephemeral.is_(False),
            or_(LLMTenantKey.expires_at.is_(None), LLMTenantKey.expires_at > func.now()),
        ).order_by(LLMTenantKey.created_at, LLMTenantKey.id)
    )).all())
    return {
        "items": [
            {
                "id": r.id,
                "virtual_key": r.virtual_key,
                "provider_id": r.provider_id,
                "name": r.name,
                "rate_limit_rpm": r.rate_limit_rpm,
            }
            for r in rows
        ]
    }


@router.post("/tenant-keys/ephemeral", status_code=201, tags=["llm-gateway"])
async def mint_ephemeral_tenant_key(
    body: MintEphemeralKeyRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    """Mint a short-lived, run-scoped virtual key for a sandbox.

    Security: the returned key carries ``expires_at = now + ttl_seconds`` and
    is rejected by ``/chat/completions`` once expired, so a key exfiltrated
    from a sandbox can only bill the tenant for ~one run's lifetime rather than
    indefinitely. Backwards compatible — long-lived keys (NULL expiry) are
    unaffected.
    """
    from sqlalchemy import select
    from foundation_llm_gateway.domain.models import LLMProvider
    usable = select(LLMProvider).where(
        LLMProvider.tenant_id == ctx.tenant_id,
        LLMProvider.enabled.is_(True),
    )
    if body.provider_id:
        # An explicit provider must be one of the tenant's enabled providers;
        # otherwise the minted key would be bound to a provider it cannot use.
        provider = await session.scalar(usable.where(LLMProvider.id == body.provider_id).limit(1))
        if provider is None:
            raise FoundationError(PROVIDER_NOT_FOUND,
                detail=f"Provider {body.provider_id!r} not found or disabled")
    else:
        # Bind to the tenant's oldest enabled provider, ordered so the choice
        # is stable when a tenant has several (resolve_provider routes by
        # model first; the bound provider is its fallback). Fail closed (404)
        # if the tenant has no usable provider rather than minting a dud key.
        provider = await session.scalar(
            usable.order_by(LLMProvider.created_at, LLMProvider.id).limit(1)
        )
        if provider is None:
            raise FoundationError(PROVIDER_NOT_FOUND,
                detail=f"No enabled provider to bind ephemeral key for tenant={ctx.tenant_id!r}")
    provider_id = provider.id

    key = await svc.mint_ephemeral_key(
        session, tenant_id=ctx.tenant_id,
        provider_id=provider_id,
        run_id=body.run_id,
        ttl_seconds=body.ttl_seconds,
        rate_limit_rpm=body.rate_limit_rpm,
        request_id=request_id,
    )
    return {
        "id": key.id,
        "virtual_key": key.virtual_key,
        "provider_id": key.provider_id,
        "name": key.name,
        "rate_limit_rpm": key.rate_limit_rpm,
        "enabled": key.enabled,
        "run_id": key.run_id,
        "ephemeral": key.ephemeral,
        "expires_at": key.expires_at.isoformat() if key.expires_at else None,
    }


@router.post("/tenant-keys/revoke-run", tags=["llm-gateway"])
async def revoke_run_tenant_keys(
    body: RevokeRunKeysRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    """Best-effort revoke of a run's ephemeral keys (defense-in-depth).

    TTL expiry is the authoritative safety net; this lets the scheduler kill a
    run's key proactively at run completion instead of waiting for the TTL.
    """
    disabled = await svc.disable_ephemeral_keys_for_run(
        session, tenant_id=ctx.tenant_id, run_id=body.run_id,
    )
    return {"run_id": body.run_id, "disabled": disabled}


# ---------------------------------------------------------------------------
# P1 Chat — OpenAI-compatible /chat/completions
# ---------------------------------------------------------------------------

class _ContentBlock(BaseModel):
    type: str
    text: str | None = None


class _ToolCall(BaseModel):
    id: str
    type: str = "function"
    function: dict[str, Any]


class ChatCompletionMessage(BaseModel):
    role: str
    content: str | list[_ContentBlock] | None = None
    tool_calls: list[_ToolCall] | None = None
    tool_call_id: str | None = None


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatCompletionMessage]
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None
    temperature: float | None = 0.7
    max_tokens: int | None = None
    top_p: float | None = None
    stop: str | list[str] | None = None
    stream: bool = False
    metadata: dict[str, Any] | None = Field(default=None, description="run_id, user_id passthrough")


def _compute_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    pricing = MODEL_PRICING.get(model)
    if pricing is None:
        return 0.0
    inp_per_1m, out_per_1m = pricing
    return (prompt_tokens * inp_per_1m + completion_tokens * out_per_1m) / 1_000_000


def _serialize_messages(messages: list[ChatCompletionMessage]) -> list[dict[str, Any]]:
    """Convert pydantic message objects to OpenAI-wire dicts."""
    result = []
    for m in messages:
        d: dict[str, Any] = {"role": m.role}
        if isinstance(m.content, list):
            d["content"] = [b.model_dump(exclude_none=True) for b in m.content]
        elif m.content is not None:
            d["content"] = m.content
        else:
            d["content"] = None
        if m.tool_calls:
            d["tool_calls"] = [tc.model_dump() for tc in m.tool_calls]
        if m.tool_call_id:
            d["tool_call_id"] = m.tool_call_id
        result.append(d)
    return result


async def _get_virtual_key_and_tenant(
    request: Request,
    ctx: FoundationContext,
    virtual_key_header: str | None,
) -> str:
    """
    Security: resolve effective tenant_id for the request.

    Current trust model (P1):
      - We receive X-Tenant-Id from TenantContextMiddleware (blindly trusted from header).
      - If X-LLM-Virtual-Key is present: we will cross-check the key's tenant_id
        against ctx.tenant_id inside resolve_provider. Mismatch → 403.
      - If Authorization Bearer is present and looks like a JWT: a real JWT validator
        should be wired here. This codebase does NOT yet have JWT verification in the
        llm-gateway middleware (only Keycloak in the identity service). We log a
        clear note so future implementers know the gap.
      - Remaining assumption clearly documented: X-Tenant-Id header is trusted at
        the network edge (API gateway / service mesh mutual-TLS enforces origin).
        Add JWT validation here when the gateway is exposed publicly.

    Returns the tenant_id to use.
    """
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.removeprefix("Bearer ")
        # TODO(P2-auth): validate JWT issued by Keycloak; extract tenant_id claim.
        # For now we accept the token as an opaque value and rely on the network edge.
        # If a virtual_key is also present the cross-check in resolve_provider covers misuse.
        log.debug("bearer_token_received_not_validated",
                  note="JWT validation not yet wired in llm-gateway; relying on network edge + virtual-key cross-check")
    return ctx.tenant_id


@router.post("/chat/completions", tags=["llm-gateway"])
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
    x_llm_virtual_key: str | None = Header(default=None, alias="X-LLM-Virtual-Key"),
) -> Any:
    """OpenAI-compatible chat completions with enterprise controls.

    Security pipeline:
      1. Resolve tenant_id from context (middleware).
      2. Require X-LLM-Virtual-Key and resolve provider via virtual key + model.
         Virtual key tenant_id cross-checked against request tenant_id (→ 403 on mismatch).
      3. Quota check via billing service (fail-close on EXCEEDED, fail-open on unavailability).
      4. Decrypt api_key envelope (migration-compatible: plaintext tolerated).
      5. Forward to provider (streaming or non-streaming).
      6. Extract usage; record LLMUsageRecord + billing deduction (async best-effort).
      7. Emit audit event (metadata only, no prompt plaintext).
    """
    settings = get_settings()
    tenant_id = await _get_virtual_key_and_tenant(request, ctx, x_llm_virtual_key)
    run_id = (body.metadata or {}).get("run_id")
    user_id = (body.metadata or {}).get("user_id") or ctx.user_id
    # Affinity routing key: prefer an explicit session_id, else reuse run_id.
    session_id = (body.metadata or {}).get("session_id") or run_id or None

    # -- Step 2: Provider resolution.  Enterprise mode is fail-closed: the
    # gateway never falls back to an arbitrary tenant provider when a virtual
    # key is missing, because that exposes provider credentials and bypasses
    # per-key rate controls.
    if not x_llm_virtual_key:
        raise FoundationError(VIRTUAL_KEY_REQUIRED)
    _, provider = await svc.resolve_provider(
        session, virtual_key=x_llm_virtual_key, model=body.model, tenant_id=tenant_id
    )

    # Estimate token budget for quota check (rough: 1 token ≈ 4 chars)
    messages_wire = _serialize_messages(body.messages)
    prompt_chars = sum(len(str(m.get("content") or "")) for m in messages_wire)
    tokens_estimate = max(1, prompt_chars // 4) + (body.max_tokens or 1024)

    # -- Step 3: Quota check (fail-close on quota exceeded, fail-open on service down)
    quota = await _check_billing_quota(tenant_id, tokens_estimate,
                                        settings.billing_url, settings.external_timeout_seconds)
    if not quota.get("allowed", True):
        raise FoundationError(QUOTA_EXCEEDED,
            detail=f"LLM token quota exceeded. Remaining: {quota.get('remaining', 0)}")

    # -- Step 4: Decrypt api_key
    api_key = await _decrypt_api_key(
        provider.api_key_encrypted, settings.crypto_url, settings.external_timeout_seconds, tenant_id
    )

    # -- Build upstream payload
    payload: dict[str, Any] = {
        "model": body.model,
        "messages": messages_wire,
        "stream": body.stream,
    }
    if body.temperature is not None:
        payload["temperature"] = body.temperature
    if body.max_tokens:
        payload["max_tokens"] = body.max_tokens
    if body.top_p is not None:
        payload["top_p"] = body.top_p
    if body.stop is not None:
        payload["stop"] = body.stop
    if body.tools:
        payload["tools"] = body.tools
    if body.tool_choice is not None:
        payload["tool_choice"] = body.tool_choice
    if body.stream:
        # Request usage in stream_options if provider supports it (OpenAI does)
        payload["stream_options"] = {"include_usage": True}

    # The registered ``base_url`` is the full OpenAI-compatible base, which by
    # convention already includes the version segment (e.g.
    # ``https://api.deepseek.com/v1``).  The OpenAI SDK that the in-sandbox
    # enforcer uses appends ``/chat/completions`` to exactly that base, so we
    # mirror that here.  We tolerate a base_url that already ends in
    # ``/chat/completions`` and one with or without a trailing slash so a
    # mis-registered provider still routes correctly.
    _base = provider.base_url.rstrip("/")
    if _base.endswith("/chat/completions"):
        upstream_url = _base
    else:
        upstream_url = f"{_base}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    # Session affinity (gateway side of affinity routing): when the provider is
    # fronted by an affinity-aware LB, forward the session key so the LB can
    # pin the request to the worker holding the warm KV cache. Default "none"
    # means no header is sent.
    affinity_mode = (provider.capabilities or {}).get("affinity_mode", "none")
    if affinity_mode != "none" and session_id:
        headers["X-Session-Id"] = session_id

    t_start = time.monotonic()

    if body.stream:
        return await _handle_streaming(
            body=body, payload=payload, upstream_url=upstream_url,
            headers=headers, messages_wire=messages_wire,
            session=session, svc=svc, tenant_id=tenant_id,
            provider_id=provider.id, request_id=request_id,
            user_id=user_id, run_id=run_id, t_start=t_start,
            settings=settings, provider=provider,
        )
    else:
        return await _handle_non_streaming(
            body=body, payload=payload, upstream_url=upstream_url,
            headers=headers, messages_wire=messages_wire,
            session=session, svc=svc, tenant_id=tenant_id,
            provider_id=provider.id, request_id=request_id,
            user_id=user_id, run_id=run_id, t_start=t_start,
            settings=settings, provider=provider,
        )


async def _handle_non_streaming(
    *, body: ChatCompletionRequest, payload: dict, upstream_url: str,
    headers: dict, messages_wire: list,
    session: AsyncSession, svc: LLMGatewayService, tenant_id: str,
    provider_id: str, request_id: str, user_id: str | None,
    run_id: str | None, t_start: float, settings: Any,
    provider: Any = None,
) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=120.0) as c:
            resp = await c.post(upstream_url, headers=headers, json=payload)
    except Exception as exc:
        raise FoundationError(PROVIDER_UPSTREAM_ERROR, detail=str(exc))

    if resp.status_code >= 400:
        raise FoundationError(PROVIDER_UPSTREAM_ERROR,
            detail=f"Provider returned HTTP {resp.status_code}: {resp.text[:200]}")

    latency_ms = (time.monotonic() - t_start) * 1000
    data = resp.json()

    # Extract usage — normalize prompt-cache stats across engines (fail-open).
    usage = data.get("usage") or {}
    if provider is not None:
        norm = normalize_usage(provider.kind, usage, data, provider.capabilities)
        prompt_tokens = norm.prompt_tokens
        completion_tokens = norm.completion_tokens
        prompt_cache_hit_tokens = norm.prompt_cache_hit_tokens
        prompt_cache_miss_tokens = norm.prompt_cache_miss_tokens
    else:
        # Legacy path (provider not supplied): top-level DeepSeek-style fields.
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        prompt_cache_hit_tokens = usage.get("prompt_cache_hit_tokens", 0) or 0
        prompt_cache_miss_tokens = usage.get("prompt_cache_miss_tokens", 0) or 0
    if prompt_tokens == 0 and completion_tokens == 0:
        resp_text = ""
        choices = data.get("choices") or []
        if choices:
            resp_text = str((choices[0].get("message") or {}).get("content") or "")
        prompt_tokens, completion_tokens = _estimate_tokens(messages_wire, resp_text)
    total_tokens = prompt_tokens + completion_tokens
    cost_usd = _compute_cost(body.model, prompt_tokens, completion_tokens)
    finish_reason = None
    choices = data.get("choices") or []
    if choices:
        finish_reason = choices[0].get("finish_reason")

    # Record usage (DB + billing async)
    await svc.record_usage(
        session, tenant_id=tenant_id, provider_id=provider_id,
        model=body.model, prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens, total_tokens=total_tokens,
        prompt_cache_hit_tokens=prompt_cache_hit_tokens,
        prompt_cache_miss_tokens=prompt_cache_miss_tokens,
        request_id=request_id, cost_usd=cost_usd, latency_ms=latency_ms,
    )
    asyncio.create_task(_record_billing_usage(
        tenant_id, total_tokens, settings.billing_url, settings.external_timeout_seconds
    ))
    asyncio.create_task(_emit_audit_event(
        tenant_id=tenant_id, user_id=user_id, run_id=run_id,
        model=body.model, prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        prompt_cache_hit_tokens=prompt_cache_hit_tokens,
        prompt_cache_miss_tokens=prompt_cache_miss_tokens,
        finish_reason=finish_reason, latency_ms=latency_ms,
        audit_url=settings.audit_url, timeout=settings.external_timeout_seconds,
    ))

    return data


async def _handle_streaming(
    *, body: ChatCompletionRequest, payload: dict, upstream_url: str,
    headers: dict, messages_wire: list,
    session: AsyncSession, svc: LLMGatewayService, tenant_id: str,
    provider_id: str, request_id: str, user_id: str | None,
    run_id: str | None, t_start: float, settings: Any,
    provider: Any = None,
) -> StreamingResponse:
    """Stream SSE from provider to client, collect usage, record after stream ends."""

    async def _generate():
        prompt_tokens = 0
        completion_tokens = 0
        prompt_cache_hit_tokens = 0
        prompt_cache_miss_tokens = 0
        finish_reason = None
        accumulated_text = ""
        error_occurred = False
        # Last non-empty usage payload + its carrying chunk, captured from the
        # trailing usage frame (choices empty, usage populated) for engine-aware
        # normalization after the stream completes.
        last_usage: dict | None = None
        last_usage_chunk: dict | None = None

        try:
            async with httpx.AsyncClient(timeout=120.0) as c:
                async with c.stream("POST", upstream_url, headers=headers, json=payload) as resp:
                    if resp.status_code >= 400:
                        body_text = await resp.aread()
                        err_frame = json.dumps({
                            "error": {
                                "code": "PROVIDER.UPSTREAM_ERROR",
                                "status": resp.status_code,
                                "message": body_text.decode(errors="replace")[:200],
                            }
                        })
                        yield f"data: {err_frame}\n\n"
                        error_occurred = True
                        return

                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str.strip() == "[DONE]":
                                yield "data: [DONE]\n\n"
                                break
                            try:
                                chunk = json.loads(data_str)
                                # Accumulate usage if provider sends it
                                usage = chunk.get("usage") or {}
                                if usage.get("prompt_tokens"):
                                    prompt_tokens = usage["prompt_tokens"]
                                if usage.get("completion_tokens"):
                                    completion_tokens = usage["completion_tokens"]
                                # DeepSeek-style prompt cache stats (fail-open)
                                if usage.get("prompt_cache_hit_tokens"):
                                    prompt_cache_hit_tokens = usage["prompt_cache_hit_tokens"]
                                if usage.get("prompt_cache_miss_tokens"):
                                    prompt_cache_miss_tokens = usage["prompt_cache_miss_tokens"]
                                # Capture the full trailing usage frame for
                                # engine-aware normalization after the stream.
                                if usage:
                                    last_usage = usage
                                    last_usage_chunk = chunk
                                # Accumulate content for estimator fallback
                                choices = chunk.get("choices") or []
                                if choices:
                                    delta = choices[0].get("delta") or {}
                                    accumulated_text += delta.get("content") or ""
                                    if choices[0].get("finish_reason"):
                                        finish_reason = choices[0]["finish_reason"]
                            except json.JSONDecodeError:
                                pass
                            yield f"data: {data_str}\n\n"
                        else:
                            # Pass through non-data lines (e.g. "event: ...")
                            yield f"{line}\n"

        except Exception as exc:
            error_occurred = True
            err_frame = json.dumps({"error": {"code": "PROVIDER.UPSTREAM_ERROR", "message": str(exc)}})
            yield f"data: {err_frame}\n\n"

        if error_occurred:
            return

        latency_ms = (time.monotonic() - t_start) * 1000

        # Engine-aware normalization of the trailing usage frame (fail-open).
        if provider is not None and last_usage is not None:
            norm = normalize_usage(
                provider.kind, last_usage, last_usage_chunk, provider.capabilities
            )
            prompt_tokens = norm.prompt_tokens or prompt_tokens
            completion_tokens = norm.completion_tokens or completion_tokens
            prompt_cache_hit_tokens = norm.prompt_cache_hit_tokens
            prompt_cache_miss_tokens = norm.prompt_cache_miss_tokens

        # Usage fallback: if provider didn't send usage in stream, estimate
        if prompt_tokens == 0 and completion_tokens == 0:
            prompt_tokens, completion_tokens = _estimate_tokens(messages_wire, accumulated_text)
            log.info("streaming.usage_estimated",
                     prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                     note="provider did not include usage in SSE; using char-based estimate")
        total_tokens = prompt_tokens + completion_tokens
        cost_usd = _compute_cost(body.model, prompt_tokens, completion_tokens)

        # Post-stream accounting (best-effort, must not raise).
        #
        # TWO traps handled here:
        #   1. The request-scoped ``session`` is already closed by the time
        #      this generator body runs, so we must open a *fresh* session.
        #   2. Starlette's ``BaseHTTPMiddleware`` cancels the response task as
        #      soon as the client closes the SSE connection (which the OpenAI
        #      SDK does right after the final content token).  Awaiting the DB
        #      write inline therefore races a ``CancelledError`` and the
        #      llm_usage_record INSERT gets rolled back.  We detach the write
        #      into its own task (like the billing/audit calls below) so it
        #      survives the request-task cancellation and actually commits.
        async def _persist_usage() -> None:
            try:
                from foundation_llm_gateway.domain.db import session_scope
                async with session_scope() as rec_session:
                    await svc.record_usage(
                        rec_session, tenant_id=tenant_id, provider_id=provider_id,
                        model=body.model, prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens, total_tokens=total_tokens,
                        prompt_cache_hit_tokens=prompt_cache_hit_tokens,
                        prompt_cache_miss_tokens=prompt_cache_miss_tokens,
                        request_id=request_id, cost_usd=cost_usd, latency_ms=latency_ms,
                    )
            except Exception as exc:  # noqa: BLE001
                log.warning("streaming.record_usage_failed", error=str(exc))

        asyncio.create_task(_persist_usage())

        asyncio.create_task(_record_billing_usage(
            tenant_id, total_tokens, settings.billing_url, settings.external_timeout_seconds
        ))
        asyncio.create_task(_emit_audit_event(
            tenant_id=tenant_id, user_id=user_id, run_id=run_id,
            model=body.model, prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            prompt_cache_hit_tokens=prompt_cache_hit_tokens,
            prompt_cache_miss_tokens=prompt_cache_miss_tokens,
            finish_reason=finish_reason, latency_ms=latency_ms,
            audit_url=settings.audit_url, timeout=settings.external_timeout_seconds,
        ))

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-Request-Id": request_id,
        },
    )


# ---------------------------------------------------------------------------
# Legacy /chat alias (kept for knowledge-ingest backward compat)
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    temperature: float = 0.7
    max_tokens: int | None = None
    stream: bool = False


@router.post("/chat", tags=["llm-gateway"])
async def chat(
    body: ChatRequest,
    request: Request,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
    x_llm_virtual_key: str | None = Header(default=None, alias="X-LLM-Virtual-Key"),
) -> dict[str, Any]:
    """Legacy simplified chat endpoint. Delegates to /chat/completions logic (non-streaming only)."""
    # Convert to ChatCompletionRequest and call the shared non-streaming path
    cc_req = ChatCompletionRequest(
        model=body.model,
        messages=[ChatCompletionMessage(role=m.role, content=m.content) for m in body.messages],
        temperature=body.temperature,
        max_tokens=body.max_tokens,
        stream=False,  # legacy endpoint always non-streaming
    )
    settings = get_settings()
    tenant_id = ctx.tenant_id

    if not x_llm_virtual_key:
        raise FoundationError(VIRTUAL_KEY_REQUIRED)
    _, provider = await svc.resolve_provider(
        session, virtual_key=x_llm_virtual_key, model=body.model, tenant_id=tenant_id
    )

    messages_wire = [{"role": m.role, "content": m.content} for m in body.messages]
    tokens_estimate = max(1, sum(len(m["content"]) for m in messages_wire) // 4) + (body.max_tokens or 1024)
    quota = await _check_billing_quota(tenant_id, tokens_estimate,
                                        settings.billing_url, settings.external_timeout_seconds)
    if not quota.get("allowed", True):
        raise FoundationError(QUOTA_EXCEEDED,
            detail=f"LLM token quota exceeded. Remaining: {quota.get('remaining', 0)}")

    api_key = await _decrypt_api_key(
        provider.api_key_encrypted, settings.crypto_url, settings.external_timeout_seconds, tenant_id
    )
    payload: dict[str, Any] = {
        "model": body.model,
        "messages": messages_wire,
        "temperature": body.temperature,
        "stream": False,
    }
    if body.max_tokens:
        payload["max_tokens"] = body.max_tokens

    # Legacy /chat has no metadata field, so there is no session key to forward;
    # affinity header injection is a no-op here but kept structurally consistent.
    upstream_headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    session_id = None
    affinity_mode = (provider.capabilities or {}).get("affinity_mode", "none")
    if affinity_mode != "none" and session_id:
        upstream_headers["X-Session-Id"] = session_id

    t_start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            resp = await c.post(f"{provider.base_url}/v1/chat/completions",
                                headers=upstream_headers,
                                json=payload)
            data = resp.json()
    except Exception as exc:
        return {"error": str(exc), "model": body.model, "choices": []}

    latency_ms = (time.monotonic() - t_start) * 1000
    # Engine-aware prompt-cache normalization (fail-open).
    usage = data.get("usage") or {}
    norm = normalize_usage(provider.kind, usage, data, provider.capabilities)
    prompt_tokens = norm.prompt_tokens
    completion_tokens = norm.completion_tokens
    prompt_cache_hit_tokens = norm.prompt_cache_hit_tokens
    prompt_cache_miss_tokens = norm.prompt_cache_miss_tokens
    if prompt_tokens == 0:
        prompt_tokens, completion_tokens = _estimate_tokens(messages_wire, "")
    total_tokens = prompt_tokens + completion_tokens
    cost_usd = _compute_cost(body.model, prompt_tokens, completion_tokens)
    finish_reason = None
    choices = data.get("choices") or []
    if choices:
        finish_reason = choices[0].get("finish_reason")

    await svc.record_usage(
        session, tenant_id=tenant_id, provider_id=provider.id,
        model=body.model, prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens, total_tokens=total_tokens,
        prompt_cache_hit_tokens=prompt_cache_hit_tokens,
        prompt_cache_miss_tokens=prompt_cache_miss_tokens,
        request_id=request_id, cost_usd=cost_usd, latency_ms=latency_ms,
    )
    asyncio.create_task(_record_billing_usage(
        tenant_id, total_tokens, settings.billing_url, settings.external_timeout_seconds
    ))
    asyncio.create_task(_emit_audit_event(
        tenant_id=tenant_id, user_id=ctx.user_id, run_id=None,
        model=body.model, prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        prompt_cache_hit_tokens=prompt_cache_hit_tokens,
        prompt_cache_miss_tokens=prompt_cache_miss_tokens,
        finish_reason=finish_reason, latency_ms=latency_ms,
        audit_url=settings.audit_url, timeout=settings.external_timeout_seconds,
    ))
    return data


# ---------------------------------------------------------------------------
# Default Model — Tenant Defaults & User Preferences
# ---------------------------------------------------------------------------

Purpose = Literal["llm", "embedding", "rerank", "tts", "stt"]


class UpsertTenantDefaultRequest(BaseModel):
    purpose: Purpose
    model_id: str
    provider_id: str


class UpsertUserPreferenceRequest(BaseModel):
    purpose: Purpose
    model_id: str
    provider_id: str


def _serialize_tenant_default(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "purpose": row.purpose,
        "model_id": row.model_id,
        "provider_id": row.provider_id,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _serialize_user_preference(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "user_id": row.user_id,
        "purpose": row.purpose,
        "model_id": row.model_id,
        "provider_id": row.provider_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


# --- Tenant Defaults (admin-scoped) ---


@router.get("/tenant-defaults", tags=["llm-gateway"])
async def list_tenant_defaults(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    rows = await svc.list_tenant_defaults(session, tenant_id=ctx.tenant_id)
    return {"items": [_serialize_tenant_default(r) for r in rows]}


@router.put("/tenant-defaults", tags=["llm-gateway"])
async def upsert_tenant_default(
    body: UpsertTenantDefaultRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    # Only privileged actors (admin operators or trusted services) may write
    # tenant-wide defaults. The actor is parsed from the X-Actor header by the
    # auth middleware; downstream BFF sends `X-Actor: ADMIN` for admin operations.
    if ctx.actor not in {"ADMIN", "SERVICE"}:
        raise FoundationError(
            PERMISSION_DENIED,
            detail="Writing tenant defaults requires an ADMIN or SERVICE actor.",
        )
    row = await svc.upsert_tenant_default(
        session,
        tenant_id=ctx.tenant_id,
        purpose=body.purpose,
        model_id=body.model_id,
        provider_id=body.provider_id,
        created_by=ctx.user_id,
    )
    return _serialize_tenant_default(row)


@router.get("/tenant-defaults/resolve", tags=["llm-gateway"])
async def resolve_tenant_default(
    purpose: Purpose,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    result = await svc.resolve_default(
        session, tenant_id=ctx.tenant_id, user_id=None, purpose=purpose,
    )
    if result is None:
        raise FoundationError(PROVIDER_NOT_FOUND,
            detail=f"No default model available for purpose={purpose!r}")
    return result


# --- User Preferences ---


@router.get("/user-preferences", tags=["llm-gateway"])
async def list_user_preferences(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    if not ctx.user_id:
        raise FoundationError(VALIDATION_FAILED, detail="user_id required for user preferences")
    rows = await svc.list_user_preferences(session, tenant_id=ctx.tenant_id, user_id=ctx.user_id)
    return {"items": [_serialize_user_preference(r) for r in rows]}


@router.put("/user-preferences", tags=["llm-gateway"])
async def upsert_user_preference(
    body: UpsertUserPreferenceRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    if not ctx.user_id:
        raise FoundationError(VALIDATION_FAILED, detail="user_id required for user preferences")
    row = await svc.upsert_user_preference(
        session,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        purpose=body.purpose,
        model_id=body.model_id,
        provider_id=body.provider_id,
    )
    return _serialize_user_preference(row)


@router.delete("/user-preferences/{purpose}", tags=["llm-gateway"])
async def delete_user_preference(
    purpose: Purpose,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    if not ctx.user_id:
        raise FoundationError(VALIDATION_FAILED, detail="user_id required for user preferences")
    deleted = await svc.delete_user_preference(
        session, tenant_id=ctx.tenant_id, user_id=ctx.user_id, purpose=purpose,
    )
    return {"deleted": deleted}


# --- A member's preferences (tenant-admin data-subject requests) ---
#
# The /user-preferences routes above answer only for the calling user.  An
# administrator handling a GDPR access or erasure request for another member of
# the tenant (Art. 15 / 17) reads and deletes that member's preferences here.

_MEMBER_USER_ID = r"^usr_[0-9A-Z]{26}$"


def _require_privileged_actor(ctx: FoundationContext) -> None:
    # The BFF sends ``X-Actor: ADMIN`` only after enforcing a tenant-admin
    # permission (the same contract as PUT /tenant-defaults).
    if ctx.actor not in {"ADMIN", "SERVICE"}:
        raise FoundationError(
            PERMISSION_DENIED,
            detail="Another user's preferences require an ADMIN or SERVICE actor.",
        )


@router.get("/users/{user_id}/preferences", tags=["llm-gateway"])
async def list_member_preferences(
    user_id: str = Path(pattern=_MEMBER_USER_ID),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    """Every model preference one member of the caller's tenant has set."""
    _require_privileged_actor(ctx)
    rows = await svc.list_user_preferences(session, tenant_id=ctx.tenant_id, user_id=user_id)
    return {"items": [_serialize_user_preference(r) for r in rows]}


@router.delete("/users/{user_id}/preferences", tags=["llm-gateway"])
async def delete_member_preferences(
    user_id: str = Path(pattern=_MEMBER_USER_ID),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    """Delete every model preference of one member of the caller's tenant.

    Idempotent: a member with none left answers ``{"deleted": 0}``.
    """
    _require_privileged_actor(ctx)
    deleted = await svc.delete_all_user_preferences(
        session, tenant_id=ctx.tenant_id, user_id=user_id,
    )
    return {"deleted": deleted}


@router.get("/user-preferences/resolve", tags=["llm-gateway"])
async def resolve_user_preference(
    purpose: Purpose,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    result = await svc.resolve_default(
        session, tenant_id=ctx.tenant_id, user_id=ctx.user_id, purpose=purpose,
    )
    if result is None:
        raise FoundationError(PROVIDER_NOT_FOUND,
            detail=f"No default model available for purpose={purpose!r}")
    return result
