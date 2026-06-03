"""LLM Gateway API endpoints — probe, providers, pricing, chat."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_llm_gateway.api.dependencies import (
    current_context, current_request_id, db_session, llm_gateway_service,
)
from foundation_llm_gateway.domain.base import FoundationContext
from foundation_llm_gateway.services.llm_gateway_service import LLMGatewayService, ProviderKind, MODEL_PRICING

router = APIRouter()


# ---------- Probe ----------

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


# ---------- Providers ----------

class RegisterProviderRequest(BaseModel):
    name: str
    api_base: str
    api_key: str
    provider_type: str
    models: list[str] = []


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
            LLMProvider.enabled.is_(True),
        )
    )).all())
    return {"items": [{"id": r.id, "name": r.name, "kind": r.kind, "models": r.models, "enabled": r.enabled} for r in rows]}


@router.post("/providers", status_code=201, tags=["llm-gateway"])
async def register_provider(
    body: RegisterProviderRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    try:
        kind = ProviderKind(body.provider_type)
    except ValueError:
        kind = ProviderKind.OPENAI_COMPATIBLE
    provider = await svc.register_provider(
        session, tenant_id=ctx.tenant_id,
        name=body.name, kind=kind,
        base_url=body.api_base,
        api_key_encrypted=body.api_key,
        models=body.models,
        default_model=body.models[0] if body.models else "",
        capabilities=None,
        request_id=request_id,
    )
    return {"id": provider.id, "name": provider.name, "kind": provider.kind, "models": provider.models}


# ---------- Pricing ----------

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


# ---------- Chat ----------

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
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: LLMGatewayService = Depends(llm_gateway_service),
) -> dict[str, Any]:
    # Find a registered provider for this tenant
    from sqlalchemy import select
    from foundation_llm_gateway.domain.models import LLMProvider
    provider = await session.scalar(
        select(LLMProvider).where(
            LLMProvider.tenant_id == ctx.tenant_id,
            LLMProvider.enabled.is_(True),
        ).limit(1)
    )
    if provider is None:
        return {"error": "No LLM provider registered", "model": body.model, "choices": []}

    # Forward to provider
    import httpx
    headers = {
        "Authorization": f"Bearer {provider.api_key_encrypted}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": body.model,
        "messages": [{"role": m.role, "content": m.content} for m in body.messages],
        "temperature": body.temperature,
        "stream": body.stream,
    }
    if body.max_tokens:
        payload["max_tokens"] = body.max_tokens

    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            resp = await c.post(f"{provider.base_url}/v1/chat/completions", headers=headers, json=payload)
            return resp.json()
    except Exception as exc:
        return {"error": str(exc), "model": body.model, "choices": []}
