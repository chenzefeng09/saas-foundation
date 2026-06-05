"""Evaluate API — POST /evaluate and POST /evaluate-batch.

SDK contract (do NOT break):
  is_enabled(flag)      → POST /api/feature-flag/v1/evaluate          body={flag: str}
  evaluate_batch(flags) → POST /api/feature-flag/v1/evaluate-batch    body={flags: list[str]}

Response schema: {enabled: bool, variant: str|null, reason: str}

Body compatibility: accepts both {flag: str} and {flag_key: str} + optional {context: dict}.
Tenant/user are taken from middleware context (X-Tenant-Id / X-User-Id headers).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, model_validator

from foundation_feature_flag.domain.base import foundation_context
from foundation_feature_flag.observability import get_logger
from foundation_feature_flag.services.unleash_gateway import UnleashGateway

log = get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class EvaluateRequest(BaseModel):
    """Accepts {flag: str} (SDK default) or {flag_key: str} (OpenAPI spec)."""

    flag: str | None = None
    flag_key: str | None = None
    context: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _resolve_flag(self) -> "EvaluateRequest":
        if self.flag_key and not self.flag:
            self.flag = self.flag_key
        if not self.flag:
            raise ValueError("Either 'flag' or 'flag_key' is required")
        return self


class EvaluateResponse(BaseModel):
    enabled: bool
    variant: str | None = None
    reason: str


class BatchEvaluateRequest(BaseModel):
    flags: list[str]
    context: dict[str, Any] | None = None


class BatchEvaluateResponse(BaseModel):
    results: dict[str, EvaluateResponse]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx_from_request() -> tuple[str | None, str | None]:
    """Extract tenant_id / user_id from ContextVar set by middleware."""
    ctx = foundation_context.get()
    if ctx is None:
        return None, None
    return ctx.tenant_id, ctx.user_id


def _get_gateway(request: Request) -> UnleashGateway:
    return request.app.state.unleash_gateway


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/evaluate", response_model=EvaluateResponse, tags=["evaluation"])
async def evaluate_flag(body: EvaluateRequest, request: Request) -> EvaluateResponse:
    """Evaluate a single feature flag for the requesting tenant/user."""
    tenant_id, user_id = _ctx_from_request()
    gateway = _get_gateway(request)

    result = gateway.evaluate(
        body.flag,  # type: ignore[arg-type]
        tenant_id=tenant_id,
        user_id=user_id,
        extra_props=body.context,
    )
    log.debug(
        "evaluate.result",
        flag=body.flag,
        tenant_id=tenant_id,
        enabled=result["enabled"],
        reason=result["reason"],
    )
    return EvaluateResponse(**result)


@router.post("/evaluate-batch", response_model=BatchEvaluateResponse, tags=["evaluation"])
async def evaluate_batch(body: BatchEvaluateRequest, request: Request) -> BatchEvaluateResponse:
    """Evaluate multiple feature flags in a single request."""
    tenant_id, user_id = _ctx_from_request()
    gateway = _get_gateway(request)

    results = gateway.evaluate_batch(
        body.flags,
        tenant_id=tenant_id,
        user_id=user_id,
        extra_props=body.context,
    )
    return BatchEvaluateResponse(
        results={k: EvaluateResponse(**v) for k, v in results.items()}
    )
