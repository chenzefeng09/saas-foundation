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
from sqlalchemy import select

from foundation_feature_flag.domain.base import foundation_context
from foundation_feature_flag.domain.db import session_scope
from foundation_feature_flag.domain.models import Flag, UserFlagOverride
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


async def _load_user_overrides(
    tenant_id: str | None,
    user_id: str | None,
    flag_keys: list[str],
    gateway: UnleashGateway,
) -> dict[str, bool]:
    """Load effective user overrides for the given flags.

    Returns a dict of {flag_key: enabled} only for flags that:
    1. Have an active user override row in the DB
    2. Are marked user_overridable (in DB or presets)
    """
    if not tenant_id or not user_id or not flag_keys:
        return {}

    try:
        async with session_scope() as session:
            # Fetch user overrides
            stmt = (
                select(UserFlagOverride)
                .where(
                    UserFlagOverride.tenant_id == tenant_id,
                    UserFlagOverride.user_id == user_id,
                    UserFlagOverride.flag_key.in_(flag_keys),
                )
            )
            result = await session.execute(stmt)
            overrides = {r.flag_key: r.enabled for r in result.scalars().all()}

            if not overrides:
                return {}

            # Check which of those flags are user_overridable (DB)
            db_stmt = (
                select(Flag.key, Flag.user_overridable)
                .where(Flag.key.in_(list(overrides.keys())))
            )
            db_result = await session.execute(db_stmt)
            db_overridable = {row.key: row.user_overridable for row in db_result}

            effective: dict[str, bool] = {}
            for key, enabled in overrides.items():
                if db_overridable.get(key, False):
                    effective[key] = enabled
                elif gateway._presets.get(key) and gateway._presets[key].user_overridable:
                    effective[key] = enabled

            return effective
    except Exception as exc:
        log.warning("evaluate.user_overrides_failed", error=str(exc))
        return {}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/evaluate", response_model=EvaluateResponse, tags=["evaluation"])
async def evaluate_flag(body: EvaluateRequest, request: Request) -> EvaluateResponse:
    """Evaluate a single feature flag for the requesting tenant/user."""
    tenant_id, user_id = _ctx_from_request()
    gateway = _get_gateway(request)

    # Check user override first (after kill-switch, which is inside gateway.evaluate)
    flag_key = body.flag  # type: ignore[arg-type]
    user_overrides = await _load_user_overrides(tenant_id, user_id, [flag_key], gateway)
    if flag_key in user_overrides and not gateway.is_killed(flag_key):
        result = {"enabled": user_overrides[flag_key], "variant": None, "reason": "user_override"}
    else:
        result = gateway.evaluate(
            flag_key,
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

    # Load all user overrides in one query
    user_overrides = await _load_user_overrides(tenant_id, user_id, body.flags, gateway)

    results: dict[str, dict[str, Any]] = {}
    for flag_key in body.flags:
        if flag_key in user_overrides and not gateway.is_killed(flag_key):
            results[flag_key] = {"enabled": user_overrides[flag_key], "variant": None, "reason": "user_override"}
        else:
            results[flag_key] = gateway.evaluate(
                flag_key,
                tenant_id=tenant_id,
                user_id=user_id,
                extra_props=body.context,
            )

    return BatchEvaluateResponse(
        results={k: EvaluateResponse(**v) for k, v in results.items()}
    )
