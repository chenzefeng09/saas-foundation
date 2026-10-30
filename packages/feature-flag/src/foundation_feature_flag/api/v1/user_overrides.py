"""User-level feature flag overrides.

Endpoints:
  GET    /user-overrides              — list caller's overrides
  PUT    /user-overrides/{flag_key}   — set/update an override
  DELETE /user-overrides/{flag_key}   — remove an override (revert to tenant default)

Any authenticated user can manage their own overrides (no admin check).
Identity comes from middleware context (X-User-Id / X-Tenant-Id headers).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import delete, select

from foundation_feature_flag.domain.base import foundation_context
from foundation_feature_flag.domain.db import session_scope
from foundation_feature_flag.domain.models import Flag, UserFlagOverride
from foundation_feature_flag.errors import (
    TENANT_CONTEXT_MISSING,
    USER_CONTEXT_MISSING,
    FoundationError,
)
from foundation_feature_flag.observability import get_logger
from foundation_feature_flag.services.unleash_gateway import UnleashGateway

log = get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class UserOverrideView(BaseModel):
    flag_key: str
    enabled: bool
    updated_at: datetime | None = None


class SetUserOverrideRequest(BaseModel):
    enabled: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _identity() -> tuple[str, str]:
    """Return (tenant_id, user_id) or raise 401."""
    ctx = foundation_context.get()
    if ctx is None or not ctx.tenant_id:
        raise FoundationError(TENANT_CONTEXT_MISSING)
    if not ctx.user_id:
        raise FoundationError(USER_CONTEXT_MISSING)
    return ctx.tenant_id, ctx.user_id


async def _is_user_overridable(flag_key: str, gateway: UnleashGateway) -> bool:
    """Check whether a flag allows user-level override (DB first, then presets)."""
    try:
        async with session_scope() as session:
            db_flag = await session.get(Flag, flag_key)
            if db_flag is not None:
                return db_flag.user_overridable
    except Exception as exc:
        log.warning("user_overrides.db_check_failed", flag_key=flag_key, error=str(exc))

    preset = gateway._presets.get(flag_key)
    if preset is not None:
        return preset.user_overridable
    return False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/user-overrides", response_model=list[UserOverrideView], tags=["user-overrides"])
async def list_user_overrides(request: Request) -> list[UserOverrideView]:
    """List the calling user's personal flag overrides."""
    tenant_id, user_id = _identity()

    try:
        async with session_scope() as session:
            stmt = (
                select(UserFlagOverride)
                .where(
                    UserFlagOverride.tenant_id == tenant_id,
                    UserFlagOverride.user_id == user_id,
                )
                .order_by(UserFlagOverride.flag_key)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                UserOverrideView(
                    flag_key=r.flag_key,
                    enabled=r.enabled,
                    updated_at=r.updated_at,
                )
                for r in rows
            ]
    except Exception as exc:
        log.warning("user_overrides.list_failed", error=str(exc))
        return []


@router.put("/user-overrides/{flag_key}", response_model=UserOverrideView, tags=["user-overrides"])
async def set_user_override(
    flag_key: str, body: SetUserOverrideRequest, request: Request,
) -> UserOverrideView:
    """Set or update a personal flag override."""
    tenant_id, user_id = _identity()
    gateway: UnleashGateway = request.app.state.unleash_gateway

    if not await _is_user_overridable(flag_key, gateway):
        raise HTTPException(status_code=422, detail=f"flag '{flag_key}' does not allow user-level override")

    async with session_scope() as session:
        existing = await session.get(UserFlagOverride, (tenant_id, user_id, flag_key))
        if existing is None:
            existing = UserFlagOverride(
                tenant_id=tenant_id,
                user_id=user_id,
                flag_key=flag_key,
                enabled=body.enabled,
            )
            session.add(existing)
        else:
            existing.enabled = body.enabled

        log.info(
            "user_overrides.set",
            flag_key=flag_key,
            enabled=body.enabled,
            user_id=user_id,
            tenant_id=tenant_id,
        )
        return UserOverrideView(
            flag_key=flag_key,
            enabled=body.enabled,
            updated_at=existing.updated_at,
        )


@router.delete("/user-overrides/{flag_key}", status_code=204, tags=["user-overrides"])
async def delete_user_override(flag_key: str, request: Request) -> Response:
    """Remove a personal flag override (revert to tenant default)."""
    tenant_id, user_id = _identity()

    async with session_scope() as session:
        stmt = (
            delete(UserFlagOverride)
            .where(
                UserFlagOverride.tenant_id == tenant_id,
                UserFlagOverride.user_id == user_id,
                UserFlagOverride.flag_key == flag_key,
            )
        )
        await session.execute(stmt)

    log.info("user_overrides.deleted", flag_key=flag_key, user_id=user_id, tenant_id=tenant_id)
    return Response(status_code=204)
