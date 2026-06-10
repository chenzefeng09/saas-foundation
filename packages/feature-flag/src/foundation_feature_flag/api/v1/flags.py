"""Flags management API.

Endpoints:
  GET  /flags                     — list flags (tenant view)
  PUT  /flags/{flag}              — upsert flag (DB + Unleash admin sync)
  POST /flags/{flag}/kill-switch  — emergency kill-switch (reason required)

SDK contract (do NOT break):
  list_flags()              → GET  /api/feature-flag/v1/flags
  set_flag(flag, enabled, rollout_percentage, tenant_whitelist)
                            → PUT  /api/feature-flag/v1/flags/{flag}
                               body={enabled, rollout_percentage, tenant_whitelist}
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from foundation_feature_flag.domain.base import foundation_context
from foundation_feature_flag.domain.db import session_scope
from foundation_feature_flag.domain.models import Flag, KillSwitchLog
from foundation_feature_flag.errors import ACCESS_DENIED, FoundationError
from foundation_feature_flag.observability import get_logger
from foundation_feature_flag.services.feature_flag_service import FeatureFlagService
from foundation_feature_flag.services.unleash_gateway import UnleashGateway
from sqlalchemy import select

log = get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class FlagView(BaseModel):
    key: str
    name: str
    description: str | None = None
    enabled: bool
    default_value: bool
    fail_open: bool
    owner_team: str | None = None
    tags: dict[str, Any] | None = None
    kill_switch_active: bool = False
    unleash_synced_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class SetFlagRequest(BaseModel):
    """SDK set_flag body: {enabled, rollout_percentage, tenant_whitelist}."""

    enabled: bool
    rollout_percentage: int = 100
    tenant_whitelist: list[str] = []
    description: str | None = None
    fail_open: bool = False
    owner_team: str | None = None
    tags: dict[str, Any] | None = None


class KillSwitchRequest(BaseModel):
    reason: str

    model_config = {"json_schema_extra": {"example": {"reason": "P0 incident: flag causing 500s"}}}


class KillSwitchResponse(BaseModel):
    flag: str
    killed: bool
    reason: str
    actor: str
    timestamp: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_services(request: Request) -> tuple[FeatureFlagService, UnleashGateway]:
    return request.app.state.feature_flag_service, request.app.state.unleash_gateway


def _actor() -> str:
    ctx = foundation_context.get()
    if ctx is None:
        return "SYSTEM"
    return ctx.user_id or ctx.actor


def _tenant_id() -> str | None:
    ctx = foundation_context.get()
    return ctx.tenant_id if ctx else None


def _require_admin() -> None:
    ctx = foundation_context.get()
    if ctx is None or ctx.actor != "ADMIN":
        raise FoundationError(ACCESS_DENIED, detail="ADMIN actor required")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/flags", response_model=list[FlagView], tags=["flags"])
async def list_flags(request: Request) -> list[FlagView]:
    """List all feature flags with their current state.

    Baseline comes from the in-memory presets (the DB has no seed rows);
    DB rows override/extend the baseline per key. If the DB read fails,
    the preset baseline alone is returned.
    """
    gateway = request.app.state.unleash_gateway
    tenant_id = _tenant_id()

    # Preset baseline (in-memory)
    svc: FeatureFlagService = request.app.state.feature_flag_service
    raw = svc.list_flags(tenant_id=tenant_id)
    merged: dict[str, FlagView] = {
        item["name"]: FlagView(
            key=item["name"],
            name=item["name"],
            description=item.get("description"),
            enabled=item["enabled"],
            default_value=item["enabled"],
            fail_open=False,
            kill_switch_active=gateway.is_killed(item["name"]),
        )
        for item in raw
    }

    # Overlay DB rows — a DB row is authoritative for its key
    try:
        async with session_scope() as session:
            stmt = select(Flag).order_by(Flag.key)
            result = await session.execute(stmt)
            db_flags = result.scalars().all()

            for f in db_flags:
                merged[f.key] = FlagView(
                    key=f.key,
                    name=f.name,
                    description=f.description,
                    enabled=f.enabled,
                    default_value=f.default_value,
                    fail_open=f.fail_open,
                    owner_team=f.owner_team,
                    tags=f.tags,
                    kill_switch_active=gateway.is_killed(f.key),
                    unleash_synced_at=f.unleash_synced_at,
                    created_at=f.created_at,
                    updated_at=f.updated_at,
                )
    except Exception as exc:
        log.warning("flags.list.db_failed", error=str(exc))
        # DB unavailable — fall back to the preset baseline only

    return [merged[key] for key in sorted(merged)]


@router.put("/flags/{flag}", response_model=FlagView, tags=["flags"])
async def set_flag(flag: str, body: SetFlagRequest, request: Request) -> FlagView:
    """Upsert a feature flag.

    Writes to the local DB and syncs to Unleash admin API.
    SDK call: set_flag(flag=str, enabled=bool, rollout_percentage=int, tenant_whitelist=list)
    """
    _require_admin()
    gateway: UnleashGateway = request.app.state.unleash_gateway

    # Build Unleash strategy based on SDK parameters
    strategies: list[dict[str, Any]] = []
    if body.tenant_whitelist:
        strategies.append({
            "name": "userWithId",
            "constraints": [],
            "parameters": {"userIds": ",".join(body.tenant_whitelist)},
        })
    elif body.rollout_percentage < 100:
        strategies.append({
            "name": "gradualRolloutRandom",
            "constraints": [],
            "parameters": {"percentage": str(body.rollout_percentage)},
        })
    else:
        strategies.append({"name": "default", "constraints": [], "parameters": {}})

    # Sync to Unleash admin
    gateway.admin_upsert_flag(
        flag_key=flag,
        description=body.description,
        enabled=body.enabled,
        strategies=strategies,
    )

    now = datetime.now(UTC)

    # Upsert to DB
    try:
        async with session_scope() as session:
            existing = await session.get(Flag, flag)
            if existing is None:
                existing = Flag(
                    key=flag,
                    name=body.description or flag,
                    description=body.description,
                    enabled=body.enabled,
                    default_value=body.enabled,
                    fail_open=body.fail_open,
                    owner_team=body.owner_team,
                    tags=body.tags,
                    unleash_synced_at=now,
                )
                session.add(existing)
            else:
                existing.enabled = body.enabled
                existing.fail_open = body.fail_open
                if body.description is not None:
                    existing.description = body.description
                if body.owner_team is not None:
                    existing.owner_team = body.owner_team
                if body.tags is not None:
                    existing.tags = body.tags
                existing.unleash_synced_at = now

            return FlagView(
                key=flag,
                name=existing.name,
                description=existing.description,
                enabled=body.enabled,
                default_value=existing.default_value,
                fail_open=existing.fail_open,
                owner_team=existing.owner_team,
                tags=existing.tags,
                kill_switch_active=gateway.is_killed(flag),
                unleash_synced_at=now,
            )
    except Exception as exc:
        log.error("flags.set.db_failed", flag=flag, error=str(exc))
        raise HTTPException(
            status_code=503,
            detail=f"flag '{flag}' synced to Unleash but DB persistence failed",
        ) from exc


@router.post("/flags/{flag}/kill-switch", response_model=KillSwitchResponse, tags=["flags"])
async def kill_switch(flag: str, body: KillSwitchRequest, request: Request) -> KillSwitchResponse:
    """Emergency kill-switch — immediately disables a flag globally.

    1. Sets in-process kill override (instant effect, no Unleash refresh delay)
    2. Calls Unleash Admin API to disable the flag (persists across restarts)
    3. Writes audit record to kill_switch_log
    4. Returns confirmation

    reason is required (min 5 chars enforced by Pydantic).
    """
    _require_admin()
    if len(body.reason.strip()) < 5:
        raise HTTPException(status_code=422, detail="reason must be at least 5 characters")

    gateway: UnleashGateway = request.app.state.unleash_gateway
    actor = _actor()
    tenant_id = _tenant_id()
    now = datetime.now(UTC)

    # 1. In-process kill — immediate, before any Unleash round-trip
    gateway.kill(flag)

    # 2. Persist to Unleash admin API
    gateway.admin_set_kill_switch(flag, killed=True)

    # 3. Write audit log to DB
    try:
        async with session_scope() as session:
            entry = KillSwitchLog(
                flag_key=flag,
                tenant_id=tenant_id,
                reason=body.reason,
                actor=actor,
                action="KILL",
            )
            session.add(entry)
        log.warning("kill_switch.applied", flag=flag, actor=actor, reason=body.reason)
    except Exception as exc:
        log.warning("kill_switch.db_write_failed", flag=flag, error=str(exc))
        # Kill already applied in-process — don't fail the request

    return KillSwitchResponse(
        flag=flag,
        killed=True,
        reason=body.reason,
        actor=actor,
        timestamp=now.isoformat(),
    )
