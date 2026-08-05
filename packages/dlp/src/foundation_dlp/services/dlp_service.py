"""DLP + Classification service — tag resources, check access (dlp-classification-v1 §3-4)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, cast

import ulid
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_dlp.domain.models import Classification, DLPEvent, DLPRule, Outbox, SensitivityLevel
from foundation_dlp.errors import (
    SENSITIVITY_IMMUTABLE_DOWNGRADE,
    VALIDATION_FAILED,
    FoundationError,
)
from foundation_dlp.observability import (
    dlp_check_total,
    dlp_scan_hits_total,
    dlp_scan_total,
    get_logger,
)

log = get_logger(__name__)

# Max chars of scan-hit detail JSON persisted to dlp_event.detail (Text column).
_SCAN_DETAIL_MAX_CHARS = 4000

# Clearance hierarchy: user clearance must be >= resource sensitivity
_CLR_ORDER: dict[str, int] = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}


def _validate_level(value: str, *, field: str) -> SensitivityLevel:
    """Validate every level at the service boundary; never coerce/fall back."""
    if value not in _CLR_ORDER:
        raise FoundationError(
            VALIDATION_FAILED,
            detail=f"{field} must be exactly one of L1, L2, L3, L4, L5.",
        )
    return cast(SensitivityLevel, value)


class DLPService:
    """Core DLP + Classification operations."""

    def __init__(self, *, default_sensitivity: SensitivityLevel = "L3") -> None:
        self._default_sensitivity = _validate_level(
            default_sensitivity, field="default_sensitivity"
        )

    # ------------------------------------------------------------------ Classification

    async def tag_resource(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        sensitivity: SensitivityLevel,
        tags: list[str] | None,
        reason: str | None,
        tagged_by: str,
        request_id: str,
    ) -> Classification:
        sensitivity = _validate_level(sensitivity, field="sensitivity")
        # Upsert
        existing = await session.scalar(
            select(Classification)
            .where(
                Classification.tenant_id == tenant_id,
                Classification.resource_type == resource_type,
                Classification.resource_id == resource_id,
            )
            .limit(1)
        )
        if existing is not None:
            existing_sensitivity = _validate_level(existing.sensitivity, field="stored sensitivity")
            # Prevent downgrade of L5
            if existing_sensitivity == "L5" and _CLR_ORDER[sensitivity] < 5:
                raise FoundationError(
                    SENSITIVITY_IMMUTABLE_DOWNGRADE, extra={"resource_id": resource_id}
                )
            # Only allow upgrade or same level
            if _CLR_ORDER[sensitivity] < _CLR_ORDER[existing_sensitivity]:
                raise FoundationError(
                    SENSITIVITY_IMMUTABLE_DOWNGRADE, extra={"resource_id": resource_id}
                )
            existing.sensitivity = sensitivity
            existing.tags = tags
            existing.reason = reason
            existing.downgradable = sensitivity != "L5"
            existing.updated_at = datetime.now(UTC)
            cls = existing
        else:
            cls = Classification(
                id=f"cls_{ulid.new()!s}",
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                sensitivity=sensitivity,
                tags=tags or [],
                reason=reason,
                tagged_by=tagged_by,
                downgradable=(sensitivity != "L5"),
            )
            session.add(cls)

        self._emit(
            session,
            tenant_id,
            "foundation.dlp.classification.tagged",
            {"resource_id": resource_id, "sensitivity": sensitivity},
            request_id,
        )
        await session.flush()
        return cls

    async def get_sensitivity(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
    ) -> Classification:
        cls = await session.scalar(
            select(Classification)
            .where(
                Classification.tenant_id == tenant_id,
                Classification.resource_type == resource_type,
                Classification.resource_id == resource_id,
            )
            .limit(1)
        )
        if cls is None:
            # No caller may choose this fallback; it is a centrally configured
            # policy and defaults to the ordinary-employee L3 baseline.
            return Classification(
                id="cls_default",
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                sensitivity=self._default_sensitivity,
                tags=[],
                downgradable=self._default_sensitivity != "L5",
            )
        _validate_level(cls.sensitivity, field="stored sensitivity")
        return cls

    # ------------------------------------------------------------------ Access Check

    async def check_read(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        user_clearance: SensitivityLevel,
        resource_type: str,
        resource_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Check if user can READ a resource based on clearance vs sensitivity."""
        user_clearance = _validate_level(user_clearance, field="user_clearance")
        cls = await self.get_sensitivity(
            session, tenant_id=tenant_id, resource_type=resource_type, resource_id=resource_id
        )

        allowed = _CLR_ORDER[user_clearance] >= _CLR_ORDER[cls.sensitivity]
        reason = (
            None
            if allowed
            else (f"User clearance {user_clearance} < resource sensitivity {cls.sensitivity}")
        )

        decision = "ALLOW" if allowed else "DENY"
        self._record_decision(
            session,
            tenant_id,
            "READ",
            user_id,
            resource_type,
            resource_id,
            decision,
            None if allowed else "CLEARANCE_INSUFFICIENT",
            request_id,
        )
        dlp_check_total.labels(check_type="READ", decision=decision).inc()
        return {"allowed": allowed, "sensitivity": cls.sensitivity, "reason": reason}

    async def check_download(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        user_clearance: SensitivityLevel,
        resource_type: str,
        resource_id: str,
        destination: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Check if user can DOWNLOAD a resource."""
        user_clearance = _validate_level(user_clearance, field="user_clearance")
        cls = await self.get_sensitivity(
            session, tenant_id=tenant_id, resource_type=resource_type, resource_id=resource_id
        )

        # L5 can never be downloaded (even by L5 users — requires 4-eyes in person)
        if cls.sensitivity == "L5":
            self._record_decision(
                session,
                tenant_id,
                "DOWNLOAD",
                user_id,
                resource_type,
                resource_id,
                "DENY",
                "L5_DOWNLOAD_FORBIDDEN",
                request_id,
            )
            dlp_check_total.labels(check_type="DOWNLOAD", decision="DENY").inc()
            return {
                "allowed": False,
                "sensitivity": "L5",
                "reason": "L5 resources cannot be downloaded",
            }

        # L4 requires MFA (checked by caller via authz)
        if cls.sensitivity == "L4" and destination in ("external_share", "email", "usb"):
            self._record_decision(
                session,
                tenant_id,
                "DOWNLOAD",
                user_id,
                resource_type,
                resource_id,
                "DENY",
                "L4_EXTERNAL_FORBIDDEN",
                request_id,
            )
            dlp_check_total.labels(check_type="DOWNLOAD", decision="DENY").inc()
            return {
                "allowed": False,
                "sensitivity": "L4",
                "reason": f"L4 resources cannot be exported to {destination}",
            }

        allowed = _CLR_ORDER[user_clearance] >= _CLR_ORDER[cls.sensitivity]
        decision = "ALLOW" if allowed else "DENY"
        self._record_decision(
            session,
            tenant_id,
            "DOWNLOAD",
            user_id,
            resource_type,
            resource_id,
            decision,
            None if allowed else "CLEARANCE_INSUFFICIENT",
            request_id,
        )
        dlp_check_total.labels(check_type="DOWNLOAD", decision=decision).inc()
        return {
            "allowed": allowed,
            "sensitivity": cls.sensitivity,
            "reason": None if allowed else f"Clearance {user_clearance} < {cls.sensitivity}",
        }

    # ------------------------------------------------------------------ Sensitive Content Scan

    async def scan_content(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        content: str,
        resource_type: str,
        resource_id: str | None,
        request_id: str,
        user_id: str | None = None,
        persist_classification: bool = True,
    ) -> dict[str, Any]:
        """Scan content and optionally auto-upgrade the concrete resource label.

        Core resource scans pass a real ``resource_type`` / ``resource_id`` and
        persist the highest matched level.  Shape-only SDK scans have no concrete
        resource identity and must set ``persist_classification=False`` so a
        placeholder can never become an authorization label.
        """
        if persist_classification and not resource_id:
            raise FoundationError(
                VALIDATION_FAILED,
                detail="resource_id is required when persisting scan classification.",
            )
        rules = list(
            (
                await session.scalars(
                    select(DLPRule).where(
                        (DLPRule.tenant_id == tenant_id) | (DLPRule.tenant_id.is_(None)),
                        DLPRule.enabled.is_(True),
                    )
                )
            ).all()
        )

        hits: list[dict] = []
        max_sensitivity = "L1"
        for rule in rules:
            rule_sensitivity = _validate_level(
                rule.min_sensitivity, field=f"rule {rule.id} min_sensitivity"
            )
            if rule.rule_type == "REGEX":
                try:
                    if re.search(rule.pattern, content, re.IGNORECASE):
                        hits.append(
                            {
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "sensitivity": rule_sensitivity,
                            }
                        )
                        if _CLR_ORDER[rule_sensitivity] > _CLR_ORDER[max_sensitivity]:
                            max_sensitivity = rule_sensitivity
                except re.error:
                    pass
            elif rule.rule_type == "KEYWORD":
                try:
                    keywords = json.loads(rule.pattern)
                    for kw in keywords:
                        if kw.lower() in content.lower():
                            hits.append(
                                {
                                    "rule_id": rule.id,
                                    "rule_name": rule.name,
                                    "keyword": kw,
                                    "sensitivity": rule_sensitivity,
                                }
                            )
                            if _CLR_ORDER[rule_sensitivity] > _CLR_ORDER[max_sensitivity]:
                                max_sensitivity = rule_sensitivity
                            break
                except (json.JSONDecodeError, TypeError):
                    pass

        action = (
            "ALLOW"
            if max_sensitivity == "L1"
            else "QUARANTINE"
            if _CLR_ORDER[max_sensitivity] >= 4
            else "SCAN_REQUIRED"
        )

        dlp_scan_total.labels(action=action).inc()
        if hits:
            dlp_scan_hits_total.inc()
            if persist_classification:
                # ``resource_id`` was validated above.  Keep the assertion close
                # to the policy mutation so future call-site changes cannot turn
                # a placeholder/None into a durable resource label.
                assert resource_id is not None
                await self._auto_upgrade_from_scan(
                    session,
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    sensitivity=cast(SensitivityLevel, max_sensitivity),
                    request_id=request_id,
                )
            self._emit(
                session,
                tenant_id,
                "foundation.dlp.scan.hit",
                {"resource_id": resource_id, "hits": len(hits), "max_sensitivity": max_sensitivity},
                request_id,
            )
            # Persist a durable audit row (the outbox event is fire-and-forget).
            self._record_decision(
                session,
                tenant_id,
                "SCAN",
                user_id,
                resource_type,
                resource_id,
                action,
                None,
                request_id,
                detail=self._scan_detail(hits, max_sensitivity),
            )
            await session.flush()

        return {"hits": hits, "max_sensitivity": max_sensitivity, "action": action}

    async def _auto_upgrade_from_scan(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        sensitivity: SensitivityLevel,
        request_id: str,
    ) -> Classification:
        """Create or raise a scan-derived label without ever lowering it.

        An absent row already has the configured fallback sensitivity at the
        policy layer, so a newly persisted label is floored at that fallback.
        Existing explicit L1/L2 labels remain valid and are only raised when the
        scan finds a strictly higher level.  Manual tags/reasons are preserved.
        """
        sensitivity = _validate_level(sensitivity, field="scan sensitivity")
        existing = await session.scalar(
            select(Classification)
            .where(
                Classification.tenant_id == tenant_id,
                Classification.resource_type == resource_type,
                Classification.resource_id == resource_id,
            )
            .limit(1)
            .with_for_update()
        )

        previous_sensitivity: SensitivityLevel | None = None
        changed = False
        if existing is None:
            target = (
                sensitivity
                if _CLR_ORDER[sensitivity] >= _CLR_ORDER[self._default_sensitivity]
                else self._default_sensitivity
            )
            cls = Classification(
                id=f"cls_{ulid.new()!s}",
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                sensitivity=target,
                tags=[],
                reason="Automatically classified by DLP scan",
                tagged_by="system:scanner",
                auto_upgraded=True,
                downgradable=(target != "L5"),
            )
            session.add(cls)
            changed = True
        else:
            cls = existing
            previous_sensitivity = _validate_level(
                existing.sensitivity, field="stored sensitivity"
            )
            if _CLR_ORDER[sensitivity] > _CLR_ORDER[previous_sensitivity]:
                cls.sensitivity = sensitivity
                cls.auto_upgraded = True
                cls.downgradable = sensitivity != "L5"
                cls.updated_at = datetime.now(UTC)
                changed = True

        if changed:
            self._emit(
                session,
                tenant_id,
                "foundation.dlp.classification.upgraded",
                {
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "from": previous_sensitivity,
                    "to": cls.sensitivity,
                    "source": "scanner",
                },
                request_id,
            )
        return cls

    # ------------------------------------------------------------------ Governance reads

    async def list_events(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        check_type: str | None = None,
        decision: str | None = None,
        before: datetime | None = None,
        limit: int = 50,
    ) -> list[DLPEvent]:
        """Keyset page over dlp_event ordered by occurred_at desc (decision + scan history)."""
        stmt = select(DLPEvent).where(DLPEvent.tenant_id == tenant_id)
        if check_type is not None:
            stmt = stmt.where(DLPEvent.check_type == check_type)
        if decision is not None:
            stmt = stmt.where(DLPEvent.decision == decision)
        if before is not None:
            stmt = stmt.where(DLPEvent.occurred_at < before)
        stmt = stmt.order_by(DLPEvent.occurred_at.desc(), DLPEvent.id.desc()).limit(limit)
        return list((await session.scalars(stmt)).all())

    async def list_classifications(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        sensitivity: str | None = None,
        resource_type: str | None = None,
        before: datetime | None = None,
        limit: int = 50,
    ) -> list[Classification]:
        """Keyset page over classification ordered by updated_at desc (tagged resources)."""
        stmt = select(Classification).where(Classification.tenant_id == tenant_id)
        if sensitivity is not None:
            stmt = stmt.where(Classification.sensitivity == sensitivity)
        if resource_type is not None:
            stmt = stmt.where(Classification.resource_type == resource_type)
        if before is not None:
            stmt = stmt.where(Classification.updated_at < before)
        stmt = stmt.order_by(Classification.updated_at.desc(), Classification.id.desc()).limit(
            limit
        )
        return list((await session.scalars(stmt)).all())

    async def stats(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        since: datetime,
    ) -> dict[str, Any]:
        """Aggregate counts by decision / check_type (dlp_event) + sensitivity (classification)."""
        by_decision: dict[str, int] = {}
        by_check_type: dict[str, int] = {}
        total_events = 0
        dec_rows = await session.execute(
            select(DLPEvent.decision, func.count())
            .where(DLPEvent.tenant_id == tenant_id, DLPEvent.occurred_at >= since)
            .group_by(DLPEvent.decision)
        )
        for decision, count in dec_rows:
            by_decision[decision] = count
            total_events += count
        ct_rows = await session.execute(
            select(DLPEvent.check_type, func.count())
            .where(DLPEvent.tenant_id == tenant_id, DLPEvent.occurred_at >= since)
            .group_by(DLPEvent.check_type)
        )
        for check_type, count in ct_rows:
            by_check_type[check_type] = count
        by_sensitivity: dict[str, int] = {}
        sens_rows = await session.execute(
            select(Classification.sensitivity, func.count())
            .where(Classification.tenant_id == tenant_id)
            .group_by(Classification.sensitivity)
        )
        for sensitivity, count in sens_rows:
            by_sensitivity[sensitivity] = count
        return {
            "by_decision": by_decision,
            "by_check_type": by_check_type,
            "by_sensitivity": by_sensitivity,
            "total_events": total_events,
        }

    # ------------------------------------------------------------------ Helpers

    @staticmethod
    def _scan_detail(hits: list[dict], max_sensitivity: str) -> str:
        """JSON-encode scan hits for dlp_event.detail (Text), truncating to stay bounded."""
        rules = [
            {
                "rule_id": h.get("rule_id"),
                "rule_name": h.get("rule_name"),
                "sensitivity": h.get("sensitivity"),
            }
            for h in hits
        ]
        payload: dict[str, Any] = {"max_sensitivity": max_sensitivity, "rules": rules}
        encoded = json.dumps(payload, ensure_ascii=False)
        if len(encoded) <= _SCAN_DETAIL_MAX_CHARS:
            return encoded
        # Drop rules until it fits; record how many were truncated.
        while rules and len(json.dumps(payload, ensure_ascii=False)) > _SCAN_DETAIL_MAX_CHARS:
            rules.pop()
            payload = {
                "max_sensitivity": max_sensitivity,
                "rules": rules,
                "truncated": len(hits) - len(rules),
            }
        return json.dumps(payload, ensure_ascii=False)

    def _record_decision(
        self,
        session: AsyncSession,
        tenant_id: str,
        check_type: str,
        user_id: str | None,
        resource_type: str | None,
        resource_id: str | None,
        decision: str,
        reason_code: str | None,
        request_id: str | None,
        detail: str | None = None,
    ) -> None:
        session.add(
            DLPEvent(
                tenant_id=tenant_id,
                check_type=check_type,
                decision=decision,
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                reason_code=reason_code,
                request_id=request_id,
                detail=detail,
            )
        )

    def _emit(
        self,
        session: AsyncSession,
        tenant_id: str,
        event_type: str,
        payload: dict[str, Any],
        request_id: str,
    ) -> None:
        session.add(
            Outbox(
                tenant_id=tenant_id,
                event_type=event_type,
                aggregate_id=payload.get("resource_id", ""),
                payload=payload,
                request_id=request_id,
            )
        )
