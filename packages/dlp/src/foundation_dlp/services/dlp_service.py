"""DLP + Classification service — tag resources, check access (dlp-classification-v1 §3-4)."""

from __future__ import annotations
import json
import re
from datetime import UTC, datetime
from typing import Any, Literal

import ulid
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_dlp.domain.models import Classification, DLPEvent, DLPRule, Outbox, SensitivityLevel
from foundation_dlp.errors import (
    CLASSIFICATION_NOT_FOUND, CLEARANCE_INSUFFICIENT, DLP_DENIED,
    SENSITIVITY_IMMUTABLE_DOWNGRADE, FoundationError,
)
from foundation_dlp.observability import (
    dlp_check_total, dlp_scan_hits_total, dlp_scan_total, get_logger,
)

log = get_logger(__name__)

# Max chars of scan-hit detail JSON persisted to dlp_event.detail (Text column).
_SCAN_DETAIL_MAX_CHARS = 4000

# Clearance hierarchy: user clearance must be >= resource sensitivity
_CLR_ORDER: dict[str, int] = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}


class DLPService:
    """Core DLP + Classification operations."""

    # ------------------------------------------------------------------ Classification

    async def tag_resource(
        self, session: AsyncSession, *, tenant_id: str, resource_type: str,
        resource_id: str, sensitivity: SensitivityLevel, tags: list[str] | None,
        reason: str | None, tagged_by: str, request_id: str,
    ) -> Classification:
        # Upsert
        existing = await session.scalar(
            select(Classification).where(
                Classification.tenant_id == tenant_id,
                Classification.resource_type == resource_type,
                Classification.resource_id == resource_id,
            ).limit(1)
        )
        if existing is not None:
            # Prevent downgrade of L5
            if existing.sensitivity == "L5" and _CLR_ORDER.get(sensitivity, 0) < 5:
                raise FoundationError(SENSITIVITY_IMMUTABLE_DOWNGRADE, extra={"resource_id": resource_id})
            # Only allow upgrade or same level
            if _CLR_ORDER.get(sensitivity, 0) < _CLR_ORDER.get(existing.sensitivity, 0):
                raise FoundationError(SENSITIVITY_IMMUTABLE_DOWNGRADE, extra={"resource_id": resource_id})
            existing.sensitivity = sensitivity
            existing.tags = tags
            existing.reason = reason
            existing.updated_at = datetime.now(UTC)
            cls = existing
        else:
            cls = Classification(
                id=f"cls_{ulid.new()!s}", tenant_id=tenant_id,
                resource_type=resource_type, resource_id=resource_id,
                sensitivity=sensitivity, tags=tags or [], reason=reason,
                tagged_by=tagged_by, downgradable=(sensitivity != "L5"),
            )
            session.add(cls)

        self._emit(session, tenant_id, "foundation.dlp.classification.tagged",
                   {"resource_id": resource_id, "sensitivity": sensitivity}, request_id)
        await session.flush()
        return cls

    async def get_sensitivity(
        self, session: AsyncSession, *, tenant_id: str,
        resource_type: str, resource_id: str,
    ) -> Classification:
        cls = await session.scalar(
            select(Classification).where(
                Classification.tenant_id == tenant_id,
                Classification.resource_type == resource_type,
                Classification.resource_id == resource_id,
            ).limit(1)
        )
        if cls is None:
            # Default: L2 (internal)
            return Classification(
                id="cls_default", tenant_id=tenant_id,
                resource_type=resource_type, resource_id=resource_id,
                sensitivity="L2", tags=[], downgradable=True,
            )
        return cls

    # ------------------------------------------------------------------ Access Check

    async def check_read(
        self, session: AsyncSession, *, tenant_id: str,
        user_id: str, user_clearance: SensitivityLevel,
        resource_type: str, resource_id: str, request_id: str,
    ) -> dict[str, Any]:
        """Check if user can READ a resource based on clearance vs sensitivity."""
        cls = await self.get_sensitivity(
            session, tenant_id=tenant_id, resource_type=resource_type, resource_id=resource_id)

        allowed = _CLR_ORDER.get(user_clearance, 1) >= _CLR_ORDER.get(cls.sensitivity, 1)
        reason = None if allowed else (
            f"User clearance {user_clearance} < resource sensitivity {cls.sensitivity}"
        )

        decision = "ALLOW" if allowed else "DENY"
        self._record_decision(session, tenant_id, "READ", user_id, resource_type, resource_id,
                              decision, None if allowed else "CLEARANCE_INSUFFICIENT", request_id)
        dlp_check_total.labels(check_type="READ", decision=decision).inc()
        return {"allowed": allowed, "sensitivity": cls.sensitivity, "reason": reason}

    async def check_download(
        self, session: AsyncSession, *, tenant_id: str,
        user_id: str, user_clearance: SensitivityLevel,
        resource_type: str, resource_id: str, destination: str, request_id: str,
    ) -> dict[str, Any]:
        """Check if user can DOWNLOAD a resource."""
        cls = await self.get_sensitivity(
            session, tenant_id=tenant_id, resource_type=resource_type, resource_id=resource_id)

        # L5 can never be downloaded (even by L5 users — requires 4-eyes in person)
        if cls.sensitivity == "L5":
            self._record_decision(session, tenant_id, "DOWNLOAD", user_id, resource_type, resource_id,
                                  "DENY", "L5_DOWNLOAD_FORBIDDEN", request_id)
            dlp_check_total.labels(check_type="DOWNLOAD", decision="DENY").inc()
            return {"allowed": False, "sensitivity": "L5", "reason": "L5 resources cannot be downloaded"}

        # L4 requires MFA (checked by caller via authz)
        if cls.sensitivity == "L4" and destination in ("external_share", "email", "usb"):
            self._record_decision(session, tenant_id, "DOWNLOAD", user_id, resource_type, resource_id,
                                  "DENY", "L4_EXTERNAL_FORBIDDEN", request_id)
            dlp_check_total.labels(check_type="DOWNLOAD", decision="DENY").inc()
            return {"allowed": False, "sensitivity": "L4",
                    "reason": f"L4 resources cannot be exported to {destination}"}

        allowed = _CLR_ORDER.get(user_clearance, 1) >= _CLR_ORDER.get(cls.sensitivity, 1)
        decision = "ALLOW" if allowed else "DENY"
        self._record_decision(session, tenant_id, "DOWNLOAD", user_id, resource_type, resource_id,
                              decision, None if allowed else "CLEARANCE_INSUFFICIENT", request_id)
        dlp_check_total.labels(check_type="DOWNLOAD", decision=decision).inc()
        return {"allowed": allowed, "sensitivity": cls.sensitivity,
                "reason": None if allowed else f"Clearance {user_clearance} < {cls.sensitivity}"}

    # ------------------------------------------------------------------ Sensitive Content Scan

    async def scan_content(
        self, session: AsyncSession, *, tenant_id: str, content: str,
        resource_type: str, resource_id: str, request_id: str,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Scan content against DLP rules. Returns highest sensitivity hit."""
        rules = list((await session.scalars(
            select(DLPRule).where(
                (DLPRule.tenant_id == tenant_id) | (DLPRule.tenant_id.is_(None)),
                DLPRule.enabled.is_(True),
            )
        )).all())

        hits: list[dict] = []
        max_sensitivity = "L1"
        for rule in rules:
            if rule.rule_type == "REGEX":
                try:
                    if re.search(rule.pattern, content, re.IGNORECASE):
                        hits.append({"rule_id": rule.id, "rule_name": rule.name, "sensitivity": rule.min_sensitivity})
                        if _CLR_ORDER.get(rule.min_sensitivity, 1) > _CLR_ORDER.get(max_sensitivity, 1):
                            max_sensitivity = rule.min_sensitivity
                except re.error:
                    pass
            elif rule.rule_type == "KEYWORD":
                try:
                    keywords = json.loads(rule.pattern)
                    for kw in keywords:
                        if kw.lower() in content.lower():
                            hits.append({"rule_id": rule.id, "rule_name": rule.name, "keyword": kw, "sensitivity": rule.min_sensitivity})
                            if _CLR_ORDER.get(rule.min_sensitivity, 1) > _CLR_ORDER.get(max_sensitivity, 1):
                                max_sensitivity = rule.min_sensitivity
                            break
                except (json.JSONDecodeError, TypeError):
                    pass

        action = (
            "ALLOW" if max_sensitivity == "L1"
            else "QUARANTINE" if _CLR_ORDER.get(max_sensitivity, 1) >= 4
            else "SCAN_REQUIRED"
        )

        dlp_scan_total.labels(action=action).inc()
        if hits:
            dlp_scan_hits_total.inc()
            self._emit(session, tenant_id, "foundation.dlp.scan.hit",
                       {"resource_id": resource_id, "hits": len(hits), "max_sensitivity": max_sensitivity}, request_id)
            # Persist a durable audit row (the outbox event is fire-and-forget).
            self._record_decision(
                session, tenant_id, "SCAN", user_id, resource_type, resource_id,
                action, None, request_id, detail=self._scan_detail(hits, max_sensitivity))

        return {"hits": hits, "max_sensitivity": max_sensitivity, "action": action}

    # ------------------------------------------------------------------ Governance reads

    async def list_events(
        self, session: AsyncSession, *, tenant_id: str,
        check_type: str | None = None, decision: str | None = None,
        before: datetime | None = None, limit: int = 50,
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
        self, session: AsyncSession, *, tenant_id: str,
        sensitivity: str | None = None, resource_type: str | None = None,
        before: datetime | None = None, limit: int = 50,
    ) -> list[Classification]:
        """Keyset page over classification ordered by updated_at desc (tagged resources)."""
        stmt = select(Classification).where(Classification.tenant_id == tenant_id)
        if sensitivity is not None:
            stmt = stmt.where(Classification.sensitivity == sensitivity)
        if resource_type is not None:
            stmt = stmt.where(Classification.resource_type == resource_type)
        if before is not None:
            stmt = stmt.where(Classification.updated_at < before)
        stmt = stmt.order_by(Classification.updated_at.desc(), Classification.id.desc()).limit(limit)
        return list((await session.scalars(stmt)).all())

    async def stats(
        self, session: AsyncSession, *, tenant_id: str, since: datetime,
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
            {"rule_id": h.get("rule_id"), "rule_name": h.get("rule_name"),
             "sensitivity": h.get("sensitivity")}
            for h in hits
        ]
        payload: dict[str, Any] = {"max_sensitivity": max_sensitivity, "rules": rules}
        encoded = json.dumps(payload, ensure_ascii=False)
        if len(encoded) <= _SCAN_DETAIL_MAX_CHARS:
            return encoded
        # Drop rules until it fits; record how many were truncated.
        while rules and len(json.dumps(payload, ensure_ascii=False)) > _SCAN_DETAIL_MAX_CHARS:
            rules.pop()
            payload = {"max_sensitivity": max_sensitivity, "rules": rules,
                       "truncated": len(hits) - len(rules)}
        return json.dumps(payload, ensure_ascii=False)

    def _record_decision(self, session: AsyncSession, tenant_id: str, check_type: str,
                         user_id: str | None, resource_type: str | None, resource_id: str | None,
                         decision: str, reason_code: str | None, request_id: str | None,
                         detail: str | None = None) -> None:
        session.add(DLPEvent(
            tenant_id=tenant_id, check_type=check_type, decision=decision,
            user_id=user_id, resource_type=resource_type, resource_id=resource_id,
            reason_code=reason_code, request_id=request_id, detail=detail,
        ))

    def _emit(self, session: AsyncSession, tenant_id: str, event_type: str,
              payload: dict[str, Any], request_id: str) -> None:
        session.add(Outbox(
            tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("resource_id", ""), payload=payload, request_id=request_id,
        ))
