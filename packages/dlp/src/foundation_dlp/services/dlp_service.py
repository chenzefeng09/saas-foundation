"""DLP + Classification service — tag resources, check access (dlp-classification-v1 §3-4)."""

from __future__ import annotations
import re
from datetime import UTC, datetime
from typing import Any, Literal

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_dlp.domain.models import Classification, DLPEvent, DLPRule, Outbox, SensitivityLevel
from foundation_dlp.errors import (
    CLASSIFICATION_NOT_FOUND, CLEARANCE_INSUFFICIENT, DLP_DENIED,
    SENSITIVITY_IMMUTABLE_DOWNGRADE, FoundationError,
)
from foundation_dlp.observability import get_logger

log = get_logger(__name__)

# Clearance hierarchy: user clearance must be >= resource sensitivity
_CLR_ORDER: dict[str, int] = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}

# Default clearance per role
DEFAULT_CLEARANCE: dict[str, str] = {
    "EMPLOYEE": "L2", "MANAGER": "L3", "EXECUTIVE": "L4", "SECURITY_ADMIN": "L5",
}


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

        self._record_decision(session, tenant_id, "READ", user_id, resource_type, resource_id,
                              "ALLOW" if allowed else "DENY",
                              None if allowed else "CLEARANCE_INSUFFICIENT", request_id)
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
            return {"allowed": False, "sensitivity": "L5", "reason": "L5 resources cannot be downloaded"}

        # L4 requires MFA (checked by caller via authz)
        if cls.sensitivity == "L4" and destination in ("external_share", "email", "usb"):
            self._record_decision(session, tenant_id, "DOWNLOAD", user_id, resource_type, resource_id,
                                  "DENY", "L4_EXTERNAL_FORBIDDEN", request_id)
            return {"allowed": False, "sensitivity": "L4",
                    "reason": f"L4 resources cannot be exported to {destination}"}

        allowed = _CLR_ORDER.get(user_clearance, 1) >= _CLR_ORDER.get(cls.sensitivity, 1)
        self._record_decision(session, tenant_id, "DOWNLOAD", user_id, resource_type, resource_id,
                              "ALLOW" if allowed else "DENY",
                              None if allowed else "CLEARANCE_INSUFFICIENT", request_id)
        return {"allowed": allowed, "sensitivity": cls.sensitivity,
                "reason": None if allowed else f"Clearance {user_clearance} < {cls.sensitivity}"}

    # ------------------------------------------------------------------ Sensitive Content Scan

    async def scan_content(
        self, session: AsyncSession, *, tenant_id: str, content: str,
        resource_type: str, resource_id: str, request_id: str,
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
                import json
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

        if hits:
            self._emit(session, tenant_id, "foundation.dlp.scan.hit",
                       {"resource_id": resource_id, "hits": len(hits), "max_sensitivity": max_sensitivity}, request_id)

        return {"hits": hits, "max_sensitivity": max_sensitivity, "action": "ALLOW" if max_sensitivity == "L1" else "QUARANTINE" if max_sensitivity >= "L4" else "SCAN_REQUIRED"}

    # ------------------------------------------------------------------ Helpers

    def _record_decision(self, session: AsyncSession, tenant_id: str, check_type: str,
                         user_id: str | None, resource_type: str | None, resource_id: str | None,
                         decision: str, reason_code: str | None, request_id: str | None) -> None:
        session.add(DLPEvent(
            tenant_id=tenant_id, check_type=check_type, decision=decision,
            user_id=user_id, resource_type=resource_type, resource_id=resource_id,
            reason_code=reason_code, request_id=request_id,
        ))

    def _emit(self, session: AsyncSession, tenant_id: str, event_type: str,
              payload: dict[str, Any], request_id: str) -> None:
        session.add(Outbox(
            tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("resource_id", ""), payload=payload, request_id=request_id,
        ))
