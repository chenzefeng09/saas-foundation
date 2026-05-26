"""Data Protection service — cross-border, destruction, consent (data-protection-v1 §3-5)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_data_protection.domain.models import (
    CrossBorderTransfer, DataDestructionRequest, ConsentRecord, Outbox,
)
from foundation_data_protection.errors import FoundationError
from foundation_data_protection.observability import get_logger

log = get_logger(__name__)

# Regulated data residency zones
RESTRICTED_DESTINATIONS = frozenset({
    "US", "GB", "AU", "SG", "JP",  # countries outside China (for cn-only residency)
})

# Sensitive data markers in payload (for scanning)
SENSITIVE_KEYWORDS = [
    "身份证", "id_card", "passport", "phone", "email", "address",
    "bank", "medical", "health", "biometric", "password", "secret",
]


class DataProtectionService:
    """Cross-border transfer check, data destruction, consent management."""

    # ------------------------------------------------------------------ Cross-Border

    async def check_cross_border(
        self, session: AsyncSession, *, tenant_id: str,
        data_country: str, destination_country: str,
        data_type: str, data_size_bytes: int,
        has_standard_contract: bool, has_safety_assessment: bool,
        request_id: str,
    ) -> dict[str, Any]:
        """Check if a cross-border data transfer is allowed.

        PIPL requirements:
          - Safety assessment by CAC (for CII / 1M+ users / "important data")
          - Standard contract with the overseas recipient
          - Personal information protection certification
        """
        risks: list[str] = []
        blocked = False

        # Data residency constraint
        if data_country == "CN" and destination_country in RESTRICTED_DESTINATIONS:
            if not has_standard_contract:
                risks.append("missing_standard_contract")
            if not has_safety_assessment:
                risks.append("missing_safety_assessment")
            if not has_standard_contract and not has_safety_assessment:
                blocked = True

        # Sensitive data check
        data_lower = data_type.lower()
        for kw in SENSITIVE_KEYWORDS:
            if kw in data_lower:
                risks.append(f"sensitive_data:{kw}")

        decision = "BLOCKED" if blocked else ("REVIEW" if risks else "ALLOW")

        # Record the check
        session.add(CrossBorderTransfer(
            id=f"xfr_{ulid.new()!s}",
            tenant_id=tenant_id,
            data_country=data_country,
            destination_country=destination_country,
            data_type=data_type,
            data_size_bytes=data_size_bytes,
            has_standard_contract=has_standard_contract,
            has_safety_assessment=has_safety_assessment,
            decision=decision,
            risks=risks,
        ))

        self._emit(session, tenant_id, "foundation.data_protection.cross_border.checked",
                   {"destination": destination_country, "decision": decision}, request_id)
        await session.flush()

        return {"allowed": not blocked, "decision": decision, "risks": risks,
                "required_actions": ["standard_contract"] if not has_standard_contract else []}

    # ------------------------------------------------------------------ Data Destruction

    async def request_destruction(
        self, session: AsyncSession, *, tenant_id: str,
        resource_type: str, resource_ids: list[str],
        destruction_method: str, reason: str,
        requested_by: str, witness_user_id: str | None,
        request_id: str,
    ) -> DataDestructionRequest:
        """Create a data destruction request (for 4-eyes approval)."""
        req = DataDestructionRequest(
            id=f"ddr_{ulid.new()!s}",
            tenant_id=tenant_id,
            resource_type=resource_type,
            resource_ids=resource_ids,
            destruction_method=destruction_method,
            reason=reason,
            requested_by=requested_by,
            witness_user_id=witness_user_id,
            status="PENDING_APPROVAL",
        )
        session.add(req)
        self._emit(session, tenant_id, "foundation.data_protection.destruction.requested",
                   {"resource_type": resource_type, "count": len(resource_ids)}, request_id)
        await session.flush()
        return req

    async def approve_destruction(
        self, session: AsyncSession, *, tenant_id: str,
        request_id: str, approved_by: str,
    ) -> DataDestructionRequest:
        """Approve a destruction request (4-eyes: approver != requester)."""
        req = await session.get(DataDestructionRequest, request_id)
        if req is None or req.tenant_id != tenant_id:
            raise FoundationError(
                FoundationError._ec("RESOURCE", "NOT_FOUND", 404, "Not found", "", ""),
                extra={"request_id": request_id})

        from foundation_data_protection.errors import DESTRUCTION_APPROVAL_INVALID
        if req.requested_by == approved_by:
            raise FoundationError(DESTRUCTION_APPROVAL_INVALID,
                                  detail="Approver must be different from requester (four-eyes)")

        req.status = "APPROVED"
        req.approved_by = approved_by
        req.approved_at = datetime.now(UTC)
        self._emit(session, tenant_id, "foundation.data_protection.destruction.approved",
                   {"request_id": request_id}, "")
        await session.flush()
        return req

    # ------------------------------------------------------------------ Consent

    async def record_consent(
        self, session: AsyncSession, *, tenant_id: str,
        user_id: str, consent_type: str, purpose: str,
        granted: bool, ip_address: str | None,
        request_id: str,
    ) -> ConsentRecord:
        """Record a user consent decision (GDPR/PIPL)."""
        record = ConsentRecord(
            id=f"cns_{ulid.new()!s}",
            tenant_id=tenant_id,
            user_id=user_id,
            consent_type=consent_type,
            purpose=purpose,
            granted=granted,
            ip_address=ip_address,
        )
        session.add(record)
        self._emit(session, tenant_id, "foundation.data_protection.consent.recorded",
                   {"user_id": user_id, "consent_type": consent_type, "granted": granted}, request_id)
        await session.flush()
        return record

    # ------------------------------------------------------------------ Helpers

    def _emit(self, session: AsyncSession, tenant_id: str, event_type: str,
              payload: dict[str, Any], request_id: str) -> None:
        session.add(Outbox(
            tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("resource_id", ""),
            payload=payload, request_id=request_id,
        ))
