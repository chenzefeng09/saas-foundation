"""Compliance service — ROPA, DPIA, DSAR, cross-border contract templates.

Regulatory coverage:
  - ROPA (GDPR Art.30 / PIPL): Record of Processing Activities
  - DPIA (GDPR Art.35 / PIPL): Data Protection Impact Assessment
  - DSAR (GDPR Art.15-22 / PIPL): Data Subject Access Request
  - Cross-border: Standard contractual clauses (PIPL) + safety assessment
  - Compliance reports: auto-generate for audits
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Literal

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_compliance.domain.models import (
    ROPARecord, DPIA, DSARRequest, ComplianceReport, Outbox,
)
from foundation_compliance.observability import get_logger

log = get_logger(__name__)

ComplianceMode = Literal[
    "equal_protection_3", "equal_protection_4", "finance_jrt0071",
    "pipl", "gdpr", "hipaa", "soc2", "iso27001",
]


class ComplianceService:
    """Regulatory compliance management."""

    # ------------------------------------------------------------------ ROPA

    async def record_processing(
        self, session: AsyncSession, *, tenant_id: str,
        service: str, data_category: str, purpose: str,
        legal_basis: str, data_subjects: list[str],
        recipients: list[str], retention_days: int,
        cross_border: bool, destination_countries: list[str] | None,
        request_id: str,
    ) -> ROPARecord:
        """Record a data processing activity (ROPA entry)."""
        record = ROPARecord(
            id=f"ropa_{ulid.new()!s}",
            tenant_id=tenant_id,
            service=service,
            data_category=data_category,
            purpose=purpose,
            legal_basis=legal_basis,
            data_subjects=data_subjects,
            recipients=recipients,
            retention_days=retention_days,
            cross_border=cross_border,
            destination_countries=destination_countries or [],
        )
        session.add(record)
        await session.flush()
        return record

    async def list_ropa(
        self, session: AsyncSession, *, tenant_id: str,
    ) -> list[ROPARecord]:
        stmt = select(ROPARecord).where(ROPARecord.tenant_id == tenant_id).order_by(ROPARecord.recorded_at.desc())
        return list((await session.scalars(stmt)).all())

    # ------------------------------------------------------------------ DPIA

    async def assess_dpia(
        self, session: AsyncSession, *, tenant_id: str,
        project_name: str, description: str,
        data_categories: list[str], risks: list[dict[str, str]],
        mitigations: list[dict[str, str]],
        assessed_by: str, request_id: str,
    ) -> DPIA:
        """Create a DPIA assessment record."""
        dpia = DPIA(
            id=f"dpia_{ulid.new()!s}",
            tenant_id=tenant_id,
            project_name=project_name,
            description=description,
            data_categories=data_categories,
            risks=risks,
            mitigations=mitigations,
            conclusion="ASSESSMENT_IN_PROGRESS",
            assessed_by=assessed_by,
        )
        session.add(dpia)
        self._emit(session, tenant_id, "foundation.compliance.dpia.created",
                   {"project": project_name}, request_id)
        await session.flush()
        return dpia

    async def complete_dpia(
        self, session: AsyncSession, *, tenant_id: str,
        dpia_id: str, conclusion: str, residual_risks: str,
        approved_by: str,
    ) -> DPIA:
        dpia = await session.get(DPIA, dpia_id)
        if dpia is None or dpia.tenant_id != tenant_id:
            raise ValueError(f"DPIA {dpia_id} not found")
        dpia.conclusion = conclusion
        dpia.residual_risks = residual_risks
        dpia.approved_by = approved_by
        dpia.completed_at = datetime.now(UTC)
        await session.flush()
        return dpia

    # ------------------------------------------------------------------ DSAR

    async def request_dsar(
        self, session: AsyncSession, *, tenant_id: str,
        user_id: str, request_type: str, details: str,
        request_id: str,
    ) -> DSARRequest:
        """File a Data Subject Access Request.

        request_type: ACCESS / RECTIFICATION / ERASURE / RESTRICTION /
                      PORTABILITY / OBJECTION / AUTOMATED_DECISION
        """
        dsar = DSARRequest(
            id=f"dsar_{ulid.new()!s}",
            tenant_id=tenant_id,
            user_id=user_id,
            request_type=request_type,
            details=details,
            status="RECEIVED",
            sla_deadline=datetime.now(UTC).replace(hour=0, minute=0) + __import__("datetime").timedelta(days=30),
        )
        session.add(dsar)
        self._emit(session, tenant_id, "foundation.compliance.dsar.requested",
                   {"user_id": user_id, "type": request_type}, request_id)
        await session.flush()
        return dsar

    async def update_dsar_status(
        self, session: AsyncSession, *, tenant_id: str,
        dsar_id: str, status: str, response: str | None,
    ) -> DSARRequest:
        dsar = await session.get(DSARRequest, dsar_id)
        if dsar is None or dsar.tenant_id != tenant_id:
            raise ValueError(f"DSAR {dsar_id} not found")
        dsar.status = status
        if response:
            dsar.response = response
        if status == "COMPLETED":
            dsar.completed_at = datetime.now(UTC)
        await session.flush()
        return dsar

    # ------------------------------------------------------------------ Reports

    async def generate_report(
        self, session: AsyncSession, *, tenant_id: str,
        report_type: str, compliance_modes: list[ComplianceMode],
        generated_by: str, request_id: str,
    ) -> ComplianceReport:
        """Generate a compliance report (e.g. SOC2 control mapping)."""
        report = ComplianceReport(
            id=f"cpr_{ulid.new()!s}",
            tenant_id=tenant_id,
            report_type=report_type,
            compliance_modes=compliance_modes,
            generated_by=generated_by,
            content_json={
                "generated_at": datetime.now(UTC).isoformat(),
                "compliance_modes": compliance_modes,
                "sections": self._get_report_sections(report_type, compliance_modes),
            },
        )
        session.add(report)
        await session.flush()
        return report

    def _get_report_sections(self, report_type: str, modes: Sequence[str]) -> list[dict]:
        sections = []
        if "soc2" in modes:
            sections.append({"name": "Security", "controls": ["CC1-CC9"], "status": "MAPPED"})
            sections.append({"name": "Availability", "controls": ["A1.1-A1.3"], "status": "MAPPED"})
            sections.append({"name": "Confidentiality", "controls": ["C1.1-C1.2"], "status": "MAPPED"})
            sections.append({"name": "Privacy", "controls": ["P1-P8"], "status": "MAPPED"})
        if "iso27001" in modes:
            sections.append({"name": "A.5 Information Security Policies", "controls": ["A.5.1.1", "A.5.1.2"], "status": "MAPPED"})
            sections.append({"name": "A.8 Asset Management", "controls": ["A.8.1.1-A.8.1.4"], "status": "MAPPED"})
            sections.append({"name": "A.9 Access Control", "controls": ["A.9.1.1-A.9.4.5"], "status": "MAPPED"})
            sections.append({"name": "A.12 Operations Security", "controls": ["A.12.1.1-A.12.7.1"], "status": "MAPPED"})
        if "equal_protection_3" in modes:
            sections.append({"name": "安全通信网络", "controls": ["8.1.2.1-8.1.2.3"], "status": "MAPPED"})
            sections.append({"name": "安全区域边界", "controls": ["8.1.3.1-8.1.3.6"], "status": "MAPPED"})
            sections.append({"name": "安全计算环境", "controls": ["8.1.4.1-8.1.4.10"], "status": "MAPPED"})
        if "pipl" in modes:
            pipl_sections: list[tuple[str, list[str]]] = [
                ("个人信息处理者基本情况", ["PIPL §51"]),
                ("个人信息处理活动概览", ["PIPL §17", "ROPA"]),
                ("告知与同意机制（含单独同意、敏感个人信息告知）", ["PIPL §14", "PIPL §29-30"]),  # noqa: RUF001
                ("个人信息主体权利响应", ["PIPL §44-50", "DSAR"]),
                ("个人信息保护影响评估（PIA）", ["PIPL §55-56", "DPIA"]),  # noqa: RUF001
                ("跨境传输与安全保障措施（PIPL §38）", ["PIPL §38-39"]),  # noqa: RUF001
                ("合规风险与整改", ["PIPL §64-66"]),
            ]
            for name, controls in pipl_sections:
                sections.append({"name": name, "controls": controls, "status": "MAPPED"})
        return sections

    def _emit(self, session, tenant_id, event_type, payload, request_id):
        session.add(Outbox(tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("user_id", ""), payload=payload, request_id=request_id))
