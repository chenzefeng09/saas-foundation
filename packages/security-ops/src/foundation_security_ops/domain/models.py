"""Security-ops domain models.

Tables (schema = security_ops):
  - scan_run         CI 扫描记录（SAST/SCA/DAST/IMAGE_VULN/IAC/SECRET/LICENSE）
  - vulnerability    统一漏洞跟踪 + SLA 截止
  - incident         应急响应事件
  - sbom_record      SBOM 元数据 + attestation 位置
  - sbom_watch       Grype watch 注册
  - license_finding  License 扫描结果
  - drill            演练记录
  - security_ops_event_outbox  事件出站箱
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from foundation_security_ops.domain.base import Base


# ---------------------------------------------------------------------------
# scan_run
# ---------------------------------------------------------------------------

class ScanRun(Base):
    __tablename__ = "scan_run"
    __table_args__ = (
        Index("idx_scan_run_type_status", "type", "status"),
        {"schema": "security_ops"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    # SAST / SCA / DAST / IMAGE_VULN / IAC / SECRET / LICENSE
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    pipeline_id: Mapped[str | None] = mapped_column(String(100))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # RUNNING / PASSED / FAILED / ERRORED
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    sarif_s3_key: Mapped[str | None] = mapped_column(String(500))
    # {"critical": 0, "high": 2, "medium": 5, "low": 10}
    findings_count: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(Base):
    __tablename__ = "vulnerability"
    __table_args__ = (
        Index(
            "idx_vuln_status_due",
            "status", "due_at",
            postgresql_where="status NOT IN ('CLOSED','RISK_ACCEPTED','EXEMPTED')",
        ),
        Index("idx_vuln_severity_status", "severity", "status"),
        {"schema": "security_ops"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    # SAST / SCA / PENTEST / CVE_MONITOR / CUSTOMER_REPORT
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(200))
    cve_id: Mapped[str | None] = mapped_column(String(30))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    # CRITICAL / HIGH / MEDIUM / LOW
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    package_affected: Mapped[str | None] = mapped_column(String(200))
    # OPEN / TRIAGED / IN_FIX / AWAITING_VERIFY / CLOSED / RISK_ACCEPTED / EXEMPTED
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(200))
    fix_pr_url: Mapped[str | None] = mapped_column(String(500))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exception_id: Mapped[str | None] = mapped_column(String(40))
    risk_acceptance_id: Mapped[str | None] = mapped_column(String(40))
    notes_md: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# incident
# ---------------------------------------------------------------------------

class Incident(Base):
    __tablename__ = "incident"
    __table_args__ = (
        Index("idx_incident_status", "status", "severity"),
        {"schema": "security_ops"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    # CRITICAL / HIGH / MEDIUM / LOW
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    # DATA_BREACH / RANSOMWARE / DDOS / INSIDER / OUTAGE / OTHER
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reported_by: Mapped[str] = mapped_column(String(200), nullable=False)
    ic: Mapped[str | None] = mapped_column(String(200))
    # DETECTED / INVESTIGATING / CONTAINED / RESOLVED / POST_MORTEM
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    containment_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    root_cause: Mapped[str | None] = mapped_column(Text)
    pir_s3_key: Mapped[str | None] = mapped_column(String(500))
    customers_notified: Mapped[bool | None] = mapped_column(Boolean)
    regulators_notified: Mapped[bool | None] = mapped_column(Boolean)
    affected_tenants: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    audit_event_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# sbom_record — SBOM 元数据存储
# ---------------------------------------------------------------------------

class SbomRecord(Base):
    __tablename__ = "sbom_record"
    __table_args__ = (
        Index("idx_sbom_image_ref", "image_ref"),
        {"schema": "security_ops"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    image_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    # CycloneDX / SPDX
    format: Mapped[str] = mapped_column(String(20), nullable=False, default="CycloneDX")
    sbom_s3_key: Mapped[str | None] = mapped_column(String(500))
    attestation_digest: Mapped[str | None] = mapped_column(String(200))
    component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Syft / cosign / adapter
    generator_tool: Mapped[str] = mapped_column(String(50), nullable=False, default="syft")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# sbom_watch — Grype watch 注册
# ---------------------------------------------------------------------------

class SbomWatch(Base):
    __tablename__ = "sbom_watch"
    __table_args__ = ({"schema": "security_ops"},)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    image_ref: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notify: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    new_cves_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


# ---------------------------------------------------------------------------
# license_finding — License 扫描结果
# ---------------------------------------------------------------------------

class LicenseFinding(Base):
    __tablename__ = "license_finding"
    __table_args__ = (
        Index("idx_license_scan_run", "scan_run_id"),
        {"schema": "security_ops"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(String(40), nullable=False)
    package_name: Mapped[str] = mapped_column(String(200), nullable=False)
    package_version: Mapped[str | None] = mapped_column(String(100))
    license_spdx: Mapped[str] = mapped_column(String(100), nullable=False)
    # ALLOWED / BLOCKED / REVIEW_REQUIRED
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    exception_id: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# drill — 演练记录
# ---------------------------------------------------------------------------

class Drill(Base):
    __tablename__ = "drill"
    __table_args__ = ({"schema": "security_ops"},)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    # TABLETOP / PLAYBOOK_DRILL / RED_BLUE_TEAM
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # SCHEDULED / RUNNING / COMPLETED / CANCELED
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pir_s3_key: Mapped[str | None] = mapped_column(String(500))
    participants: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    scenario_runbook: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# outbox — transactional event publishing
# ---------------------------------------------------------------------------

class Outbox(Base):
    __tablename__ = "security_ops_event_outbox"
    __table_args__ = ({"schema": "security_ops"},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
