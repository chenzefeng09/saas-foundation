"""Security Operations Service.

Core business logic for:
  - scan.report_run()          CI 扫描结果上报 + 自动开漏洞票
  - vuln.list() / assign() / mark_in_fix() / close() / request_exception()
  - vuln.sla_dashboard()
  - sbom.generate() / watch_register()
  - incident.declare() / update() / resolve()
  - drill.schedule() / complete()
  - license_finding.record()

SDK-facing top-level functions:
  report_incident()            -> Incident
  get_vulnerability_status()   -> list[Vulnerability]
  generate_sbom()              -> bytes (CycloneDX)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_security_ops.domain.models import (
    Drill,
    Incident,
    LicenseFinding,
    Outbox,
    SbomRecord,
    SbomWatch,
    ScanRun,
    Vulnerability,
)
from foundation_security_ops.errors import (
    INCIDENT_NOT_FOUND,
    VALIDATION_FAILED,
    VULN_NOT_FOUND,
    FoundationError,
)
from foundation_security_ops.observability import get_logger
from foundation_security_ops.services import license_policy, sla
from foundation_security_ops.services.sbom_adapter import (
    SbomToolUnavailable,
    stub_sbom,
)
from foundation_security_ops.services.sbom_adapter import (
    generate_sbom as _syft_generate,
)
from foundation_security_ops.services.sbom_adapter import (
    verify_attestation as _cosign_verify,
)

log = get_logger(__name__)

# ── SLA thresholds for automated scan → vulnerability fanout ────────────────
_BLOCK_SEVERITIES = {"CRITICAL", "HIGH"}

# ── License blocked verdict triggers vuln if not excepted ───────────────────


def _new_id(prefix: str) -> str:
    return f"{prefix}_{ulid.new()!s}"


# ── storage-v1 §7.2: validate *_s3_key request body format ───────────────────
# security-ops itself does NOT write S3 — keys come in over the wire from CI
# pipelines / SDK callers and we trust them.  But Phase 2 starts policing the
# wire format so future writers can rely on a single canonical layout
# (``{bucket}::tenants/{tid}/...``).  The behaviour is feature-flagged so a
# bad rollout can't block CI before all callers have caught up.

_KEY_FORMAT_FLAG = "storage.security_ops_validate_key_format"


def _validate_s3_key_format(s3_key: str) -> None:
    """Parse ``s3_key`` with foundation_storage.ObjectKey.from_string.

    Raises ``FoundationError(VALIDATION_FAILED)`` on any parse failure.  Caller
    is responsible for the feature-flag gate; this helper always raises.
    """
    try:
        from foundation_storage import ObjectKey
        from foundation_storage import get_settings as get_storage_settings
        from foundation_storage.errors import KeyValidationError
    except ImportError as exc:  # pragma: no cover - defensive
        raise FoundationError(
            VALIDATION_FAILED,
            detail=f"foundation_storage not installed: {exc}",
        ) from exc

    settings = get_storage_settings()
    try:
        ObjectKey.from_string(s3_key, settings.bucket_to_purpose_map())
    except KeyValidationError as exc:
        raise FoundationError(
            VALIDATION_FAILED,
            detail=f"s3_key {s3_key!r} does not match storage-v1 format: {exc.detail}",
            extra={"s3_key": s3_key},
        ) from exc


def _flag_enabled(name: str) -> bool:
    """Evaluate a feature flag; treat any failure as OFF (fail_open=False)."""
    try:
        from foundation_feature_flag.services.feature_flag_service import (
            FeatureFlagService,
        )
        svc = FeatureFlagService()
        return bool(svc.is_enabled(name))
    except Exception as exc:
        log.warning("feature_flag.lookup.failed", flag=name, error=str(exc))
        return False


def _check_s3_keys(s3_keys: list[str | None]) -> None:
    """Run validation for every non-None s3_key supplied; flag-gated.

    Flag OFF: only emit a warning per drift (log fields ``security_ops.s3_key.format_drift``).
    Flag ON : raise FoundationError(VALIDATION_FAILED) on first drift.
    """
    enabled = _flag_enabled(_KEY_FORMAT_FLAG)
    for key in s3_keys:
        if not key:
            continue
        try:
            _validate_s3_key_format(key)
        except FoundationError as exc:
            if enabled:
                raise
            log.warning(
                "security_ops.s3_key.format_drift",
                s3_key=key,
                detail=exc.detail,
            )


def _encode_s3_location(s3_keys: list[str | None]) -> str | None:
    """Pack one-or-more raw ``*_s3_key`` strings into the row's ``s3_location``.

    Returns ``None`` if no keys are supplied so we don't pollute rows that
    have no S3 dependency.  Format is JSON list (small, human-readable, lets
    Phase 4 GC iterate without parsing per-field knowledge).
    """
    import json as _json

    valid = [k for k in s3_keys if k]
    if not valid:
        return None
    return _json.dumps(valid, ensure_ascii=False)


class SecurityOpsService:
    """Platform-level security operations service.

    Note: this service is platform-scoped (not tenant-scoped).  Scans, vulns,
    incidents, and SBOMs belong to the platform/org level; affected_tenants is
    an annotation field, not an RLS gate.
    """

    # ────────────────────────────────────────────────────────── Scan runs ───

    async def report_scan_run(
        self,
        session: AsyncSession,
        *,
        type: str,
        tool: str,
        target: str,
        commit_sha: str | None,
        pipeline_id: str | None,
        started_at: datetime,
        finished_at: datetime | None,
        status: str,
        sarif_s3_key: str | None,
        findings_count: dict[str, int],
        request_id: str,
    ) -> tuple[ScanRun, list[Vulnerability]]:
        """Persist a CI scan result and auto-open vulnerability tickets.

        For each critical/high finding in findings_count, a Vulnerability
        record is created with the appropriate SLA deadline.  This is the
        SDK report_incident() entrypoint for CI-sourced findings.

        Returns (scan_run, list_of_new_vulns).
        """
        # storage-v1 §7.2: validate *_s3_key request body format (feature-flagged).
        _check_s3_keys([sarif_s3_key])
        scan = ScanRun(
            id=_new_id("scan"),
            type=type.upper(),
            tool=tool,
            target=target,
            commit_sha=commit_sha,
            pipeline_id=pipeline_id,
            started_at=started_at,
            finished_at=finished_at,
            status=status.upper(),
            sarif_s3_key=sarif_s3_key,
            s3_location=_encode_s3_location([sarif_s3_key]),
            findings_count=findings_count,
        )
        session.add(scan)

        new_vulns: list[Vulnerability] = []
        now = datetime.now(UTC)
        source = type.upper()

        # Auto-fanout: create one aggregate vuln per blocked severity level
        for severity in ("CRITICAL", "HIGH"):
            count = findings_count.get(severity.lower(), 0) or findings_count.get(severity, 0)
            if count <= 0:
                continue
            vuln = Vulnerability(
                id=_new_id("vuln"),
                source=source if source in {"SAST", "SCA", "DAST", "IMAGE_VULN", "IAC", "SECRET"} else "SAST",
                source_ref=scan.id,
                title=f"[{tool}] {count} {severity.title()} findings in {target}",
                severity=severity,
                status="OPEN",
                found_at=now,
                due_at=sla.compute_due_at(now, severity),
            )
            session.add(vuln)
            new_vulns.append(vuln)

        if status.upper() == "FAILED":
            self._emit(session, None, "foundation.security_ops.scan.failed",
                       {"scan_id": scan.id, "tool": tool, "target": target,
                        "findings_count": findings_count}, request_id)

        for v in new_vulns:
            self._emit(session, None, "foundation.security_ops.vuln.opened",
                       {"vuln_id": v.id, "severity": v.severity, "source": v.source}, request_id)

        await session.flush()
        return scan, new_vulns

    async def list_scan_runs(
        self,
        session: AsyncSession,
        *,
        type_filter: str | None = None,
        status_filter: str | None = None,
        limit: int = 50,
    ) -> list[ScanRun]:
        stmt = select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)
        if type_filter:
            stmt = stmt.where(ScanRun.type == type_filter.upper())
        if status_filter:
            stmt = stmt.where(ScanRun.status == status_filter.upper())
        return list((await session.scalars(stmt)).all())

    # ──────────────────────────────────────────────────── Vulnerabilities ───

    async def list_vulnerabilities(
        self,
        session: AsyncSession,
        *,
        severity: str | None = None,
        status: str | None = None,
        package_affected: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[Vulnerability]:
        stmt = select(Vulnerability).order_by(Vulnerability.due_at.asc()).limit(limit)
        if severity:
            stmt = stmt.where(Vulnerability.severity == severity.upper())
        if status:
            stmt = stmt.where(Vulnerability.status == status.upper())
        if package_affected:
            stmt = stmt.where(Vulnerability.package_affected == package_affected)
        if source:
            stmt = stmt.where(Vulnerability.source == source.upper())
        return list((await session.scalars(stmt)).all())

    async def get_vulnerability(self, session: AsyncSession, vuln_id: str) -> Vulnerability:
        """SDK get_vulnerability_status() for a single record."""
        vuln = await session.get(Vulnerability, vuln_id)
        if vuln is None:
            raise FoundationError(VULN_NOT_FOUND, f"Vulnerability {vuln_id!r} not found")
        return vuln

    async def update_vulnerability(
        self,
        session: AsyncSession,
        vuln_id: str,
        *,
        status: str | None = None,
        assignee: str | None = None,
        fix_pr_url: str | None = None,
        notes_md: str | None = None,
        request_id: str = "",
    ) -> Vulnerability:
        vuln = await session.get(Vulnerability, vuln_id)
        if vuln is None:
            raise FoundationError(VULN_NOT_FOUND, f"Vulnerability {vuln_id!r} not found")

        if status:
            vuln.status = status.upper()
            if status.upper() in ("CLOSED",):
                vuln.closed_at = datetime.now(UTC)
                self._emit(session, None, "foundation.security_ops.vuln.closed",
                           {"vuln_id": vuln_id, "severity": vuln.severity}, request_id)
        if assignee is not None:
            vuln.assignee = assignee
        if fix_pr_url is not None:
            vuln.fix_pr_url = fix_pr_url
        if notes_md is not None:
            vuln.notes_md = notes_md

        await session.flush()
        return vuln

    async def request_risk_acceptance(
        self,
        session: AsyncSession,
        vuln_id: str,
        *,
        rationale: str,
        mitigations: list[str],
        expires_at: datetime | None,
        request_id: str = "",
    ) -> str:
        vuln = await session.get(Vulnerability, vuln_id)
        if vuln is None:
            raise FoundationError(VULN_NOT_FOUND, f"Vulnerability {vuln_id!r} not found")

        approval_id = _new_id("rapproval")
        vuln.risk_acceptance_id = approval_id
        vuln.status = "RISK_ACCEPTED"
        self._emit(session, None, "foundation.security_ops.vuln.risk_accepted",
                   {"vuln_id": vuln_id, "approval_id": approval_id,
                    "rationale": rationale}, request_id)
        await session.flush()
        return approval_id

    async def sla_dashboard(self, session: AsyncSession) -> dict[str, Any]:
        """Aggregate SLA metrics: overdue by severity, by owner, MTTR.

        SDK: vuln.sla_dashboard()
        """
        now = datetime.now(UTC)
        all_open = list((await session.scalars(
            select(Vulnerability).where(
                Vulnerability.status.not_in(["CLOSED", "RISK_ACCEPTED", "EXEMPTED"])
            )
        )).all())

        overdue_by_severity: dict[str, int] = {}
        by_owner: dict[str, dict[str, int]] = {}
        closed_vulns = list((await session.scalars(
            select(Vulnerability).where(Vulnerability.status == "CLOSED")
        )).all())

        for v in all_open:
            if sla.is_overdue(v.due_at, now):
                overdue_by_severity[v.severity] = overdue_by_severity.get(v.severity, 0) + 1
            owner = v.assignee or "unassigned"
            if owner not in by_owner:
                by_owner[owner] = {}
            by_owner[owner][v.severity] = by_owner[owner].get(v.severity, 0) + 1

        # MTTR: average days from found_at to closed_at per severity
        mttr_sums: dict[str, float] = {}
        mttr_counts: dict[str, int] = {}
        for v in closed_vulns:
            if v.closed_at and v.found_at:
                delta = (v.closed_at - v.found_at).total_seconds() / 86400
                mttr_sums[v.severity] = mttr_sums.get(v.severity, 0.0) + delta
                mttr_counts[v.severity] = mttr_counts.get(v.severity, 0) + 1
        mttr_days = {
            sev: round(mttr_sums[sev] / mttr_counts[sev], 1)
            for sev in mttr_sums
        }

        return {
            "overdue_by_severity": overdue_by_severity,
            "by_owner": by_owner,
            "mttr_days": mttr_days,
        }

    # ────────────────────────────────────────────────────────────── SBOM ───

    async def generate_sbom(
        self,
        session: AsyncSession,
        image_ref: str,
        *,
        fmt: str = "cyclonedx-json",
        request_id: str = "",
    ) -> tuple[bytes, SbomRecord]:
        """SDK generate_sbom(image_ref) -> bytes.

        Attempts to call Syft; falls back to a stub payload if Syft is absent.
        Always persists an SbomRecord regardless of tool availability.
        """
        from foundation_security_ops.services.sbom_adapter import SbomFormat
        safe_fmt: SbomFormat = "cyclonedx-json" if "cyclonedx" in fmt.lower() else "spdx-json"

        is_stub = False
        try:
            raw = _syft_generate(image_ref, fmt=safe_fmt)
        except SbomToolUnavailable:
            log.warning("sbom.syft_unavailable", image_ref=image_ref)
            raw = stub_sbom(image_ref, safe_fmt)
            is_stub = True

        import json as _json
        try:
            doc = _json.loads(raw)
            component_count = len(doc.get("components", []))
        except Exception:
            component_count = 0

        record = SbomRecord(
            id=_new_id("sbom"),
            image_ref=image_ref,
            format="CycloneDX" if "cyclonedx" in safe_fmt else "SPDX",
            component_count=component_count,
            generated_at=datetime.now(UTC),
            generator_tool="syft-stub" if is_stub else "syft",
        )
        session.add(record)
        self._emit(session, None, "foundation.security_ops.sbom.generated",
                   {"sbom_id": record.id, "image_ref": image_ref, "is_stub": is_stub},
                   request_id)
        await session.flush()
        return raw, record

    async def verify_sbom_attestation(self, image_ref: str) -> bool:
        """SDK sbom.verify_attestation(image_ref) -> bool."""
        return _cosign_verify(image_ref)

    async def register_sbom_watch(
        self,
        session: AsyncSession,
        image_ref: str,
        *,
        notify: list[str] | None = None,
        request_id: str = "",
    ) -> SbomWatch:
        """SDK sbom.watch_register(image_ref, notify=[...])."""
        # Upsert pattern — check existing
        existing = (await session.scalars(
            select(SbomWatch).where(SbomWatch.image_ref == image_ref)
        )).first()
        if existing:
            if notify is not None:
                existing.notify = notify
            await session.flush()
            return existing

        watch = SbomWatch(
            id=_new_id("sbomwatch"),
            image_ref=image_ref,
            registered_at=datetime.now(UTC),
            notify=notify or [],
            new_cves_count=0,
        )
        session.add(watch)
        await session.flush()
        return watch

    async def list_sbom_watches(self, session: AsyncSession) -> list[SbomWatch]:
        return list((await session.scalars(select(SbomWatch))).all())

    async def get_sbom_for_image(self, session: AsyncSession, image_ref: str) -> SbomRecord | None:
        return (await session.scalars(
            select(SbomRecord)
            .where(SbomRecord.image_ref == image_ref)
            .order_by(SbomRecord.generated_at.desc())
        )).first()

    # ───────────────────────────────────────────────────────── Incidents ───

    async def declare_incident(
        self,
        session: AsyncSession,
        *,
        severity: str,
        category: str,
        title: str,
        reported_by: str,
        ic: str | None = None,
        affected_tenants: list[str] | None = None,
        request_id: str = "",
    ) -> Incident:
        """SDK report_incident() — declare an IR event.

        Creates the incident with status DETECTED and emits
        foundation.security_ops.incident.declared.
        """
        incident = Incident(
            id=_new_id("inc"),
            severity=severity.upper(),
            category=category.upper(),
            title=title,
            detected_at=datetime.now(UTC),
            reported_by=reported_by,
            ic=ic,
            status="DETECTED",
            affected_tenants=affected_tenants or [],
        )
        session.add(incident)
        self._emit(session, None, "foundation.security_ops.incident.declared",
                   {"inc_id": incident.id, "severity": incident.severity,
                    "category": incident.category, "title": title}, request_id)
        await session.flush()
        return incident

    async def get_incident(self, session: AsyncSession, inc_id: str) -> Incident:
        inc = await session.get(Incident, inc_id)
        if inc is None:
            raise FoundationError(INCIDENT_NOT_FOUND, f"Incident {inc_id!r} not found")
        return inc

    async def update_incident(
        self,
        session: AsyncSession,
        inc_id: str,
        *,
        status: str | None = None,
        ic: str | None = None,
        customers_notified: bool | None = None,
        regulators_notified: bool | None = None,
        request_id: str = "",
    ) -> Incident:
        inc = await session.get(Incident, inc_id)
        if inc is None:
            raise FoundationError(INCIDENT_NOT_FOUND, f"Incident {inc_id!r} not found")

        if status:
            inc.status = status.upper()
            if status.upper() == "CONTAINED":
                inc.containment_at = datetime.now(UTC)
        if ic is not None:
            inc.ic = ic
        if customers_notified is not None:
            inc.customers_notified = customers_notified
        if regulators_notified is not None:
            inc.regulators_notified = regulators_notified

        await session.flush()
        return inc

    async def resolve_incident(
        self,
        session: AsyncSession,
        inc_id: str,
        *,
        root_cause: str,
        pir_s3_key: str,
        request_id: str = "",
    ) -> Incident:
        inc = await session.get(Incident, inc_id)
        if inc is None:
            raise FoundationError(INCIDENT_NOT_FOUND, f"Incident {inc_id!r} not found")

        # storage-v1 §7.2: validate *_s3_key request body format (feature-flagged).
        _check_s3_keys([pir_s3_key])
        inc.status = "RESOLVED"
        inc.resolved_at = datetime.now(UTC)
        inc.root_cause = root_cause
        inc.pir_s3_key = pir_s3_key
        inc.s3_location = _encode_s3_location([pir_s3_key])
        self._emit(session, None, "foundation.security_ops.incident.resolved",
                   {"inc_id": inc_id, "root_cause": root_cause}, request_id)
        await session.flush()
        return inc

    async def list_incidents(
        self,
        session: AsyncSession,
        *,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        stmt = select(Incident).order_by(Incident.detected_at.desc()).limit(limit)
        if severity:
            stmt = stmt.where(Incident.severity == severity.upper())
        if status:
            stmt = stmt.where(Incident.status == status.upper())
        return list((await session.scalars(stmt)).all())

    # ────────────────────────────────────────────────────────── Drills ───

    async def schedule_drill(
        self,
        session: AsyncSession,
        *,
        kind: str,
        scheduled_at: datetime,
        participants: list[str] | None = None,
        scenario_runbook: str | None = None,
        request_id: str = "",
    ) -> Drill:
        drill = Drill(
            id=_new_id("drill"),
            kind=kind.upper(),
            scheduled_at=scheduled_at,
            status="SCHEDULED",
            participants=participants or [],
            scenario_runbook=scenario_runbook,
        )
        session.add(drill)
        await session.flush()
        return drill

    async def complete_drill(
        self,
        session: AsyncSession,
        drill_id: str,
        *,
        pir_s3_key: str | None = None,
        request_id: str = "",
    ) -> Drill:
        drill = await session.get(Drill, drill_id)
        if drill is None:
            raise ValueError(f"Drill {drill_id!r} not found")
        # storage-v1 §7.2: validate *_s3_key request body format (feature-flagged).
        if pir_s3_key:
            _check_s3_keys([pir_s3_key])
        drill.status = "COMPLETED"
        drill.completed_at = datetime.now(UTC)
        if pir_s3_key:
            drill.pir_s3_key = pir_s3_key
            drill.s3_location = _encode_s3_location([pir_s3_key])
        self._emit(session, None, "foundation.security_ops.drill.completed",
                   {"drill_id": drill_id, "kind": drill.kind}, request_id)
        await session.flush()
        return drill

    async def list_drills(
        self,
        session: AsyncSession,
        *,
        kind: str | None = None,
        limit: int = 50,
    ) -> list[Drill]:
        stmt = select(Drill).order_by(Drill.scheduled_at.desc()).limit(limit)
        if kind:
            stmt = stmt.where(Drill.kind == kind.upper())
        return list((await session.scalars(stmt)).all())

    # ──────────────────────────────────────────────── License findings ───

    async def record_license_finding(
        self,
        session: AsyncSession,
        *,
        scan_run_id: str,
        package_name: str,
        package_version: str | None,
        license_spdx: str,
        exception_id: str | None = None,
        request_id: str = "",
    ) -> LicenseFinding:
        verdict = license_policy.evaluate_license(license_spdx, exception_id=exception_id)
        finding = LicenseFinding(
            id=_new_id("lic"),
            scan_run_id=scan_run_id,
            package_name=package_name,
            package_version=package_version,
            license_spdx=license_spdx,
            verdict=verdict,
            exception_id=exception_id,
        )
        session.add(finding)
        await session.flush()
        return finding

    # ──────────────────────────────────────────── Internal helpers ───────

    def _emit(
        self,
        session: AsyncSession,
        tenant_id: str | None,
        event_type: str,
        payload: dict[str, Any],
        request_id: str,
    ) -> None:
        agg = payload.get("inc_id") or payload.get("vuln_id") or payload.get("scan_id") or ""
        session.add(Outbox(
            tenant_id=tenant_id,
            event_type=event_type,
            aggregate_id=str(agg),
            payload=payload,
            request_id=request_id,
        ))
