"""Tests for SecurityOpsService — scan, vulnerability, incident, SBOM, drill."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from foundation_security_ops.domain.models import (
    Drill,
    Incident,
    SbomWatch,
    ScanRun,
    Vulnerability,
)
from foundation_security_ops.errors import FoundationError
from foundation_security_ops.services.security_ops_service import SecurityOpsService


@pytest.fixture
def svc() -> SecurityOpsService:
    return SecurityOpsService()


@pytest.fixture
def scan_time() -> datetime:
    return datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


# ════════════════════════════════════════════════════════════════ Scans ══════


class TestReportScanRun:
    async def test_passed_scan_no_vulns(self, svc, fake_session, request_id, scan_time):
        scan, vulns = await svc.report_scan_run(
            fake_session,
            type="SAST",
            tool="semgrep",
            target="repo:saas-foundation",
            commit_sha="abc123",
            pipeline_id="ci-001",
            started_at=scan_time,
            finished_at=scan_time + timedelta(minutes=5),
            status="PASSED",
            sarif_s3_key=None,
            findings_count={"critical": 0, "high": 0, "medium": 2},
            request_id=request_id,
        )
        assert isinstance(scan, ScanRun)
        assert scan.id.startswith("scan_")
        assert scan.status == "PASSED"
        assert len(vulns) == 0  # no CRITICAL/HIGH → no auto-vuln

    async def test_failed_scan_opens_vulns(self, svc, fake_session, request_id, scan_time):
        scan, vulns = await svc.report_scan_run(
            fake_session,
            type="SCA",
            tool="trivy",
            target="repo:saas-foundation",
            commit_sha=None,
            pipeline_id=None,
            started_at=scan_time,
            finished_at=None,
            status="FAILED",
            sarif_s3_key="s3://bucket/sarif.json",
            findings_count={"critical": 1, "high": 2, "medium": 5},
            request_id=request_id,
        )
        # Should open one vuln for CRITICAL + one for HIGH
        assert len(vulns) == 2
        severities = {v.severity for v in vulns}
        assert severities == {"CRITICAL", "HIGH"}

    async def test_critical_vuln_sla_24h(self, svc, fake_session, request_id, scan_time):
        _scan, vulns = await svc.report_scan_run(
            fake_session,
            type="SAST",
            tool="semgrep",
            target="repo:test",
            commit_sha=None,
            pipeline_id=None,
            started_at=scan_time,
            finished_at=None,
            status="FAILED",
            sarif_s3_key=None,
            findings_count={"critical": 3},
            request_id=request_id,
        )
        crit_vuln = next(v for v in vulns if v.severity == "CRITICAL")
        # SLA should be ~24h from found_at
        delta = crit_vuln.due_at - crit_vuln.found_at
        assert timedelta(hours=23) < delta <= timedelta(hours=25)

    async def test_outbox_event_emitted_on_failure(self, svc, fake_session, request_id, scan_time):
        from foundation_security_ops.domain.models import Outbox

        await svc.report_scan_run(
            fake_session,
            type="SECRET",
            tool="gitleaks",
            target="repo:x",
            commit_sha=None,
            pipeline_id=None,
            started_at=scan_time,
            finished_at=None,
            status="FAILED",
            sarif_s3_key=None,
            findings_count={"critical": 1},
            request_id=request_id,
        )
        outbox_events = [o for o in fake_session.added if isinstance(o, Outbox)]
        event_types = {o.event_type for o in outbox_events}
        assert "foundation.security_ops.scan.failed" in event_types
        assert "foundation.security_ops.vuln.opened" in event_types


# ═══════════════════════════════════════════════════════ Vulnerabilities ════


class TestVulnerabilityLifecycle:
    async def test_get_existing_vuln(self, svc, fake_session, request_id):
        now = datetime.now(UTC)
        vuln = Vulnerability(
            id="vuln_TEST01", source="SAST", title="SQL Injection",
            severity="HIGH", status="OPEN",
            found_at=now, due_at=now + timedelta(days=7),
        )
        fake_session.put(vuln)

        result = await svc.get_vulnerability(fake_session, "vuln_TEST01")
        assert result.id == "vuln_TEST01"
        assert result.severity == "HIGH"

    async def test_get_nonexistent_raises(self, svc, fake_session):
        with pytest.raises(FoundationError, match="not found"):
            await svc.get_vulnerability(fake_session, "vuln_NONEXISTENT")

    async def test_update_vuln_assigns(self, svc, fake_session, request_id):
        now = datetime.now(UTC)
        vuln = Vulnerability(
            id="vuln_ASSIGN", source="SCA", title="Log4Shell",
            severity="CRITICAL", status="OPEN",
            found_at=now, due_at=now + timedelta(days=1),
        )
        fake_session.put(vuln)

        updated = await svc.update_vulnerability(
            fake_session, "vuln_ASSIGN",
            assignee="alice@example.com",
            request_id=request_id,
        )
        assert updated.assignee == "alice@example.com"

    async def test_close_vuln_sets_closed_at(self, svc, fake_session, request_id):
        now = datetime.now(UTC)
        vuln = Vulnerability(
            id="vuln_CLOSE", source="PENTEST", title="XSS",
            severity="MEDIUM", status="IN_FIX",
            found_at=now, due_at=now + timedelta(days=30),
        )
        fake_session.put(vuln)

        updated = await svc.update_vulnerability(
            fake_session, "vuln_CLOSE",
            status="CLOSED",
            request_id=request_id,
        )
        assert updated.status == "CLOSED"
        assert updated.closed_at is not None

    async def test_risk_acceptance(self, svc, fake_session, request_id):
        now = datetime.now(UTC)
        vuln = Vulnerability(
            id="vuln_RISK", source="CVE_MONITOR", title="CVE-2025-9999",
            severity="MEDIUM", status="OPEN",
            found_at=now, due_at=now + timedelta(days=30),
        )
        fake_session.put(vuln)

        approval_id = await svc.request_risk_acceptance(
            fake_session, "vuln_RISK",
            rationale="This dependency is only used in test tooling, not shipped in production.",
            mitigations=["Isolated test environment", "No network access"],
            expires_at=None,
            request_id=request_id,
        )
        assert approval_id.startswith("rapproval_")
        assert vuln.status == "RISK_ACCEPTED"
        assert vuln.risk_acceptance_id == approval_id


# ═══════════════════════════════════════════════════════════ SLA Dashboard ══


class TestSlaDashboard:
    async def test_empty_dashboard(self, svc, fake_session):
        # No vulns queued — empty dashboard
        dashboard = await svc.sla_dashboard(fake_session)
        assert "overdue_by_severity" in dashboard
        assert "by_owner" in dashboard
        assert "mttr_days" in dashboard

    async def test_overdue_counted(self, svc, fake_session):
        now = datetime.now(UTC)
        # One overdue CRITICAL (due in the past)
        overdue_vuln = Vulnerability(
            id="vuln_OD1", source="SAST", title="Overdue Critical",
            severity="CRITICAL", status="OPEN",
            found_at=now - timedelta(days=5),
            due_at=now - timedelta(days=2),  # 2 days overdue
            assignee="bob@example.com",
        )
        # One not-yet-due HIGH
        fresh_vuln = Vulnerability(
            id="vuln_OD2", source="SCA", title="Fresh High",
            severity="HIGH", status="OPEN",
            found_at=now,
            due_at=now + timedelta(days=6),
        )
        # Queue two separate scalars calls (open vulns, closed vulns)
        fake_session.queue_scalars([overdue_vuln, fresh_vuln])
        fake_session.queue_scalars([])  # closed vulns

        dashboard = await svc.sla_dashboard(fake_session)
        assert dashboard["overdue_by_severity"].get("CRITICAL", 0) == 1
        assert dashboard["overdue_by_severity"].get("HIGH", 0) == 0
        assert "bob@example.com" in dashboard["by_owner"]


# ═══════════════════════════════════════════════════════════════ Incidents ══


class TestIncidentLifecycle:
    async def test_declare_incident(self, svc, fake_session, request_id):
        inc = await svc.declare_incident(
            fake_session,
            severity="CRITICAL",
            category="DATA_BREACH",
            title="Cross-tenant data leak detected",
            reported_by="sre-oncall@example.com",
            ic="alice@example.com",
            affected_tenants=["tnt_01", "tnt_02"],
            request_id=request_id,
        )
        assert isinstance(inc, Incident)
        assert inc.id.startswith("inc_")
        assert inc.severity == "CRITICAL"
        assert inc.status == "DETECTED"
        assert "tnt_01" in inc.affected_tenants

    async def test_declare_incident_emits_event(self, svc, fake_session, request_id):
        from foundation_security_ops.domain.models import Outbox

        await svc.declare_incident(
            fake_session,
            severity="HIGH",
            category="OUTAGE",
            title="PG primary down",
            reported_by="oncall@example.com",
            request_id=request_id,
        )
        outbox_events = [o for o in fake_session.added if isinstance(o, Outbox)]
        event_types = {o.event_type for o in outbox_events}
        assert "foundation.security_ops.incident.declared" in event_types

    async def test_update_incident_status(self, svc, fake_session, request_id):
        inc = Incident(
            id="inc_TEST01", severity="HIGH", category="OUTAGE",
            title="DB down", detected_at=datetime.now(UTC),
            reported_by="oncall", status="DETECTED",
        )
        fake_session.put(inc)

        updated = await svc.update_incident(
            fake_session, "inc_TEST01",
            status="INVESTIGATING",
            request_id=request_id,
        )
        assert updated.status == "INVESTIGATING"

    async def test_containment_sets_timestamp(self, svc, fake_session, request_id):
        inc = Incident(
            id="inc_CONT", severity="CRITICAL", category="RANSOMWARE",
            title="Ransomware attack", detected_at=datetime.now(UTC),
            reported_by="security@example.com", status="INVESTIGATING",
        )
        fake_session.put(inc)

        updated = await svc.update_incident(
            fake_session, "inc_CONT", status="CONTAINED", request_id=request_id
        )
        assert updated.status == "CONTAINED"
        assert updated.containment_at is not None

    async def test_resolve_incident(self, svc, fake_session, request_id):
        inc = Incident(
            id="inc_RESOLVE", severity="HIGH", category="OUTAGE",
            title="DB failover", detected_at=datetime.now(UTC),
            reported_by="oncall", status="CONTAINED",
        )
        fake_session.put(inc)

        resolved = await svc.resolve_incident(
            fake_session, "inc_RESOLVE",
            root_cause="Primary DB OOM-killed; standby promoted in 4 minutes.",
            pir_s3_key="s3://bucket/pir/inc_RESOLVE.pdf",
            request_id=request_id,
        )
        assert resolved.status == "RESOLVED"
        assert resolved.resolved_at is not None
        assert resolved.pir_s3_key is not None

    async def test_get_nonexistent_incident_raises(self, svc, fake_session):
        with pytest.raises(FoundationError, match="not found"):
            await svc.get_incident(fake_session, "inc_NONEXISTENT")


# ════════════════════════════════════════════════════════════════ SBOM ══════


class TestSbomService:
    async def test_generate_sbom_stub(self, svc, fake_session, request_id):
        """generate_sbom() should succeed even without Syft (stub mode)."""
        raw, record = await svc.generate_sbom(
            fake_session,
            "registry.example.com/myapp:v1.0.0",
            fmt="cyclonedx-json",
            request_id=request_id,
        )
        assert isinstance(raw, bytes)
        assert len(raw) > 0
        assert record.id.startswith("sbom_")
        assert record.image_ref == "registry.example.com/myapp:v1.0.0"

    async def test_register_sbom_watch(self, svc, fake_session, request_id):
        watch = await svc.register_sbom_watch(
            fake_session,
            "registry.example.com/myapp:v1.0.0",
            notify=["security@example.com", "oncall@example.com"],
            request_id=request_id,
        )
        assert isinstance(watch, SbomWatch)
        assert watch.id.startswith("sbomwatch_")
        assert "security@example.com" in watch.notify

    async def test_register_watch_upsert(self, svc, fake_session, request_id):
        """Re-registering the same image_ref should upsert, not duplicate."""
        existing_watch = SbomWatch(
            id="sbomwatch_EXIST",
            image_ref="registry.example.com/myapp:v1.0.0",
            registered_at=datetime.now(UTC),
            notify=["old@example.com"],
            new_cves_count=0,
        )
        fake_session.queue_scalars([existing_watch])

        watch = await svc.register_sbom_watch(
            fake_session,
            "registry.example.com/myapp:v1.0.0",
            notify=["new@example.com"],
            request_id=request_id,
        )
        assert watch.id == "sbomwatch_EXIST"
        assert "new@example.com" in watch.notify


# ═══════════════════════════════════════════════════════════════ Drills ═════


class TestDrillService:
    async def test_schedule_drill(self, svc, fake_session, request_id):
        future = datetime.now(UTC) + timedelta(days=30)
        drill = await svc.schedule_drill(
            fake_session,
            kind="TABLETOP",
            scheduled_at=future,
            participants=["alice@example.com", "bob@example.com"],
            scenario_runbook="docs/security/runbooks/data-breach.md",
            request_id=request_id,
        )
        assert isinstance(drill, Drill)
        assert drill.id.startswith("drill_")
        assert drill.kind == "TABLETOP"
        assert drill.status == "SCHEDULED"
        assert "alice@example.com" in drill.participants

    async def test_complete_drill(self, svc, fake_session, request_id):
        future = datetime.now(UTC) + timedelta(days=7)
        drill = Drill(
            id="drill_TEST", kind="PLAYBOOK_DRILL",
            scheduled_at=future, status="RUNNING",
        )
        fake_session.put(drill)

        completed = await svc.complete_drill(
            fake_session, "drill_TEST",
            pir_s3_key="s3://bucket/pir/drill_TEST.pdf",
            request_id=request_id,
        )
        assert completed.status == "COMPLETED"
        assert completed.completed_at is not None
        assert completed.pir_s3_key == "s3://bucket/pir/drill_TEST.pdf"

    async def test_complete_nonexistent_drill_raises(self, svc, fake_session, request_id):
        with pytest.raises(ValueError, match="not found"):
            await svc.complete_drill(fake_session, "drill_GHOST", request_id=request_id)
