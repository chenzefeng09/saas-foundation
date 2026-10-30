"""API endpoint tests using FastAPI TestClient + in-memory service stubs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from foundation_security_ops.domain.base import foundation_context
from foundation_security_ops.domain.models import (
    Drill,
    Incident,
    SbomWatch,
    ScanRun,
    Vulnerability,
)
from foundation_security_ops.main import create_app

# ─── App factory with overridden DI ─────────────────────────────────────────


def _make_scan(id: str = "scan_TEST01", status: str = "PASSED") -> ScanRun:
    now = datetime.now(UTC)
    return ScanRun(
        id=id,
        type="SAST",
        tool="semgrep",
        target="repo:test",
        started_at=now,
        status=status,
        findings_count={"high": 0},
    )


def _make_vuln(id: str = "vuln_TEST01") -> Vulnerability:
    now = datetime.now(UTC)
    return Vulnerability(
        id=id,
        source="SAST",
        title="SQL Injection",
        severity="HIGH",
        status="OPEN",
        found_at=now,
        due_at=now + timedelta(days=7),
    )


def _make_incident(id: str = "inc_TEST01") -> Incident:
    now = datetime.now(UTC)
    return Incident(
        id=id,
        severity="HIGH",
        category="OUTAGE",
        title="DB down",
        detected_at=now,
        reported_by="oncall",
        status="DETECTED",
    )


def _make_watch(image_ref: str = "myapp:v1") -> SbomWatch:
    return SbomWatch(
        id="sbomwatch_T1",
        image_ref=image_ref,
        registered_at=datetime.now(UTC),
        notify=[],
        new_cves_count=0,
    )


def _make_drill(id: str = "drill_TEST01") -> Drill:
    return Drill(
        id=id,
        kind="TABLETOP",
        scheduled_at=datetime.now(UTC) + timedelta(days=7),
        status="SCHEDULED",
    )


# Shared client fixture — overrides DB and service DI
@pytest.fixture
def client():
    app = create_app()

    from foundation_security_ops.api.dependencies import db_session, security_ops_service

    mock_svc = MagicMock()
    mock_session = AsyncMock()

    async def _fake_db():
        yield mock_session

    app.dependency_overrides[db_session] = _fake_db
    app.dependency_overrides[security_ops_service] = lambda: mock_svc

    with TestClient(app, raise_server_exceptions=False) as c:
        c._mock_svc = mock_svc
        yield c

    app.dependency_overrides.clear()


# ─── Health ──────────────────────────────────────────────────────────────────


class TestHealth:
    def test_healthz(self, client):
        resp = client.get("/api/security-ops/v1/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"
        assert data["service"] == "security-ops"

    def test_readyz(self, client):
        resp = client.get("/api/security-ops/v1/readyz")
        assert resp.status_code == 200


# ─── Scan runs ───────────────────────────────────────────────────────────────


class TestScanRunsApi:
    def test_list_scan_runs(self, client):
        client._mock_svc.list_scan_runs = AsyncMock(return_value=[_make_scan()])
        resp = client.get("/api/security-ops/v1/scans/runs")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["id"] == "scan_TEST01"

    def test_report_scan_run(self, client):
        now = datetime.now(UTC).isoformat()
        client._mock_svc.report_scan_run = AsyncMock(return_value=(_make_scan(), []))
        resp = client.post(
            "/api/security-ops/v1/scans/runs",
            json={
                "type": "SAST",
                "tool": "semgrep",
                "target": "repo:saas-foundation",
                "started_at": now,
                "status": "PASSED",
                "findings_count": {"critical": 0, "high": 0},
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "scan_id" in data
        assert data["vulnerabilities_opened"] == 0


# ─── Vulnerabilities ─────────────────────────────────────────────────────────


class TestVulnerabilitiesApi:
    def test_list_vulnerabilities(self, client):
        client._mock_svc.list_vulnerabilities = AsyncMock(return_value=[_make_vuln()])
        resp = client.get("/api/security-ops/v1/vulnerabilities")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["severity"] == "HIGH"

    def test_get_vulnerability(self, client):
        client._mock_svc.get_vulnerability = AsyncMock(return_value=_make_vuln())
        resp = client.get("/api/security-ops/v1/vulnerabilities/vuln_TEST01")
        assert resp.status_code == 200
        assert resp.json()["id"] == "vuln_TEST01"

    def test_sla_dashboard(self, client):
        client._mock_svc.sla_dashboard = AsyncMock(
            return_value={
                "overdue_by_severity": {"CRITICAL": 2},
                "by_owner": {},
                "mttr_days": {},
            }
        )
        resp = client.get("/api/security-ops/v1/vulnerabilities/sla-dashboard")
        assert resp.status_code == 200
        assert resp.json()["overdue_by_severity"]["CRITICAL"] == 2

    def test_update_vulnerability(self, client):
        updated_vuln = _make_vuln()
        updated_vuln.assignee = "alice@example.com"
        client._mock_svc.update_vulnerability = AsyncMock(return_value=updated_vuln)
        resp = client.patch(
            "/api/security-ops/v1/vulnerabilities/vuln_TEST01",
            json={"assignee": "alice@example.com"},
        )
        assert resp.status_code == 200
        assert resp.json()["assignee"] == "alice@example.com"

    def test_risk_acceptance(self, client):
        client._mock_svc.request_risk_acceptance = AsyncMock(return_value="rapproval_XYZ")
        resp = client.post(
            "/api/security-ops/v1/vulnerabilities/vuln_TEST01/risk-accept",
            json={
                "rationale": "This is dev-only dependency not shipped in production artifacts.",
                "mitigations": ["Isolated test environment"],
            },
        )
        assert resp.status_code == 202
        assert resp.json()["approval_id"] == "rapproval_XYZ"


# ─── Incidents ───────────────────────────────────────────────────────────────


class TestIncidentsApi:
    def test_list_incidents(self, client):
        client._mock_svc.list_incidents = AsyncMock(return_value=[_make_incident()])
        resp = client.get("/api/security-ops/v1/incidents")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["severity"] == "HIGH"

    def test_declare_incident(self, client):
        client._mock_svc.declare_incident = AsyncMock(return_value=_make_incident())
        resp = client.post(
            "/api/security-ops/v1/incidents",
            json={
                "severity": "HIGH",
                "category": "OUTAGE",
                "title": "PG primary down",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "DETECTED"

    def test_get_incident(self, client):
        client._mock_svc.get_incident = AsyncMock(return_value=_make_incident())
        resp = client.get("/api/security-ops/v1/incidents/inc_TEST01")
        assert resp.status_code == 200

    def test_resolve_incident(self, client):
        resolved = _make_incident()
        resolved.status = "RESOLVED"
        resolved.resolved_at = datetime.now(UTC)
        client._mock_svc.resolve_incident = AsyncMock(return_value=resolved)
        resp = client.post(
            "/api/security-ops/v1/incidents/inc_TEST01/resolve",
            json={
                "root_cause": "Primary DB OOM-killed; standby promoted in 4 minutes.",
                "pir_s3_key": "s3://bucket/pir/inc_TEST01.pdf",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "RESOLVED"

    def test_resolve_requires_min_root_cause_length(self, client):
        resp = client.post(
            "/api/security-ops/v1/incidents/inc_TEST01/resolve",
            json={
                "root_cause": "short",  # < 20 chars, should fail validation
                "pir_s3_key": "s3://bucket/pir.pdf",
            },
        )
        assert resp.status_code == 422


# ─── SBOM ────────────────────────────────────────────────────────────────────


class TestSbomApi:
    def test_get_sbom_for_image(self, client):
        stub_bytes = b'{"bomFormat":"CycloneDX","components":[]}'
        client._mock_svc.generate_sbom = AsyncMock(
            return_value=(stub_bytes, MagicMock(id="sbom_T1", image_ref="myapp:v1"))
        )
        resp = client.get("/api/security-ops/v1/sbom/images/myapp:v1")
        assert resp.status_code == 200
        assert b"CycloneDX" in resp.content

    def test_list_watches(self, client):
        client._mock_svc.list_sbom_watches = AsyncMock(return_value=[_make_watch()])
        resp = client.get("/api/security-ops/v1/sbom/watch")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert data[0]["image_ref"] == "myapp:v1"

    def test_register_watch(self, client):
        client._mock_svc.register_sbom_watch = AsyncMock(return_value=_make_watch())
        resp = client.post(
            "/api/security-ops/v1/sbom/watch",
            json={"image_ref": "myapp:v1", "notify": ["sec@example.com"]},
        )
        assert resp.status_code == 201


# ─── Drills ──────────────────────────────────────────────────────────────────


class TestDrillsApi:
    def test_list_drills(self, client):
        client._mock_svc.list_drills = AsyncMock(return_value=[_make_drill()])
        resp = client.get("/api/security-ops/v1/drills")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["kind"] == "TABLETOP"

    def test_schedule_drill(self, client):
        client._mock_svc.schedule_drill = AsyncMock(return_value=_make_drill())
        future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        resp = client.post(
            "/api/security-ops/v1/drills",
            json={
                "kind": "TABLETOP",
                "scheduled_at": future,
                "participants": ["alice@example.com"],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["kind"] == "TABLETOP"


# ─── Delete endpoints (storage-v1 §6.2) ──────────────────────────────────────


class TestDeleteEndpoints:
    def test_delete_scan_run(self, client):
        client._mock_svc.delete_scan_run = AsyncMock(return_value=None)
        resp = client.delete("/api/security-ops/v1/scans/runs/scan_TEST01")
        assert resp.status_code == 204
        client._mock_svc.delete_scan_run.assert_awaited_once()

    def test_delete_incident(self, client):
        client._mock_svc.delete_incident = AsyncMock(return_value=None)
        resp = client.delete("/api/security-ops/v1/incidents/inc_TEST01")
        assert resp.status_code == 204
        client._mock_svc.delete_incident.assert_awaited_once()

    def test_delete_drill(self, client):
        client._mock_svc.delete_drill = AsyncMock(return_value=None)
        resp = client.delete("/api/security-ops/v1/drills/drill_TEST01")
        assert resp.status_code == 204
        client._mock_svc.delete_drill.assert_awaited_once()


# ─── Request context headers ─────────────────────────────────────────────────


class TestContextHeaders:
    def test_unknown_actor_is_rejected_before_the_route(self, client):
        client._mock_svc.list_incidents = AsyncMock(return_value=[])
        resp = client.get("/api/security-ops/v1/incidents", headers={"X-Actor": "ROOT"})
        assert resp.status_code == 400
        data = resp.json()
        assert data["code"] == "FOUNDATION.SECURITY_OPS.INPUT.INVALID_FORMAT"
        assert data["detail"] == "Invalid X-Actor"
        client._mock_svc.list_incidents.assert_not_awaited()

    @pytest.mark.parametrize("actor", ["USER", "SERVICE", "SYSTEM", "MIGRATOR", "ADMIN"])
    def test_known_actor_reaches_the_route_context(self, client, actor):
        seen = []

        async def _list_incidents(*_args, **_kwargs):
            seen.append(foundation_context.get())
            return []

        client._mock_svc.list_incidents = AsyncMock(side_effect=_list_incidents)
        resp = client.get("/api/security-ops/v1/incidents", headers={"X-Actor": actor})
        assert resp.status_code == 200
        assert [ctx.actor for ctx in seen] == [actor]

    def test_actor_defaults_to_service(self, client):
        seen = []

        async def _list_incidents(*_args, **_kwargs):
            seen.append(foundation_context.get())
            return []

        client._mock_svc.list_incidents = AsyncMock(side_effect=_list_incidents)
        resp = client.get("/api/security-ops/v1/incidents")
        assert resp.status_code == 200
        assert [ctx.actor for ctx in seen] == ["SERVICE"]

    def test_malformed_tenant_id_is_rejected(self, client):
        resp = client.get("/api/security-ops/v1/incidents", headers={"X-Tenant-Id": "acme"})
        assert resp.status_code == 400
        assert resp.json()["detail"] == "Invalid X-Tenant-Id"
