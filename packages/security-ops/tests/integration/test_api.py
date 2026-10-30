"""Every public endpoint, over HTTP, against Postgres."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from foundation_security_ops.domain.models import (
    Incident,
    Outbox,
    SbomRecord,
    ScanRun,
    Vulnerability,
)
from foundation_security_ops.services import security_ops_service
from foundation_security_ops.services.sbom_adapter import SbomToolUnavailable
from tests.integration._support import as_actor, new_request_id

pytestmark = pytest.mark.integration

SARIF_KEY = "foundation-artifacts::platform/security-ops/sarif/semgrep.sarif"
PIR_KEY = "foundation-artifacts::platform/security-ops/pir/inc.md"


def _iso(dt: datetime) -> str:
    return dt.isoformat()


async def _events(request_id: str) -> list[str]:
    async with as_actor("SERVICE") as session:
        rows = await session.scalars(
            select(Outbox.event_type).where(Outbox.request_id == request_id)
        )
        return sorted(rows.all())


async def _report_scan(client: httpx.AsyncClient, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": "sast",
        "tool": "semgrep",
        "target": "repo:saas-foundation",
        "commit_sha": "0123abcd",
        "pipeline_id": "gha-42",
        "started_at": _iso(datetime.now(UTC)),
        "status": "passed",
        "findings_count": {},
    }
    body.update(overrides)
    resp = await client.post("/scans/runs", json=body)
    assert resp.status_code == 201, resp.text
    data: dict[str, Any] = resp.json()
    return data


# ─── Scan runs → vulnerabilities ─────────────────────────────────────────────


async def test_failed_scan_opens_a_vuln_per_blocking_severity(client: httpx.AsyncClient) -> None:
    rid = new_request_id()
    resp = await client.post(
        "/scans/runs",
        json={
            "type": "sast",
            "tool": "semgrep",
            "target": "repo:saas-foundation",
            "started_at": _iso(datetime.now(UTC)),
            "status": "failed",
            "sarif_s3_key": SARIF_KEY,
            "findings_count": {"critical": 1, "high": 2, "medium": 5},
        },
        headers={"X-Request-Id": rid},
    )
    assert resp.status_code == 201
    assert resp.headers["X-Request-Id"] == rid
    scan_id = resp.json()["scan_id"]
    assert resp.json()["vulnerabilities_opened"] == 2

    vulns = (await client.get("/vulnerabilities")).json()["items"]
    # Ordered by due_at: CRITICAL (24h SLA) before HIGH (7d).
    assert [v["severity"] for v in vulns] == ["CRITICAL", "HIGH"]
    assert {v["source"] for v in vulns} == {"SAST"}
    assert {v["source_ref"] for v in vulns} == {scan_id}
    assert {v["status"] for v in vulns} == {"OPEN"}
    due = [
        datetime.fromisoformat(v["due_at"]) - datetime.fromisoformat(v["found_at"]) for v in vulns
    ]
    assert due == [timedelta(days=1), timedelta(days=7)]

    assert await _events(rid) == [
        "foundation.security_ops.scan.failed",
        "foundation.security_ops.vuln.opened",
        "foundation.security_ops.vuln.opened",
    ]
    async with as_actor("SERVICE") as session:
        scan = await session.get(ScanRun, scan_id)
    assert scan is not None
    assert scan.s3_location == json.dumps([SARIF_KEY])


async def test_passing_scan_opens_nothing(client: httpx.AsyncClient) -> None:
    data = await _report_scan(client, findings_count={"medium": 3, "low": 9})
    assert data["vulnerabilities_opened"] == 0
    assert (await client.get("/vulnerabilities")).json()["items"] == []


async def test_unknown_scan_type_files_vulns_as_sast(client: httpx.AsyncClient) -> None:
    await _report_scan(client, type="license", findings_count={"high": 1})
    vulns = (await client.get("/vulnerabilities")).json()["items"]
    assert [v["source"] for v in vulns] == ["SAST"]


async def test_scan_run_filters(client: httpx.AsyncClient) -> None:
    sast = (await _report_scan(client, type="sast", status="passed"))["scan_id"]
    sca = (await _report_scan(client, type="sca", status="failed"))["scan_id"]

    async def ids(**params: str) -> list[str]:
        resp = await client.get("/scans/runs", params=params)
        assert resp.status_code == 200
        return [r["id"] for r in resp.json()["items"]]

    assert set(await ids()) == {sast, sca}
    assert await ids(**{"filter.type": "sca"}) == [sca]
    assert await ids(**{"filter.status": "PASSED"}) == [sast]
    assert await ids(**{"filter.type": "sast", "filter.status": "failed"}) == []


# ─── Vulnerabilities ─────────────────────────────────────────────────────────


async def _one_vuln(client: httpx.AsyncClient) -> str:
    await _report_scan(client, findings_count={"high": 1})
    vulns = (await client.get("/vulnerabilities")).json()["items"]
    assert len(vulns) == 1
    vuln_id: str = vulns[0]["id"]
    return vuln_id


async def test_vulnerability_triage_to_close(client: httpx.AsyncClient) -> None:
    vuln_id = await _one_vuln(client)

    resp = await client.get(f"/vulnerabilities/{vuln_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "OPEN"

    resp = await client.patch(
        f"/vulnerabilities/{vuln_id}",
        json={
            "status": "in_fix",
            "assignee": "alice@example.com",
            "fix_pr_url": "https://git.example.com/foundation/pull/7",
            "notes_md": "Bump the parser.",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert (body["status"], body["assignee"], body["closed_at"]) == (
        "IN_FIX",
        "alice@example.com",
        None,
    )

    rid = new_request_id()
    resp = await client.patch(
        f"/vulnerabilities/{vuln_id}", json={"status": "closed"}, headers={"X-Request-Id": rid}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "CLOSED"
    assert resp.json()["closed_at"] is not None
    assert await _events(rid) == ["foundation.security_ops.vuln.closed"]

    stored = (await client.get(f"/vulnerabilities/{vuln_id}")).json()
    assert (stored["status"], stored["notes_md"]) == ("CLOSED", "Bump the parser.")
    closed = (await client.get("/vulnerabilities", params={"filter.status": "closed"})).json()
    assert [v["id"] for v in closed["items"]] == [vuln_id]


async def test_vulnerability_list_filters(client: httpx.AsyncClient) -> None:
    now = datetime.now(UTC)
    async with as_actor("SERVICE") as session:
        session.add_all(
            [
                Vulnerability(
                    id="vuln_PENTEST",
                    source="PENTEST",
                    title="IDOR on /exports",
                    severity="HIGH",
                    status="TRIAGED",
                    package_affected=None,
                    found_at=now,
                    due_at=now + timedelta(days=7),
                ),
                Vulnerability(
                    id="vuln_SCA",
                    source="SCA",
                    cve_id="CVE-2026-0001",
                    title="jinja2 sandbox escape",
                    severity="CRITICAL",
                    status="OPEN",
                    package_affected="jinja2",
                    cvss_score=9.8,
                    found_at=now,
                    due_at=now + timedelta(days=1),
                ),
            ]
        )

    async def ids(**params: str) -> list[str]:
        resp = await client.get("/vulnerabilities", params=params)
        assert resp.status_code == 200
        return [v["id"] for v in resp.json()["items"]]

    assert await ids() == ["vuln_SCA", "vuln_PENTEST"]
    assert await ids(**{"filter.severity": "high"}) == ["vuln_PENTEST"]
    assert await ids(**{"filter.status": "open"}) == ["vuln_SCA"]
    assert await ids(**{"filter.package_affected": "jinja2"}) == ["vuln_SCA"]
    assert await ids(**{"filter.source": "pentest"}) == ["vuln_PENTEST"]
    sca = (await client.get("/vulnerabilities/vuln_SCA")).json()
    assert (sca["cve_id"], sca["cvss_score"]) == ("CVE-2026-0001", 9.8)


async def test_risk_acceptance(client: httpx.AsyncClient) -> None:
    vuln_id = await _one_vuln(client)

    resp = await client.post(
        f"/vulnerabilities/{vuln_id}/risk-accept",
        json={"rationale": "too short", "mitigations": []},
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "FOUNDATION.SECURITY_OPS.INPUT.VALIDATION_FAILED"

    rid = new_request_id()
    resp = await client.post(
        f"/vulnerabilities/{vuln_id}/risk-accept",
        json={
            "rationale": "The vulnerable endpoint is unreachable behind the WAF allow-list.",
            "mitigations": ["waf-rule-17"],
            "expires_at": _iso(datetime.now(UTC) + timedelta(days=30)),
        },
        headers={"X-Request-Id": rid},
    )
    assert resp.status_code == 202
    approval_id = resp.json()["approval_id"]
    assert approval_id.startswith("rapproval_")

    stored = (await client.get(f"/vulnerabilities/{vuln_id}")).json()
    assert (stored["status"], stored["risk_acceptance_id"]) == ("RISK_ACCEPTED", approval_id)
    assert await _events(rid) == ["foundation.security_ops.vuln.risk_accepted"]


async def test_sla_dashboard(client: httpx.AsyncClient) -> None:
    now = datetime.now(UTC)
    async with as_actor("SERVICE") as session:
        session.add_all(
            [
                # Open and 3 days past its 7-day SLA.
                Vulnerability(
                    id="vuln_OVERDUE",
                    source="PENTEST",
                    title="overdue",
                    severity="HIGH",
                    status="IN_FIX",
                    assignee="bob@example.com",
                    found_at=now - timedelta(days=10),
                    due_at=now - timedelta(days=3),
                ),
                # Open, within SLA, nobody assigned.
                Vulnerability(
                    id="vuln_FRESH",
                    source="SCA",
                    title="fresh",
                    severity="CRITICAL",
                    status="OPEN",
                    found_at=now,
                    due_at=now + timedelta(days=1),
                ),
                # Closed after 2 days: feeds MTTR, not the open counts.
                Vulnerability(
                    id="vuln_CLOSED",
                    source="SAST",
                    title="closed",
                    severity="MEDIUM",
                    status="CLOSED",
                    found_at=now - timedelta(days=4),
                    due_at=now + timedelta(days=26),
                    closed_at=now - timedelta(days=2),
                ),
                # Accepted risk is neither open nor closed.
                Vulnerability(
                    id="vuln_ACCEPTED",
                    source="SAST",
                    title="accepted",
                    severity="LOW",
                    status="RISK_ACCEPTED",
                    found_at=now - timedelta(days=90),
                    due_at=now - timedelta(days=30),
                ),
            ]
        )

    resp = await client.get("/vulnerabilities/sla-dashboard")
    assert resp.status_code == 200
    assert resp.json() == {
        "overdue_by_severity": {"HIGH": 1},
        "by_owner": {"bob@example.com": {"HIGH": 1}, "unassigned": {"CRITICAL": 1}},
        "mttr_days": {"MEDIUM": 2.0},
    }


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/vulnerabilities/vuln_MISSING", None),
        ("PATCH", "/vulnerabilities/vuln_MISSING", {"status": "closed"}),
        (
            "POST",
            "/vulnerabilities/vuln_MISSING/risk-accept",
            {"rationale": "x" * 40, "mitigations": []},
        ),
    ],
)
async def test_missing_vulnerability_is_404(
    client: httpx.AsyncClient, method: str, path: str, body: dict[str, Any] | None
) -> None:
    resp = await client.request(method, path, json=body)
    assert resp.status_code == 404
    assert resp.json()["code"] == "FOUNDATION.SECURITY_OPS.VULN.NOT_FOUND"


# ─── SBOM ────────────────────────────────────────────────────────────────────


async def test_sbom_for_image_is_recorded(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CI runners have no syft; pin the documented fallback rather than depend on the
    # runner image (with syft present this would pull and scan a real image).
    def _no_syft(*_args: object, **_kwargs: object) -> bytes:
        raise SbomToolUnavailable("syft not found on PATH")

    monkeypatch.setattr(security_ops_service, "_syft_generate", _no_syft)
    image = "registry.example.com/foundation/security-ops:1.0.0"
    rid = new_request_id()

    resp = await client.get(f"/sbom/images/{image}", headers={"X-Request-Id": rid})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/vnd.cyclonedx+json"
    doc = resp.json()
    assert (doc["bomFormat"], doc["metadata"]["component"]["name"]) == ("CycloneDX", image)

    async with as_actor("SERVICE") as session:
        records = (await session.scalars(select(SbomRecord))).all()
    assert [(r.image_ref, r.format, r.generator_tool, r.component_count) for r in records] == [
        (image, "CycloneDX", "syft-stub", 0)
    ]
    assert await _events(rid) == ["foundation.security_ops.sbom.generated"]


async def test_sbom_watch_registration_is_an_upsert(client: httpx.AsyncClient) -> None:
    image = "registry.example.com/foundation/identity:2.3.1"
    first = await client.post("/sbom/watch", json={"image_ref": image, "notify": ["#sec-alerts"]})
    assert first.status_code == 201
    assert first.json()["new_cves_count"] == 0

    again = await client.post("/sbom/watch", json={"image_ref": image, "notify": ["#sec-oncall"]})
    assert again.status_code == 201
    assert again.json()["registered_at"] == first.json()["registered_at"]

    other = "registry.example.com/foundation/authz:2.3.1"
    assert (await client.post("/sbom/watch", json={"image_ref": other})).status_code == 201

    watches = (await client.get("/sbom/watch")).json()
    assert sorted((w["image_ref"], w["notify"]) for w in watches) == [
        (other, []),
        (image, ["#sec-oncall"]),
    ]


# ─── Incidents ───────────────────────────────────────────────────────────────


async def test_incident_lifecycle(client: httpx.AsyncClient) -> None:
    rid = new_request_id()
    resp = await client.post(
        "/incidents",
        json={
            "severity": "high",
            "category": "data_breach",
            "title": "Leaked API token in build logs",
            "affected_tenants": ["tnt_01J00000000000000000000001"],
        },
        headers={"X-Request-Id": rid},
    )
    assert resp.status_code == 201
    inc = resp.json()
    assert (inc["severity"], inc["category"], inc["status"], inc["reported_by"]) == (
        "HIGH",
        "DATA_BREACH",
        "DETECTED",
        rid,
    )
    assert await _events(rid) == ["foundation.security_ops.incident.declared"]
    inc_id = inc["id"]

    assert (await client.get(f"/incidents/{inc_id}")).json() == inc

    resp = await client.patch(
        f"/incidents/{inc_id}",
        json={"status": "contained", "ic": "carol@example.com", "customers_notified": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert (body["status"], body["ic"], body["customers_notified"]) == (
        "CONTAINED",
        "carol@example.com",
        True,
    )
    assert body["containment_at"] is not None
    assert body["regulators_notified"] is None

    resp = await client.post(
        f"/incidents/{inc_id}/resolve", json={"root_cause": "too short", "pir_s3_key": PIR_KEY}
    )
    assert resp.status_code == 422

    rid = new_request_id()
    resp = await client.post(
        f"/incidents/{inc_id}/resolve",
        json={
            "root_cause": "CI printed the deploy token; masking was disabled in the job.",
            "pir_s3_key": PIR_KEY,
        },
        headers={"X-Request-Id": rid},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert (body["status"], body["pir_s3_key"]) == ("RESOLVED", PIR_KEY)
    assert body["resolved_at"] is not None
    assert await _events(rid) == ["foundation.security_ops.incident.resolved"]
    async with as_actor("SERVICE") as session:
        stored = await session.get(Incident, inc_id)
    assert stored is not None
    assert stored.s3_location == json.dumps([PIR_KEY])
    assert stored.affected_tenants == ["tnt_01J00000000000000000000001"]


async def test_incident_list_filters(client: httpx.AsyncClient) -> None:
    async def declare(severity: str) -> str:
        resp = await client.post(
            "/incidents", json={"severity": severity, "category": "outage", "title": severity}
        )
        assert resp.status_code == 201
        inc_id: str = resp.json()["id"]
        return inc_id

    low = await declare("low")
    critical = await declare("critical")
    await client.patch(f"/incidents/{critical}", json={"status": "investigating"})

    async def ids(**params: str) -> set[str]:
        resp = await client.get("/incidents", params=params)
        assert resp.status_code == 200
        return {i["id"] for i in resp.json()["items"]}

    assert await ids() == {low, critical}
    assert await ids(**{"filter.severity": "critical"}) == {critical}
    assert await ids(**{"filter.status": "detected"}) == {low}


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/incidents/inc_MISSING", None),
        ("PATCH", "/incidents/inc_MISSING", {"status": "contained"}),
        ("POST", "/incidents/inc_MISSING/resolve", {"root_cause": "x" * 40, "pir_s3_key": PIR_KEY}),
    ],
)
async def test_missing_incident_is_404(
    client: httpx.AsyncClient, method: str, path: str, body: dict[str, Any] | None
) -> None:
    resp = await client.request(method, path, json=body)
    assert resp.status_code == 404
    assert resp.json()["code"] == "FOUNDATION.SECURITY_OPS.INCIDENT.NOT_FOUND"


# ─── Drills ──────────────────────────────────────────────────────────────────


async def test_drill_scheduling_and_filter(client: httpx.AsyncClient) -> None:
    when = datetime.now(UTC) + timedelta(days=14)
    resp = await client.post(
        "/drills",
        json={
            "kind": "tabletop",
            "scheduled_at": _iso(when),
            "participants": ["alice@example.com", "bob@example.com"],
            "scenario_runbook": "runbooks/ransomware.md",
        },
    )
    assert resp.status_code == 201
    drill = resp.json()
    assert (drill["kind"], drill["status"], drill["completed_at"]) == (
        "TABLETOP",
        "SCHEDULED",
        None,
    )
    assert datetime.fromisoformat(drill["scheduled_at"]) == when

    red = await client.post("/drills", json={"kind": "red_blue_team", "scheduled_at": _iso(when)})
    assert red.status_code == 201

    tabletop = (await client.get("/drills", params={"filter.kind": "TABLETOP"})).json()["items"]
    assert tabletop == [drill]
    assert len((await client.get("/drills")).json()["items"]) == 2


# ─── DELETE ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("/scans/runs/scan_MISSING", "FOUNDATION.SECURITY_OPS.SCAN.NOT_FOUND"),
        ("/incidents/inc_MISSING", "FOUNDATION.SECURITY_OPS.INCIDENT.NOT_FOUND"),
        ("/drills/drill_MISSING", "FOUNDATION.SECURITY_OPS.DRILL.NOT_FOUND"),
    ],
)
async def test_delete_of_missing_row_is_404(
    client: httpx.AsyncClient, path: str, code: str
) -> None:
    resp = await client.delete(path)
    assert resp.status_code == 404
    assert resp.json()["code"] == code
