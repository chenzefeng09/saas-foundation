"""Security Operations resource.

Exposes the three SDK-facing methods from design doc §9:
  report_incident()          declare an IR event
  get_vulnerability_status() retrieve vulnerability details / list
  generate_sbom()            request CycloneDX SBOM for an image

Plus higher-level helpers for the full security-ops API surface.
"""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class SecurityOpsResource:
    """SSDLC / Vulnerability SLA / SBOM / Incident Response operations."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # ── Core SDK methods (design doc §9) ─────────────────────────────────────

    def report_incident(
        self,
        *,
        severity: str,
        category: str,
        title: str,
        ic: str | None = None,
        affected_tenants: list[str] | None = None,
    ) -> dict[str, Any]:
        """Declare an IR incident (SDK report_incident()).

        severity: CRITICAL / HIGH / MEDIUM / LOW
        category: DATA_BREACH / RANSOMWARE / DDOS / INSIDER / OUTAGE / OTHER
        """
        return self._t.request(
            "POST",
            "/api/security-ops/v1/incidents",
            json={
                "severity": severity,
                "category": category,
                "title": title,
                "ic": ic,
                "affected_tenants": affected_tenants or [],
            },
        )

    def get_vulnerability_status(
        self,
        vuln_id: str | None = None,
        *,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
    ) -> dict[str, Any]:
        """SDK get_vulnerability_status().

        If vuln_id is provided, returns a single Vulnerability record.
        Otherwise returns a filtered list.
        """
        if vuln_id:
            return self._t.request("GET", f"/api/security-ops/v1/vulnerabilities/{vuln_id}")

        params: dict[str, str] = {}
        if severity:
            params["filter.severity"] = severity
        if status:
            params["filter.status"] = status
        if source:
            params["filter.source"] = source
        return self._t.request("GET", "/api/security-ops/v1/vulnerabilities", params=params)

    def generate_sbom(self, image_ref: str) -> dict[str, Any]:
        """SDK generate_sbom(image_ref) -> dict (CycloneDX JSON parsed).

        The service returns CycloneDX JSON.  If Syft is unavailable on the
        server, a stub document is returned (with _stub=true in the body).
        """
        import urllib.parse

        encoded = urllib.parse.quote(image_ref, safe="")
        return self._t.request(
            "GET",
            f"/api/security-ops/v1/sbom/images/{encoded}",
        )

    # ── Scan runs ─────────────────────────────────────────────────────────────

    def report_scan_run(
        self,
        *,
        type: str,
        tool: str,
        target: str,
        started_at: str,
        status: str,
        findings_count: dict[str, int] | None = None,
        commit_sha: str | None = None,
        pipeline_id: str | None = None,
        finished_at: str | None = None,
        sarif_s3_key: str | None = None,
    ) -> dict[str, Any]:
        """CI: report a scan result.  Auto-opens vuln tickets for CRITICAL/HIGH findings."""
        return self._t.request(
            "POST",
            "/api/security-ops/v1/scans/runs",
            json={
                "type": type,
                "tool": tool,
                "target": target,
                "started_at": started_at,
                "status": status,
                "findings_count": findings_count or {},
                "commit_sha": commit_sha,
                "pipeline_id": pipeline_id,
                "finished_at": finished_at,
                "sarif_s3_key": sarif_s3_key,
            },
        )

    def list_scan_runs(
        self,
        *,
        type: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if type:
            params["filter.type"] = type
        if status:
            params["filter.status"] = status
        return self._t.request("GET", "/api/security-ops/v1/scans/runs", params=params)

    # ── Vulnerabilities ───────────────────────────────────────────────────────

    def update_vulnerability(
        self,
        vuln_id: str,
        *,
        status: str | None = None,
        assignee: str | None = None,
        fix_pr_url: str | None = None,
        notes_md: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if assignee is not None:
            body["assignee"] = assignee
        if fix_pr_url is not None:
            body["fix_pr_url"] = fix_pr_url
        if notes_md is not None:
            body["notes_md"] = notes_md
        return self._t.request(
            "PATCH",
            f"/api/security-ops/v1/vulnerabilities/{vuln_id}",
            json=body,
        )

    def request_risk_acceptance(
        self,
        vuln_id: str,
        *,
        rationale: str,
        mitigations: list[str],
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        return self._t.request(
            "POST",
            f"/api/security-ops/v1/vulnerabilities/{vuln_id}/risk-accept",
            json={
                "rationale": rationale,
                "mitigations": mitigations,
                "expires_at": expires_at,
            },
        )

    def sla_dashboard(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/security-ops/v1/vulnerabilities/sla-dashboard")

    # ── SBOM ──────────────────────────────────────────────────────────────────

    def register_sbom_watch(
        self,
        image_ref: str,
        *,
        notify: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._t.request(
            "POST",
            "/api/security-ops/v1/sbom/watch",
            json={"image_ref": image_ref, "notify": notify or []},
        )

    def list_sbom_watches(self) -> list[dict[str, Any]]:
        return self._t.request("GET", "/api/security-ops/v1/sbom/watch")

    # ── Incidents ─────────────────────────────────────────────────────────────

    def update_incident(
        self,
        inc_id: str,
        *,
        status: str | None = None,
        ic: str | None = None,
        customers_notified: bool | None = None,
        regulators_notified: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if ic is not None:
            body["ic"] = ic
        if customers_notified is not None:
            body["customers_notified"] = customers_notified
        if regulators_notified is not None:
            body["regulators_notified"] = regulators_notified
        return self._t.request(
            "PATCH",
            f"/api/security-ops/v1/incidents/{inc_id}",
            json=body,
        )

    def resolve_incident(
        self,
        inc_id: str,
        *,
        root_cause: str,
        pir_s3_key: str,
    ) -> dict[str, Any]:
        return self._t.request(
            "POST",
            f"/api/security-ops/v1/incidents/{inc_id}/resolve",
            json={"root_cause": root_cause, "pir_s3_key": pir_s3_key},
        )

    def list_incidents(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if severity:
            params["filter.severity"] = severity
        if status:
            params["filter.status"] = status
        return self._t.request("GET", "/api/security-ops/v1/incidents", params=params)

    # ── Drills ────────────────────────────────────────────────────────────────

    def schedule_drill(
        self,
        *,
        kind: str,
        scheduled_at: str,
        participants: list[str] | None = None,
        scenario_runbook: str | None = None,
    ) -> dict[str, Any]:
        return self._t.request(
            "POST",
            "/api/security-ops/v1/drills",
            json={
                "kind": kind,
                "scheduled_at": scheduled_at,
                "participants": participants or [],
                "scenario_runbook": scenario_runbook,
            },
        )

    def list_drills(self, *, kind: str | None = None) -> dict[str, Any]:
        params: dict[str, str] = {}
        if kind:
            params["filter.kind"] = kind
        return self._t.request("GET", "/api/security-ops/v1/drills", params=params)
