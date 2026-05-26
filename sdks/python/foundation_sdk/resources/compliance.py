"""Compliance resource — ROPA, DPIA, DSAR, compliance reports."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class ComplianceResource:
    """Regulatory compliance: ROPA records, DPIA assessments, DSAR requests, reports."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- ROPA ---

    def record_processing(self, *, service: str, data_category: str, purpose: str,
                           legal_basis: str, data_subjects: list[str],
                           recipients: list[str], retention_days: int = 365,
                           cross_border: bool = False,
                           destination_countries: list[str] | None = None) -> dict[str, Any]:
        return self._t.request("POST", "/api/compliance/v1/ropa",
                                json={"service": service, "data_category": data_category,
                                      "purpose": purpose, "legal_basis": legal_basis,
                                      "data_subjects": data_subjects,
                                      "recipients": recipients,
                                      "retention_days": retention_days,
                                      "cross_border": cross_border,
                                      "destination_countries": destination_countries or []})

    def list_ropa(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/compliance/v1/ropa")

    # --- DPIA ---

    def assess_dpia(self, *, project_name: str, description: str,
                     data_categories: list[str], risks: list[dict[str, str]],
                     mitigations: list[dict[str, str]]) -> dict[str, Any]:
        return self._t.request("POST", "/api/compliance/v1/dpia",
                                json={"project_name": project_name,
                                      "description": description,
                                      "data_categories": data_categories,
                                      "risks": risks, "mitigations": mitigations})

    def complete_dpia(self, *, dpia_id: str, conclusion: str,
                       residual_risks: str) -> dict[str, Any]:
        return self._t.request("POST", f"/api/compliance/v1/dpia/{dpia_id}/complete",
                                json={"conclusion": conclusion,
                                      "residual_risks": residual_risks})

    # --- DSAR ---

    def request_dsar(self, *, user_id: str, request_type: str, details: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/compliance/v1/dsar",
                                json={"user_id": user_id, "request_type": request_type,
                                      "details": details})

    def get_dsar_status(self, dsar_id: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/compliance/v1/dsar/{dsar_id}")

    # --- Reports ---

    def generate_report(self, *, report_type: str,
                         compliance_modes: list[str]) -> dict[str, Any]:
        return self._t.request("POST", "/api/compliance/v1/reports",
                                json={"report_type": report_type,
                                      "compliance_modes": compliance_modes})

    def list_reports(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/compliance/v1/reports")
