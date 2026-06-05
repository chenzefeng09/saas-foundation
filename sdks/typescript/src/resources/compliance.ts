/**
 * Compliance resource — ROPA, DPIA, DSAR, compliance reports.
 * Mirrors Python SDK foundation_sdk/resources/compliance.py
 */

import type { Transport } from "../transport.js";

export class ComplianceResource {
  constructor(private readonly t: Transport) {}

  // --- ROPA ---

  async recordProcessing(params: {
    service: string;
    dataCategory: string;
    purpose: string;
    legalBasis: string;
    dataSubjects: string[];
    recipients: string[];
    retentionDays?: number;
    crossBorder?: boolean;
    destinationCountries?: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/compliance/v1/ropa", {
      json: {
        service: params.service,
        data_category: params.dataCategory,
        purpose: params.purpose,
        legal_basis: params.legalBasis,
        data_subjects: params.dataSubjects,
        recipients: params.recipients,
        retention_days: params.retentionDays ?? 365,
        cross_border: params.crossBorder ?? false,
        destination_countries: params.destinationCountries ?? [],
      },
    });
  }

  async listRopa(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/compliance/v1/ropa");
  }

  // --- DPIA ---

  async assessDpia(params: {
    projectName: string;
    description: string;
    dataCategories: string[];
    risks: Array<Record<string, string>>;
    mitigations: Array<Record<string, string>>;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/compliance/v1/dpia", {
      json: {
        project_name: params.projectName,
        description: params.description,
        data_categories: params.dataCategories,
        risks: params.risks,
        mitigations: params.mitigations,
      },
    });
  }

  async completeDpia(params: {
    dpiaId: string;
    conclusion: string;
    residualRisks: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/compliance/v1/dpia/${params.dpiaId}/complete`, {
      json: {
        conclusion: params.conclusion,
        residual_risks: params.residualRisks,
      },
    });
  }

  // --- DSAR ---

  async requestDsar(params: {
    userId: string;
    requestType: string;
    details: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/compliance/v1/dsar", {
      json: {
        user_id: params.userId,
        request_type: params.requestType,
        details: params.details,
      },
    });
  }

  async getDsarStatus(dsarId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/compliance/v1/dsar/${dsarId}`);
  }

  // --- Reports ---

  async generateReport(params: {
    reportType: string;
    complianceModes: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/compliance/v1/reports", {
      json: {
        report_type: params.reportType,
        compliance_modes: params.complianceModes,
      },
    });
  }

  async listReports(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/compliance/v1/reports");
  }
}
