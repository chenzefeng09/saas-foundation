/**
 * Security Operations resource.
 * Mirrors Python SDK foundation_sdk/resources/security_ops.py
 *
 * Exposes:
 *   reportIncident()          — declare an IR event
 *   getVulnerabilityStatus()  — retrieve vulnerability details / list
 *   generateSbom()            — request CycloneDX SBOM for an image
 * Plus full security-ops API surface.
 */

import type { Transport } from "../transport.js";

export class SecurityOpsResource {
  constructor(private readonly t: Transport) {}

  // ── Core SDK methods ──────────────────────────────────────────────────────

  async reportIncident(params: {
    severity: string;
    category: string;
    title: string;
    ic?: string;
    affectedTenants?: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/security-ops/v1/incidents", {
      json: {
        severity: params.severity,
        category: params.category,
        title: params.title,
        ic: params.ic ?? null,
        affected_tenants: params.affectedTenants ?? [],
      },
    });
  }

  async getVulnerabilityStatus(
    vulnId: string | null,
    filters?: {
      severity?: string;
      status?: string;
      source?: string;
    },
  ): Promise<Record<string, unknown>> {
    if (vulnId != null) {
      return this.t.request("GET", `/api/security-ops/v1/vulnerabilities/${vulnId}`);
    }
    return this.t.request("GET", "/api/security-ops/v1/vulnerabilities", {
      params: {
        "filter.severity": filters?.severity,
        "filter.status": filters?.status,
        "filter.source": filters?.source,
      },
    });
  }

  async generateSbom(imageRef: string): Promise<Record<string, unknown>> {
    const encoded = encodeURIComponent(imageRef);
    return this.t.request("GET", `/api/security-ops/v1/sbom/images/${encoded}`);
  }

  // ── Scan runs ─────────────────────────────────────────────────────────────

  async reportScanRun(params: {
    type: string;
    tool: string;
    target: string;
    startedAt: string;
    status: string;
    findingsCount?: Record<string, number>;
    commitSha?: string;
    pipelineId?: string;
    finishedAt?: string;
    sarifS3Key?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/security-ops/v1/scans/runs", {
      json: {
        type: params.type,
        tool: params.tool,
        target: params.target,
        started_at: params.startedAt,
        status: params.status,
        findings_count: params.findingsCount ?? {},
        commit_sha: params.commitSha ?? null,
        pipeline_id: params.pipelineId ?? null,
        finished_at: params.finishedAt ?? null,
        sarif_s3_key: params.sarifS3Key ?? null,
      },
    });
  }

  async listScanRuns(filters?: {
    type?: string;
    status?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/security-ops/v1/scans/runs", {
      params: {
        "filter.type": filters?.type,
        "filter.status": filters?.status,
      },
    });
  }

  // ── Vulnerabilities ───────────────────────────────────────────────────────

  async updateVulnerability(
    vulnId: string,
    params: {
      status?: string;
      assignee?: string;
      fixPrUrl?: string;
      notesMd?: string;
    },
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {};
    if (params.status != null) body["status"] = params.status;
    if (params.assignee != null) body["assignee"] = params.assignee;
    if (params.fixPrUrl != null) body["fix_pr_url"] = params.fixPrUrl;
    if (params.notesMd != null) body["notes_md"] = params.notesMd;
    return this.t.request("PATCH", `/api/security-ops/v1/vulnerabilities/${vulnId}`, {
      json: body,
    });
  }

  async requestRiskAcceptance(
    vulnId: string,
    params: {
      rationale: string;
      mitigations: string[];
      expiresAt?: string;
    },
  ): Promise<Record<string, unknown>> {
    return this.t.request(
      "POST",
      `/api/security-ops/v1/vulnerabilities/${vulnId}/risk-accept`,
      {
        json: {
          rationale: params.rationale,
          mitigations: params.mitigations,
          expires_at: params.expiresAt ?? null,
        },
      },
    );
  }

  async slaDashboard(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/security-ops/v1/vulnerabilities/sla-dashboard");
  }

  // ── SBOM ──────────────────────────────────────────────────────────────────

  async registerSbomWatch(params: {
    imageRef: string;
    notify?: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/security-ops/v1/sbom/watch", {
      json: { image_ref: params.imageRef, notify: params.notify ?? [] },
    });
  }

  async listSbomWatches(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/security-ops/v1/sbom/watch");
  }

  // ── Incidents ─────────────────────────────────────────────────────────────

  async updateIncident(
    incId: string,
    params: {
      status?: string;
      ic?: string;
      customersNotified?: boolean;
      regulatorsNotified?: boolean;
    },
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {};
    if (params.status != null) body["status"] = params.status;
    if (params.ic != null) body["ic"] = params.ic;
    if (params.customersNotified != null) body["customers_notified"] = params.customersNotified;
    if (params.regulatorsNotified != null) body["regulators_notified"] = params.regulatorsNotified;
    return this.t.request("PATCH", `/api/security-ops/v1/incidents/${incId}`, { json: body });
  }

  async resolveIncident(
    incId: string,
    params: { rootCause: string; pirS3Key: string },
  ): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/security-ops/v1/incidents/${incId}/resolve`, {
      json: { root_cause: params.rootCause, pir_s3_key: params.pirS3Key },
    });
  }

  async listIncidents(filters?: {
    severity?: string;
    status?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/security-ops/v1/incidents", {
      params: {
        "filter.severity": filters?.severity,
        "filter.status": filters?.status,
      },
    });
  }

  // ── Drills ────────────────────────────────────────────────────────────────

  async scheduleDrill(params: {
    kind: string;
    scheduledAt: string;
    participants?: string[];
    scenarioRunbook?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/security-ops/v1/drills", {
      json: {
        kind: params.kind,
        scheduled_at: params.scheduledAt,
        participants: params.participants ?? [],
        scenario_runbook: params.scenarioRunbook ?? null,
      },
    });
  }

  async listDrills(filters?: { kind?: string }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/security-ops/v1/drills", {
      params: { "filter.kind": filters?.kind },
    });
  }
}
