/**
 * PAM resource — privileged access management: JIT elevation, 4-eyes approval.
 * Mirrors Python SDK foundation_sdk/resources/pam.py
 */

import type { Transport } from "../transport.js";

export class PAMResource {
  constructor(private readonly t: Transport) {}

  async requestElevation(params: {
    reason: string;
    durationMinutes?: number;
    targetResources?: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/pam/v1/elevations", {
      json: {
        reason: params.reason,
        duration_minutes: params.durationMinutes ?? 60,
        target_resources: params.targetResources ?? [],
      },
    });
  }

  async approveElevation(elevationId: string, params?: { justification?: string }): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/pam/v1/elevations/${elevationId}/approve`, {
      json: { justification: params?.justification ?? "" },
    });
  }

  async revokeElevation(elevationId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/pam/v1/elevations/${elevationId}/revoke`);
  }

  async listActiveSessions(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/pam/v1/sessions");
  }

  async listPendingElevations(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/pam/v1/elevations/pending");
  }

  async getElevationHistory(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/pam/v1/elevations/history");
  }
}
