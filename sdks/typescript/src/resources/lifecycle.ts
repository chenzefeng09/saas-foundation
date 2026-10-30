/**
 * Lifecycle resource — retention, recycle bin, legal hold, data destruction.
 * Mirrors Python SDK foundation_sdk/resources/lifecycle.py
 */

import type { Transport } from "../transport.js";

export class LifecycleResource {
  constructor(private readonly t: Transport) {}

  // --- Legal Hold ---

  async markLegalHold(params: {
    resourceType: string;
    resourceId: string;
    reason: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/lifecycle/v1/legal-holds", {
      json: {
        resource_type: params.resourceType,
        resource_id: params.resourceId,
        reason: params.reason,
      },
    });
  }

  async releaseLegalHold(holdId: string): Promise<Record<string, unknown>> {
    return this.t.request("DELETE", `/api/lifecycle/v1/legal-holds/${holdId}`);
  }

  async listLegalHolds(params?: { resourceId?: string }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/lifecycle/v1/legal-holds", {
      params: { "filter.resource_id": params?.resourceId },
    });
  }

  // --- Retention ---

  async setRetentionPolicy(params: {
    resourceType: string;
    retentionDays: number;
  }): Promise<Record<string, unknown>> {
    return this.t.request("PUT", "/api/lifecycle/v1/retention-policies", {
      json: {
        resource_type: params.resourceType,
        retention_days: params.retentionDays,
      },
    });
  }

  async getRetentionPolicy(resourceType: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/lifecycle/v1/retention-policies/${resourceType}`);
  }

  // --- Recycle Bin ---

  async listRecycleBin(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/lifecycle/v1/recycle-bin");
  }

  async restoreFromBin(resourceId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/recycle-bin/${resourceId}/restore`);
  }

  async purgeFromBin(resourceId: string): Promise<Record<string, unknown>> {
    return this.t.request("DELETE", `/api/lifecycle/v1/recycle-bin/${resourceId}`);
  }

  // --- Destruction Certificate ---

  async generateDestructionCertificate(resourceIds: string[]): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/lifecycle/v1/destruction-certificates", {
      json: { resource_ids: resourceIds },
    });
  }
}
