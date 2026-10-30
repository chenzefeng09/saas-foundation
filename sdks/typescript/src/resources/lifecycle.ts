/**
 * Lifecycle resource — recycle bin and legal holds.
 * Mirrors Python SDK foundation_sdk/resources/lifecycle.py
 *
 * Restore, hard delete and release are recorded against the caller: the service takes
 * who acted from the authenticated context (X-User-Id), never from the request, so
 * these methods take no actor.
 */

import type { Transport } from "../transport.js";

export class LifecycleResource {
  constructor(private readonly t: Transport) {}

  // --- Legal Hold ---

  /** Place a hold on one resource. `reason` must be at least 10 characters. Returns `{hold_id, status}`. */
  async markLegalHold(params: {
    resourceType: string;
    resourceId: string;
    reason: string;
    caseReference?: string;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      resource_type_id: params.resourceType,
      resource_id: params.resourceId,
      reason: params.reason,
    };
    if (params.caseReference != null) body["case_reference"] = params.caseReference;
    return this.t.request("POST", "/api/lifecycle/v1/legal-holds", { json: body });
  }

  /** Release a hold; the service records the context user as the releaser. */
  async releaseLegalHold(holdId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/legal-holds/${holdId}:release`);
  }

  async listLegalHolds(params?: { resourceId?: string }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/lifecycle/v1/legal-holds", {
      params: { "filter.resource_id": params?.resourceId },
    });
  }

  // --- Recycle Bin ---

  async listRecycleBin(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/lifecycle/v1/recycle-bin");
  }

  /**
   * Restore a recycle-bin entry (`binId` from `listRecycleBin`, not the resource id).
   * The service records the context user as the restorer.
   */
  async restoreFromBin(binId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/recycle-bin/${binId}:restore`);
  }

  /**
   * Hard-delete a recycle-bin entry; the service records the context user as the one
   * who destroyed it. A destruction certificate names no witness.
   */
  async purgeFromBin(binId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/recycle-bin/${binId}:hard-delete`);
  }
}
