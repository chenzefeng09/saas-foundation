/**
 * Lifecycle resource — recycle bin and legal holds.
 * Mirrors Python SDK foundation_sdk/resources/lifecycle.py
 */

import type { Transport } from "../transport.js";

/** `explicit`, else the context user: the routes record who acted from the body. */
function actor(t: Transport, explicit: string | undefined, field: string): string {
  const id = explicit || t.resolveContext()?.userId;
  if (!id) {
    throw new Error(`${field} is required when the FoundationContext has no userId`);
  }
  return id;
}

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

  /** Release a hold; `releasedBy` defaults to the context user. */
  async releaseLegalHold(
    holdId: string,
    params?: { releasedBy?: string },
  ): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/legal-holds/${holdId}:release`, {
      json: { released_by: actor(this.t, params?.releasedBy, "releasedBy") },
    });
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
   * Without `restoredBy` the service records the caller.
   */
  async restoreFromBin(
    binId: string,
    params?: { restoredBy?: string },
  ): Promise<Record<string, unknown>> {
    const json = params?.restoredBy != null ? { restored_by: params.restoredBy } : undefined;
    return this.t.request("POST", `/api/lifecycle/v1/recycle-bin/${binId}:restore`, { json });
  }

  /** Hard-delete a recycle-bin entry; `destroyedBy` defaults to the context user. */
  async purgeFromBin(
    binId: string,
    params?: { destroyedBy?: string; witnessUserId?: string },
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      destroyed_by: actor(this.t, params?.destroyedBy, "destroyedBy"),
    };
    if (params?.witnessUserId != null) body["witness_user_id"] = params.witnessUserId;
    return this.t.request("POST", `/api/lifecycle/v1/recycle-bin/${binId}:hard-delete`, {
      json: body,
    });
  }
}
