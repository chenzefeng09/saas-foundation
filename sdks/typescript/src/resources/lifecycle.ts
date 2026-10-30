/**
 * Lifecycle resource — recycle bin, legal holds and their four-eyes approvals.
 * Mirrors Python SDK foundation_sdk/resources/lifecycle.py
 *
 * Restore, hard delete and release are recorded against the caller: the service takes
 * who acted from the authenticated context (X-User-Id), never from the request, so
 * these methods take no actor. Hard delete and release take a second person: they only
 * open an approval request, which another user carries out with `approveRequest`.
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

  /**
   * Ask for a hold to be released; it is released once another user approves.
   * Returns `{released: false, approval_request}`, the request to approve, or
   * `{released: true}` if the hold is already released. The service records the
   * context user as the requester and, once approved, as the releaser.
   */
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
   * Ask for a recycle-bin entry to be hard-deleted now; it is destroyed once another user
   * approves. Returns `{destroyed: false, approval_request}`, the request to approve, or
   * `{destroyed: true}` if the entry is already destroyed. The service records the context
   * user as the requester and, once approved, as the one who destroyed it; the approver is
   * the witness the destruction certificate names.
   */
  async purgeFromBin(binId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/recycle-bin/${binId}:hard-delete`);
  }

  // --- Four-eyes approvals ---

  /**
   * Approval requests, newest first: `{items, next_cursor}`.
   * A pending request whose window has closed is `EXPIRED`.
   */
  async listApprovalRequests(params?: {
    status?: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
    operation?: "HARD_DELETE" | "RELEASE_LEGAL_HOLD";
    limit?: number;
    cursor?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/lifecycle/v1/approval-requests", {
      params: {
        "filter.status": params?.status,
        "filter.operation": params?.operation,
        limit: params?.limit ?? 50,
        cursor: params?.cursor,
      },
    });
  }

  async getApprovalRequest(approvalId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/lifecycle/v1/approval-requests/${approvalId}`);
  }

  /**
   * Approve as the second person, which carries the request out now: the entry is
   * destroyed, with the context user as the certificate's witness, or the hold released.
   * The service refuses the requester's own approval (403) and a request that was already
   * decided or has expired (409).
   */
  async approveRequest(approvalId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/approval-requests/${approvalId}/approve`);
  }

  /**
   * Turn a request down; nothing is destroyed or released. The requester may withdraw
   * their own request this way.
   */
  async rejectRequest(approvalId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/lifecycle/v1/approval-requests/${approvalId}/reject`);
  }
}
