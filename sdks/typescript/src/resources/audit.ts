/**
 * Audit resource — immutable audit trail querying.
 * Mirrors Python SDK foundation_sdk/resources/audit.py
 */

import type { Transport } from "../transport.js";

export class AuditResource {
  constructor(private readonly t: Transport) {}

  async query(params?: {
    eventType?: string;
    userId?: string;
    resourceId?: string;
    since?: string;
    until?: string;
    limit?: number;
    cursor?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/audit/v1/events", {
      params: {
        limit: params?.limit ?? 100,
        event_type: params?.eventType,
        user_id: params?.userId,
        resource_id: params?.resourceId,
        since: params?.since,
        until: params?.until,
        cursor: params?.cursor,
      },
    });
  }

  async getEvent(eventId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/audit/v1/events/${eventId}`);
  }

  /** Verify the hash chain and Merkle root for a set of events. */
  async verifyChain(eventIds: string[]): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/audit/v1/verify", {
      json: { event_ids: eventIds },
    });
  }

  async export(params?: {
    format?: string;
    eventType?: string;
    since?: string;
    until?: string;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { format: params?.format ?? "csv" };
    if (params?.eventType != null) body["event_type"] = params.eventType;
    if (params?.since != null) body["since"] = params.since;
    if (params?.until != null) body["until"] = params.until;
    return this.t.request("POST", "/api/audit/v1/export", { json: body });
  }
}
