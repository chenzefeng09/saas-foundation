/**
 * Audit resource — immutable audit trail querying.
 * Mirrors Python SDK foundation_sdk/resources/audit.py
 */

import type { Transport } from "../transport.js";

interface EventFilter {
  eventType?: string;
  /** Actor user id. */
  userId?: string;
  resourceId?: string;
  /** ISO-8601 lower bound on `occurred_at`. */
  since?: string;
  /** ISO-8601 upper bound on `occurred_at`. */
  until?: string;
}

function contextTenant(t: Transport): string {
  const tenantId = t.resolveContext()?.tenantId;
  if (!tenantId) throw new Error("audit calls need a FoundationContext with a tenantId");
  return tenantId;
}

/** An `AuditQuery` for the context tenant (the routes reject any other tenant). */
function queryBody(t: Transport, filter: EventFilter): Record<string, unknown> {
  const body: Record<string, unknown> = { tenant_id: contextTenant(t) };
  const fields: Array<[string, string | undefined]> = [
    ["event_type", filter.eventType],
    ["actor_user_id", filter.userId],
    ["resource_id", filter.resourceId],
    ["occurred_from", filter.since],
    ["occurred_to", filter.until],
  ];
  for (const [key, value] of fields) {
    if (value) body[key] = value;
  }
  return body;
}

export class AuditResource {
  constructor(private readonly t: Transport) {}

  /** Events of the context tenant. Returns `{items, next_cursor, total_estimate}`. */
  async query(params?: EventFilter & {
    limit?: number;
    cursor?: string;
  }): Promise<Record<string, unknown>> {
    const body = queryBody(this.t, params ?? {});
    body["limit"] = params?.limit ?? 100;
    if (params?.cursor) body["cursor"] = params.cursor;
    return this.t.request("POST", "/api/audit/v1/events:query", { json: body });
  }

  /**
   * Re-verify the hash chain and Merkle roots of the context tenant's events,
   * oldest first from `fromEventId` (or the start), at most `limit` (≤ 10000).
   */
  async verifyChain(params?: {
    service?: string;
    fromEventId?: string;
    limit?: number;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      tenant_id: contextTenant(this.t),
      limit: params?.limit ?? 1000,
    };
    if (params?.service) body["service"] = params.service;
    if (params?.fromEventId) body["from_event_id"] = params.fromEventId;
    return this.t.request("POST", "/api/audit/v1/events:verify-integrity", { json: body });
  }

  /** The matching events (at most 10000) as the content of a CSV or JSON file. */
  async export(params?: EventFilter & { format?: "csv" | "json" }): Promise<string> {
    return this.t.request<string>("POST", "/api/audit/v1/events:export", {
      params: { format: params?.format ?? "csv" },
      json: queryBody(this.t, params ?? {}),
      responseType: "text",
    });
  }
}
