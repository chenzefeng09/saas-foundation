/**
 * Search resource — full-text search with tenant + ACL filtering.
 * Mirrors Python SDK foundation_sdk/resources/search.py
 */

import type { Transport } from "../transport.js";

export class SearchResource {
  constructor(private readonly t: Transport) {}

  async query(params: {
    q: string;
    resourceTypes?: string[];
    tags?: string[];
    cursor?: string;
    limit?: number;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      q: params.q,
      limit: params.limit ?? 20,
    };
    if (params.resourceTypes != null) body["resource_types"] = params.resourceTypes;
    if (params.tags != null) body["tags"] = params.tags;
    if (params.cursor != null) body["cursor"] = params.cursor;
    return this.t.request("POST", "/api/search/v1/query", { json: body });
  }

  async index(params: {
    resourceType: string;
    resourceId: string;
    title: string;
    content: string;
    tags?: string[];
    aclUserIds?: string[];
    metadata?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/search/v1/index", {
      json: {
        resource_type: params.resourceType,
        resource_id: params.resourceId,
        title: params.title,
        content: params.content,
        tags: params.tags ?? [],
        acl_user_ids: params.aclUserIds ?? [],
        metadata: params.metadata ?? {},
      },
    });
  }

  async deindex(resourceType: string, resourceId: string): Promise<Record<string, unknown>> {
    return this.t.request("DELETE", `/api/search/v1/index/${resourceType}/${resourceId}`);
  }
}
