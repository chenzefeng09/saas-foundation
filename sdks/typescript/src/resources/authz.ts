/**
 * Authz resource — RBAC + OPA authorization checks.
 * Mirrors Python SDK foundation_sdk/resources/authz.py
 */

import type { Transport } from "../transport.js";

export class AuthzResource {
  constructor(private readonly t: Transport) {}

  // --- Permission Check ---

  async check(params: {
    action: string;
    resourceType: string;
    resourceId?: string;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      action: params.action,
      resource_type: params.resourceType,
    };
    if (params.resourceId != null) body["resource_id"] = params.resourceId;
    return this.t.request("POST", "/api/authz/v1/check", { json: body });
  }

  // --- Roles ---

  async listRoles(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/authz/v1/roles");
  }

  async createRole(params: {
    name: string;
    permissions: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/authz/v1/roles", {
      json: { name: params.name, permissions: params.permissions },
    });
  }

  async bindRole(params: {
    userId: string;
    roleName: string;
    scope?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/authz/v1/bindings", {
      json: {
        user_id: params.userId,
        role: params.roleName,
        scope: params.scope ?? "tenant",
      },
    });
  }

  async listPermissions(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/authz/v1/permissions");
  }
}
