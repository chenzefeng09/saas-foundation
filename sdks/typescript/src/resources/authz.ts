/**
 * Authz resource — RBAC + OPA authorization checks.
 * Mirrors Python SDK foundation_sdk/resources/authz.py
 */

import type { Transport } from "../transport.js";

export class AuthzResource {
  constructor(private readonly t: Transport) {}

  // --- Permission Check ---

  /** May `userId` (default: the context user) perform `action`? */
  async check(params: {
    action: string;
    resourceType: string;
    resourceId?: string;
    userId?: string;
  }): Promise<Record<string, unknown>> {
    const userId = params.userId || this.t.resolveContext()?.userId;
    if (!userId) throw new Error("userId is required when the FoundationContext has no userId");
    const body: Record<string, unknown> = {
      user_id: userId,
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

  /** `displayName` defaults to `name`. */
  async createRole(params: {
    name: string;
    permissions: string[];
    displayName?: string;
    description?: string;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      name: params.name,
      display_name: params.displayName || params.name,
      permissions: params.permissions,
    };
    if (params.description != null) body["description"] = params.description;
    return this.t.request("POST", "/api/authz/v1/roles", { json: body });
  }

  /**
   * Bind role `roleId` (`rol_…`, from `listRoles`) to a user.
   *
   * `scopeKind` is TENANT, ORG_UNIT, TEAM, RESOURCE or GLOBAL_SYSTEM; every kind
   * but TENANT needs `scopeId`. `expiresAt` is ISO-8601.
   */
  async bindRole(params: {
    userId: string;
    roleId: string;
    scopeKind?: string;
    scopeId?: string;
    expiresAt?: string;
    grantReason?: string;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      principal_kind: "USER",
      principal_id: params.userId,
      role_id: params.roleId,
      scope_kind: params.scopeKind ?? "TENANT",
    };
    if (params.scopeId != null) body["scope_id"] = params.scopeId;
    if (params.expiresAt != null) body["expires_at"] = params.expiresAt;
    if (params.grantReason != null) body["grant_reason"] = params.grantReason;
    return this.t.request("POST", "/api/authz/v1/bindings", { json: body });
  }

  async listPermissions(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/authz/v1/permissions");
  }
}
