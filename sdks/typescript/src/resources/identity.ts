/**
 * Identity resource — user management, sessions, password policy.
 * Mirrors Python SDK foundation_sdk/resources/identity.py
 */

import type { Transport } from "../transport.js";

export class IdentityResource {
  constructor(private readonly t: Transport) {}

  // --- Users ---

  async getUser(userId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/identity/v1/users/${userId}`);
  }

  async listUsers(params?: {
    limit?: number;
    cursor?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/identity/v1/users", {
      params: { limit: params?.limit ?? 50, cursor: params?.cursor },
    });
  }

  async createUser(body: {
    email: string;
    displayName: string;
    password?: string;
    roles?: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/identity/v1/users", {
      json: {
        email: body.email,
        display_name: body.displayName,
        password: body.password,
        roles: body.roles,
      },
    });
  }

  async disableUser(userId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/identity/v1/users/${userId}/disable`);
  }

  /** Emergency freeze — invalidates all tokens immediately. */
  async freezeUser(userId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/identity/v1/users/${userId}/freeze`);
  }

  // --- Password Policy ---

  async getPasswordPolicy(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/identity/v1/password-policy");
  }

  async validatePassword(password: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/identity/v1/password-policy/validate", {
      json: { password },
    });
  }

  // --- Sessions ---

  async listSessions(userId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/identity/v1/users/${userId}/sessions`);
  }

  async revokeSession(userId: string, sessionId: string): Promise<Record<string, unknown>> {
    return this.t.request("DELETE", `/api/identity/v1/users/${userId}/sessions/${sessionId}`);
  }

  /**
   * Resolve caller identity from the current bearer token.
   *
   * BFFs call this on every page-load to rehydrate the user profile from the
   * foundation-issued JWT without trusting any client-side state.
   * Returns { user_id, tenant_id, email, display_name, roles, mfa_enabled, locale }.
   */
  async me(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/identity/v1/sessions/me");
  }

  // --- Service-account tokens ---

  /**
   * Mint a short-lived, scope-limited, tenant-bound JWT.
   *
   * Use whenever a service spawns a workload that needs to call foundation services
   * on behalf of a tenant. Do NOT forward your own service-account token.
   */
  async issueServiceAccountToken(params: {
    tenantId: string;
    subject: string;
    scopes: string[];
    audience?: string;
    ttlSeconds?: number;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/identity/v1/sessions/service-account-token", {
      json: {
        tenant_id: params.tenantId,
        subject: params.subject,
        scopes: params.scopes,
        audience: params.audience ?? "foundation",
        ttl_seconds: params.ttlSeconds ?? 3600,
      },
    });
  }

  // --- Health ---

  async healthz(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/identity/v1/healthz");
  }
}
