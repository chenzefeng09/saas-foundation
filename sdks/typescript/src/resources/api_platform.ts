/**
 * API Platform resource — API keys, OAuth apps, webhooks.
 * Mirrors Python SDK foundation_sdk/resources/api_platform.py
 */

import type { Transport } from "../transport.js";

export class ApiPlatformResource {
  constructor(private readonly t: Transport) {}

  // --- API Keys ---

  async createApiKey(params: {
    name: string;
    scopes: string[];
    ipWhitelist?: string[];
    rateLimitRpm?: number;
    expiresInDays?: number;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/api-platform/v1/keys", {
      json: {
        name: params.name,
        scopes: params.scopes,
        ip_whitelist: params.ipWhitelist ?? null,
        rate_limit_rpm: params.rateLimitRpm ?? 60,
        expires_in_days: params.expiresInDays ?? null,
      },
    });
  }

  async listApiKeys(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/api-platform/v1/keys");
  }

  async revokeApiKey(keyId: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/api-platform/v1/keys/${keyId}/revoke`);
  }

  async validateApiKey(params: {
    keyHash: string;
    requiredScope?: string;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { key_hash: params.keyHash };
    if (params.requiredScope != null) body["required_scope"] = params.requiredScope;
    return this.t.request("POST", "/api/api-platform/v1/keys/validate", { json: body });
  }

  // --- OAuth Apps ---

  async registerOAuthApp(params: {
    name: string;
    redirectUris: string[];
    scopes: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/api-platform/v1/oauth-apps", {
      json: {
        name: params.name,
        redirect_uris: params.redirectUris,
        scopes: params.scopes,
      },
    });
  }

  async listOAuthApps(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/api-platform/v1/oauth-apps");
  }

  // --- Webhooks ---

  async subscribeWebhook(params: {
    url: string;
    eventTypes: string[];
    secret?: string;
  }): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      url: params.url,
      event_types: params.eventTypes,
    };
    if (params.secret != null) body["secret"] = params.secret;
    return this.t.request("POST", "/api/api-platform/v1/webhooks", { json: body });
  }

  async listWebhooks(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/api-platform/v1/webhooks");
  }

  async deleteWebhook(webhookId: string): Promise<Record<string, unknown>> {
    return this.t.request("DELETE", `/api/api-platform/v1/webhooks/${webhookId}`);
  }
}
