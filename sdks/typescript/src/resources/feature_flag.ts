/**
 * Feature Flag resource — Unleash-compatible feature flag evaluation.
 * Mirrors Python SDK foundation_sdk/resources/feature_flag.py
 */

import type { Transport } from "../transport.js";

export class FeatureFlagResource {
  constructor(private readonly t: Transport) {}

  async isEnabled(flag: string): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/feature-flag/v1/evaluate", {
      json: { flag },
    });
  }

  async evaluateBatch(flags: string[]): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/feature-flag/v1/evaluate-batch", {
      json: { flags },
    });
  }

  async listFlags(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/feature-flag/v1/flags");
  }

  async setFlag(params: {
    flag: string;
    enabled: boolean;
    rolloutPercentage?: number;
    tenantWhitelist?: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("PUT", `/api/feature-flag/v1/flags/${params.flag}`, {
      json: {
        enabled: params.enabled,
        rollout_percentage: params.rolloutPercentage ?? 100,
        tenant_whitelist: params.tenantWhitelist ?? [],
      },
    });
  }
}
