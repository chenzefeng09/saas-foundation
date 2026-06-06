/**
 * Data Protection resource — masking engine, data destruction, cross-border transfer.
 * Mirrors Python SDK foundation_sdk/resources/data_protection.py
 */

import type { Transport } from "../transport.js";

export class DataProtectionResource {
  constructor(private readonly t: Transport) {}

  // --- Masking ---

  async mask(params: {
    data: Record<string, unknown>;
    rules: Array<Record<string, string>>;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/data-protection/v1/mask", {
      json: { data: params.data, rules: params.rules },
    });
  }

  async maskField(params: {
    fieldName: string;
    value: string;
    maskType?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/data-protection/v1/mask-field", {
      json: {
        field_name: params.fieldName,
        value: params.value,
        mask_type: params.maskType ?? "default",
      },
    });
  }

  async getMaskingRules(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/data-protection/v1/masking-rules");
  }

  // --- Data Destruction ---

  async requestDestruction(params: {
    resourceIds: string[];
    method?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/data-protection/v1/destruction", {
      json: {
        resource_ids: params.resourceIds,
        method: params.method ?? "crypto_shred",
      },
    });
  }

  async getDestructionStatus(requestId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/data-protection/v1/destruction/${requestId}`);
  }

  // --- Cross-Border ---

  async checkCrossBorder(params: {
    destinationCountry: string;
    dataCategories: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/data-protection/v1/cross-border/check", {
      json: {
        destination_country: params.destinationCountry,
        data_categories: params.dataCategories,
      },
    });
  }

  async getDataResidency(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/data-protection/v1/data-residency");
  }
}
