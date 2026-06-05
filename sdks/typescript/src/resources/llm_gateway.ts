/**
 * LLM Gateway resource — probe endpoints, manage model routing.
 * Mirrors Python SDK foundation_sdk/resources/llm_gateway.py
 */

import type { Transport } from "../transport.js";

export class LLMGatewayResource {
  constructor(private readonly t: Transport) {}

  async probeEndpoint(params: {
    url: string;
    apiKey: string;
    providerType?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/llm-gateway/v1/probe", {
      json: {
        url: params.url,
        api_key: params.apiKey,
        provider_type: params.providerType ?? "openai_compatible",
      },
    });
  }

  async listProviders(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/llm-gateway/v1/providers");
  }

  async registerProvider(params: {
    name: string;
    apiBase: string;
    apiKey: string;
    providerType: string;
    models?: string[];
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/llm-gateway/v1/providers", {
      json: {
        name: params.name,
        api_base: params.apiBase,
        api_key: params.apiKey,
        provider_type: params.providerType,
        models: params.models ?? [],
      },
    });
  }

  async getModelPricing(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/llm-gateway/v1/pricing");
  }

  async chat(params: {
    model: string;
    messages: Array<{ role: string; content: string }>;
    temperature?: number;
    maxTokens?: number;
    stream?: boolean;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/llm-gateway/v1/chat", {
      json: {
        model: params.model,
        messages: params.messages,
        temperature: params.temperature ?? 0.7,
        max_tokens: params.maxTokens ?? null,
        stream: params.stream ?? false,
      },
    });
  }
}
