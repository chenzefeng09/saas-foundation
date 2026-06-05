/**
 * Billing resource — plans, subscriptions, quota checks, invoices.
 * Mirrors Python SDK foundation_sdk/resources/billing.py
 */

import type { Transport } from "../transport.js";

export class BillingResource {
  constructor(private readonly t: Transport) {}

  // --- Plans ---

  async listPlans(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/billing/v1/plans");
  }

  async createPlan(params: {
    name: string;
    tier: string;
    quotas: Record<string, number>;
    priceMonthlyUsd: number;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/billing/v1/plans", {
      json: {
        name: params.name,
        tier: params.tier,
        quotas: params.quotas,
        price_monthly_usd: params.priceMonthlyUsd,
      },
    });
  }

  // --- Subscriptions ---

  async subscribe(params: { planId: string; mode?: string }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/billing/v1/subscriptions", {
      json: { plan_id: params.planId, mode: params.mode ?? "private" },
    });
  }

  async getSubscription(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/billing/v1/subscriptions/current");
  }

  // --- Quota ---

  async checkQuota(params: {
    dimension: string;
    requested?: number;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/billing/v1/quota/check", {
      json: { dimension: params.dimension, requested: params.requested ?? 1 },
    });
  }

  async recordUsage(params: {
    dimension: string;
    amount: number;
    description?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/billing/v1/quota/usage", {
      json: {
        dimension: params.dimension,
        amount: params.amount,
        description: params.description ?? "",
      },
    });
  }

  // --- Invoices ---

  async generateInvoice(params: {
    items: Array<Record<string, unknown>>;
    dueDays?: number;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/billing/v1/invoices", {
      json: { items: params.items, due_days: params.dueDays ?? 30 },
    });
  }

  async listInvoices(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/billing/v1/invoices");
  }
}
