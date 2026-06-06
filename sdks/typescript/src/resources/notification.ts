/**
 * Notification resource — send notifications via multiple channels.
 * Mirrors Python SDK foundation_sdk/resources/notification.py
 */

import type { Transport } from "../transport.js";

export class NotificationResource {
  constructor(private readonly t: Transport) {}

  async send(params: {
    eventType: string;
    recipients: string[];
    channel?: string;
    template?: string;
    context?: Record<string, unknown>;
    priority?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/notification/v1/send", {
      json: {
        event_type: params.eventType,
        recipients: params.recipients,
        channel: params.channel ?? "email",
        template: params.template ?? null,
        context: params.context ?? {},
        priority: params.priority ?? "normal",
      },
    });
  }

  async sendBatch(notifications: Array<Record<string, unknown>>): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/notification/v1/send-batch", {
      json: { notifications },
    });
  }

  async listTemplates(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/notification/v1/templates");
  }
}
