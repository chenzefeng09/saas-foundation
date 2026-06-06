/**
 * DLP resource — data loss prevention, content scanning, download interception.
 * Mirrors Python SDK foundation_sdk/resources/dlp.py
 */

import type { Transport } from "../transport.js";

export class DLPResource {
  constructor(private readonly t: Transport) {}

  async checkDownload(params: {
    fileId: string;
    sensitivity: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/dlp/v1/check-download", {
      json: { file_id: params.fileId, sensitivity: params.sensitivity },
    });
  }

  async scanContent(params: {
    content: string;
    contentType?: string;
    sensitivityThreshold?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/dlp/v1/scan", {
      json: {
        content: params.content,
        content_type: params.contentType ?? "text",
        sensitivity_threshold: params.sensitivityThreshold ?? "L4",
      },
    });
  }

  async classifyFile(params: {
    fileId: string;
    sensitivity: string;
    reason?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/dlp/v1/classify", {
      json: {
        file_id: params.fileId,
        sensitivity: params.sensitivity,
        reason: params.reason ?? "",
      },
    });
  }

  async getSensitiveWords(): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/dlp/v1/sensitive-words");
  }

  async addSensitiveWord(params: {
    word: string;
    category: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/dlp/v1/sensitive-words", {
      json: { word: params.word, category: params.category },
    });
  }
}
