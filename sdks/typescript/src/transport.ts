/**
 * HTTP transport layer — injects auth headers and context, parses errors.
 *
 * Mirrors Python SDK foundation_sdk/_transport.py:
 *   - Uses the fetch API (native in Node ≥18, browsers, Deno, Bun)
 *   - Injects Authorization / X-Tenant-Id / X-Request-Id / X-User-Id headers
 *   - Parses RFC 9457 error responses via fromProblem()
 *   - Exponential-backoff retry via RetryPolicy
 *
 * Context resolution order (per-call):
 *   1. Explicit `ctx` argument on the method call
 *   2. `client.setContext(ctx)` sticky context
 *   3. AsyncLocalStorage ambient context (server / Node.js)
 *   → If none found and the request needs a tenant header: throws at header-build time
 */

import { currentContext, type FoundationContext } from "./context.js";
import { type ProblemDetails, fromProblem } from "./errors.js";
import { DEFAULT_RETRY, type RetryPolicy } from "./retry.js";

// package.json carries the same number; tests/version.test.ts keeps the two equal.
const SDK_VERSION = "1.0.0";
const DEFAULT_USER_AGENT = `foundation-sdk-typescript/${SDK_VERSION}`;

export interface TransportOptions {
  baseUrl: string;
  apiToken: string;
  timeout?: number;
  retry?: RetryPolicy;
  userAgent?: string;
  /**
   * Sticky context: used when no per-call context and no AsyncLocalStorage context.
   * Typical browser usage: pass the logged-in user's context once on client creation.
   */
  stickyContext?: FoundationContext;
}

export class Transport {
  private readonly baseUrl: string;
  private readonly apiToken: string;
  private readonly timeoutMs: number;
  private readonly retry: RetryPolicy;
  private readonly userAgent: string;
  private stickyContext: FoundationContext | undefined;

  constructor(options: TransportOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiToken = options.apiToken;
    this.timeoutMs = (options.timeout ?? 30) * 1_000;
    this.retry = options.retry ?? DEFAULT_RETRY;
    this.userAgent = options.userAgent ?? DEFAULT_USER_AGENT;
    this.stickyContext = options.stickyContext;
  }

  setStickyContext(ctx: FoundationContext): void {
    this.stickyContext = ctx;
  }

  clearStickyContext(): void {
    this.stickyContext = undefined;
  }

  /**
   * The context a request made now would carry (explicit > sticky > AsyncLocalStorage).
   * Resources read it for routes that also want the tenant or user in the body.
   */
  resolveContext(explicit?: FoundationContext): FoundationContext | undefined {
    return explicit ?? this.stickyContext ?? currentContext();
  }

  private buildHeaders(ctx: FoundationContext | undefined): Record<string, string> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiToken}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": this.userAgent,
    };

    if (ctx != null) {
      headers["X-Tenant-Id"] = ctx.tenantId;
      headers["X-Request-Id"] = ctx.requestId;
      if (ctx.userId != null) {
        headers["X-User-Id"] = ctx.userId;
      }
      if (ctx.locale != null && ctx.locale !== "zh-CN") {
        headers["Accept-Language"] = ctx.locale;
      }
    }

    return headers;
  }

  async request<T = Record<string, unknown>>(
    method: string,
    path: string,
    options?: {
      json?: unknown;
      params?: Record<string, string | number | boolean | undefined | null>;
      ctx?: FoundationContext;
      /** "text" for routes that answer with a file (CSV, NDJSON): resolves to the raw body. */
      responseType?: "json" | "text";
    },
  ): Promise<T> {
    const ctx = this.resolveContext(options?.ctx);
    const headers = this.buildHeaders(ctx);

    let url = `${this.baseUrl}${path}`;
    if (options?.params != null) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(options.params)) {
        if (v != null) {
          qs.append(k, String(v));
        }
      }
      const qStr = qs.toString();
      if (qStr) url += `?${qStr}`;
    }

    const bodyStr = options?.json !== undefined ? JSON.stringify(options.json) : null;
    if (bodyStr === null) {
      delete headers["Content-Type"];
    }

    let attempt = 0;
    while (true) {
      try {
        const resp = await this.fetchWithTimeout(url, {
          method,
          headers,
          ...(bodyStr !== null ? { body: bodyStr } : {}),
        });
        return (await this.handleResponse(resp, options?.responseType ?? "json")) as T;
      } catch (err) {
        if (!this.retry.shouldRetry(err, attempt)) throw err;
        const delay = this.retry.delayFor(attempt, err);
        await sleep(delay);
        attempt++;
      }
    }
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timerId);
    }
  }

  private async handleResponse(resp: Response, responseType: "json" | "text"): Promise<unknown> {
    if (resp.status >= 200 && resp.status < 300) {
      if (responseType === "text") {
        return await resp.text();
      }
      if (resp.status === 204 || resp.headers.get("content-length") === "0") {
        return {};
      }
      // Some 2xx endpoints return no content-type for empty bodies
      const contentType = resp.headers.get("content-type") ?? "";
      if (!contentType.includes("json")) {
        const text = await resp.text();
        if (!text) return {};
        try {
          return JSON.parse(text) as unknown;
        } catch {
          return {};
        }
      }
      return (await resp.json()) as unknown;
    }

    // Error path: parse RFC 9457 Problem Details
    let body: ProblemDetails;
    try {
      body = (await resp.json()) as ProblemDetails;
    } catch {
      const text = await resp.text().catch(() => "");
      body = { detail: text.slice(0, 500) };
    }
    throw fromProblem(resp.status, body);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
