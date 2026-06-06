/**
 * Retry policy for Foundation SDK HTTP calls.
 *
 * Mirrors Python SDK foundation_sdk/_retry.py:
 *   - Exponential backoff with jitter
 *   - Respects Retry-After from RateLimitedError / QuotaExceededError
 *   - Network errors and 5xx DependencyErrors are retried up to max_attempts
 */

import { DependencyError, FoundationError, QuotaExceededError, RateLimitedError } from "./errors.js";

export interface RetryPolicyOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean;
}

export class RetryPolicy {
  readonly maxAttempts: number;
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
  readonly jitter: boolean;

  constructor(options: RetryPolicyOptions = {}) {
    this.maxAttempts = options.maxAttempts ?? 3;
    this.baseDelayMs = options.baseDelayMs ?? 500;
    this.maxDelayMs = options.maxDelayMs ?? 30_000;
    this.jitter = options.jitter ?? true;
  }

  shouldRetry(err: unknown, attempt: number): boolean {
    if (attempt >= this.maxAttempts) return false;

    // Network-level errors (fetch rejects with TypeError on network failure)
    if (err instanceof TypeError && err.message.includes("fetch")) return true;

    if (err instanceof DependencyError) return true;
    if (err instanceof QuotaExceededError || err instanceof RateLimitedError) {
      return attempt < 1;
    }
    return false;
  }

  delayFor(attempt: number, err?: unknown): number {
    // Honour Retry-After header if the error carries one
    if (err instanceof FoundationError && err.retryAfter != null) {
      return err.retryAfter * 1_000; // convert seconds → ms
    }
    let delay = Math.min(this.baseDelayMs * Math.pow(2, attempt), this.maxDelayMs);
    if (this.jitter) {
      delay *= 0.5 + Math.random();
    }
    return delay;
  }
}

export const DEFAULT_RETRY = new RetryPolicy();
