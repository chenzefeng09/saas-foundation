/**
 * @foundation/sdk — TypeScript SDK for SaaS Foundation services.
 *
 * Public API surface (mirrors Python SDK foundation_sdk/__init__.py).
 */

// Client
export { FoundationClient, createContext, runWithContext } from "./client.js";
export type { FoundationClientOptions, FoundationContext } from "./client.js";

// Errors
export {
  FoundationError,
  AuthError,
  PolicyError,
  InputError,
  ValidationError,
  ResourceNotFoundError,
  ConflictError,
  QuotaExceededError,
  RateLimitedError,
  DependencyError,
  ComplianceError,
  InternalError,
  fromProblem,
  registerErrorClass,
} from "./errors.js";
export type { FieldError, ProblemDetails } from "./errors.js";

// Context (re-exported for consumers who want the lower-level API)
export { currentContext } from "./context.js";

// Transport (for advanced users: custom transport composition)
export { Transport } from "./transport.js";
export type { TransportOptions } from "./transport.js";

// Retry policy
export { RetryPolicy, DEFAULT_RETRY } from "./retry.js";
export type { RetryPolicyOptions } from "./retry.js";

// Resources (for typing, not construction — use client.identity etc.)
export type { IdentityResource } from "./resources/identity.js";
export type { AuthzResource } from "./resources/authz.js";
export type { OrgResource } from "./resources/org.js";
export type { BillingResource } from "./resources/billing.js";
export type { AuditResource } from "./resources/audit.js";
export type { LifecycleResource } from "./resources/lifecycle.js";
export type { NotificationResource } from "./resources/notification.js";
export type { SearchResource } from "./resources/search.js";
export type { ApiPlatformResource } from "./resources/api_platform.js";
export type { LLMGatewayResource } from "./resources/llm_gateway.js";
export type { FeatureFlagResource } from "./resources/feature_flag.js";
export type { DLPResource } from "./resources/dlp.js";
export type { CryptoResource } from "./resources/crypto.js";
export type { ComplianceResource } from "./resources/compliance.js";
export type { PAMResource } from "./resources/pam.js";
export type { DataProtectionResource } from "./resources/data_protection.js";
export type { SecurityOpsResource } from "./resources/security_ops.js";
