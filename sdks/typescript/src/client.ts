/**
 * Main client — aggregates all resource groups.
 * Mirrors Python SDK foundation_sdk/client.py
 *
 * Usage:
 *   // Node.js / Server (ambient context via AsyncLocalStorage)
 *   const client = new FoundationClient({ apiUrl: "http://...", apiToken: "..." });
 *   await runWithContext(createContext({ tenantId: "tnt_..." }), async () => {
 *     const user = await client.identity.getUser("usr_...");
 *   });
 *
 *   // Browser / SPA (sticky context)
 *   const client = new FoundationClient({
 *     apiUrl: "http://...",
 *     apiToken: accessToken,
 *     context: createContext({ tenantId, userId }),
 *   });
 *   const me = await client.identity.me();
 *
 *   // From environment variables
 *   const client = FoundationClient.fromEnv();
 */

import { createContext, type FoundationContext } from "./context.js";
import { Transport } from "./transport.js";
import { ApiPlatformResource } from "./resources/api_platform.js";
import { AuditResource } from "./resources/audit.js";
import { AuthzResource } from "./resources/authz.js";
import { BillingResource } from "./resources/billing.js";
import { ComplianceResource } from "./resources/compliance.js";
import { CryptoResource } from "./resources/crypto.js";
import { DataProtectionResource } from "./resources/data_protection.js";
import { DLPResource } from "./resources/dlp.js";
import { FeatureFlagResource } from "./resources/feature_flag.js";
import { IdentityResource } from "./resources/identity.js";
import { LifecycleResource } from "./resources/lifecycle.js";
import { LLMGatewayResource } from "./resources/llm_gateway.js";
import { NotificationResource } from "./resources/notification.js";
import { OrgResource } from "./resources/org.js";
import { PAMResource } from "./resources/pam.js";
import { SearchResource } from "./resources/search.js";
import { SecurityOpsResource } from "./resources/security_ops.js";

export interface FoundationClientOptions {
  /** Base URL of the Foundation API gateway, e.g. "https://api.example.com" */
  apiUrl?: string;
  /** Bearer token (access_token from Keycloak / service-account token) */
  apiToken?: string;
  /** Request timeout in seconds (default: 30) */
  timeout?: number;
  /**
   * Optional sticky context for browser environments or when you want to pin
   * a specific tenant/user for the entire client lifetime.
   *
   * In Node.js you'll usually leave this unset and use `runWithContext()` instead.
   */
  context?: FoundationContext;
}

export class FoundationClient {
  private readonly transport: Transport;

  // --- Service resource groups (17 total, mirrors Python client) ---
  readonly identity: IdentityResource;
  readonly authz: AuthzResource;
  readonly org: OrgResource;
  readonly billing: BillingResource;
  readonly audit: AuditResource;
  readonly lifecycle: LifecycleResource;
  readonly notification: NotificationResource;
  readonly search: SearchResource;
  readonly apiPlatform: ApiPlatformResource;
  readonly llmGateway: LLMGatewayResource;
  readonly featureFlag: FeatureFlagResource;
  readonly dlp: DLPResource;
  readonly crypto: CryptoResource;
  readonly compliance: ComplianceResource;
  readonly pam: PAMResource;
  readonly dataProtection: DataProtectionResource;
  readonly securityOps: SecurityOpsResource;

  constructor(options: FoundationClientOptions = {}) {
    const apiUrl = options.apiUrl ?? "http://localhost:8000";
    const apiToken = options.apiToken ?? "";

    this.transport = new Transport({
      baseUrl: apiUrl,
      apiToken,
      timeout: options.timeout ?? 30,
      stickyContext: options.context,
    });

    this.identity = new IdentityResource(this.transport);
    this.authz = new AuthzResource(this.transport);
    this.org = new OrgResource(this.transport);
    this.billing = new BillingResource(this.transport);
    this.audit = new AuditResource(this.transport);
    this.lifecycle = new LifecycleResource(this.transport);
    this.notification = new NotificationResource(this.transport);
    this.search = new SearchResource(this.transport);
    this.apiPlatform = new ApiPlatformResource(this.transport);
    this.llmGateway = new LLMGatewayResource(this.transport);
    this.featureFlag = new FeatureFlagResource(this.transport);
    this.dlp = new DLPResource(this.transport);
    this.crypto = new CryptoResource(this.transport);
    this.compliance = new ComplianceResource(this.transport);
    this.pam = new PAMResource(this.transport);
    this.dataProtection = new DataProtectionResource(this.transport);
    this.securityOps = new SecurityOpsResource(this.transport);
  }

  /**
   * Construct from environment variables.
   *   FOUNDATION_API_URL   — base URL (default: http://localhost:8000)
   *   FOUNDATION_API_TOKEN — bearer token (required)
   *   FOUNDATION_TIMEOUT   — timeout in seconds (default: 30)
   */
  static fromEnv(): FoundationClient {
    const apiToken = process.env["FOUNDATION_API_TOKEN"] ?? "";
    if (!apiToken) {
      throw new Error(
        "FOUNDATION_API_TOKEN is required. Set it in environment variables.",
      );
    }
    return new FoundationClient({
      apiUrl: process.env["FOUNDATION_API_URL"] ?? "http://localhost:8000",
      apiToken,
      timeout: process.env["FOUNDATION_TIMEOUT"] != null
        ? parseFloat(process.env["FOUNDATION_TIMEOUT"])
        : 30,
    });
  }

  /**
   * Set or update the sticky context for this client instance.
   * Equivalent to Python's `with sdk.as_tenant(...)` for browser environments.
   */
  setContext(ctx: FoundationContext): void {
    this.transport.setStickyContext(ctx);
  }

  clearContext(): void {
    this.transport.clearStickyContext();
  }
}

// Re-export context helpers so callers don't need a separate import
export { createContext, runWithContext } from "./context.js";
export type { FoundationContext } from "./context.js";
