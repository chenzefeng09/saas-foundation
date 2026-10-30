/**
 * Tests for resource methods — verify correct URL + headers + body.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { FoundationClient, createContext } from "../src/client.js";

function makeResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("IdentityResource — getUser", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok_test",
      context: createContext({ tenantId: "tnt_test", userId: "usr_admin" }),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls correct URL", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { id: "usr_001", email: "a@b.com" }));

    await client.identity.getUser("usr_001");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/identity/v1/users/usr_001");
  });

  it("includes X-Tenant-Id header from sticky context", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { id: "usr_001" }));

    await client.identity.getUser("usr_001");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const h = init.headers as Record<string, string>;
    expect(h["X-Tenant-Id"]).toBe("tnt_test");
    expect(h["Authorization"]).toBe("Bearer tok_test");
  });

  it("includes X-User-Id when userId is in context", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { id: "usr_001" }));

    await client.identity.getUser("usr_001");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const h = init.headers as Record<string, string>;
    expect(h["X-User-Id"]).toBe("usr_admin");
  });
});

describe("IdentityResource — listUsers", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("uses default limit=50", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { items: [] }));

    await client.identity.listUsers();

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("limit=50");
  });

  it("passes cursor when provided", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { items: [] }));

    await client.identity.listUsers({ cursor: "page2" });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("cursor=page2");
  });
});

describe("AuthzResource — check", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001", userId: "usr_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("calls POST /api/authz/v1/check for the context user", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { allowed: true }));

    await client.authz.check({
      action: "session.read",
      resourceType: "Agent",
      resourceId: "agent_001",
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/authz/v1/check");
    expect(init.method).toBe("POST");

    // The route takes the subject from the body: without user_id it answers 422.
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).toEqual({
      user_id: "usr_001",
      action: "session.read",
      resource_type: "Agent",
      resource_id: "agent_001",
    });
  });

  it("refuses to check without a user instead of sending a request the route rejects", async () => {
    const anonymous = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001" }),
    });

    await expect(
      anonymous.authz.check({ action: "session.read", resourceType: "Agent" }),
    ).rejects.toThrow("userId is required");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("DLPResource — checkDownload", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001", userId: "usr_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("sends destination without accepting a caller clearance", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { allowed: true }));

    await client.dlp.checkDownload({ fileId: "file_001", destination: "usb" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/dlp/v1/check-download");
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).toEqual({ file_id: "file_001", destination: "usb" });
    expect(body).not.toHaveProperty("sensitivity");
  });
});

describe("LifecycleResource — listLegalHolds", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("filters by resource with the contract's filter.resource_id param", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { items: [], next_cursor: null }));

    await client.lifecycle.listLegalHolds({ resourceId: "res_001" });

    // A bare resource_id is ignored by GET /legal-holds, which then lists every hold.
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/lifecycle/v1/legal-holds?filter.resource_id=res_001");
  });

  it("sends no filter when no resource is given", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { items: [], next_cursor: null }));

    await client.lifecycle.listLegalHolds();

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/lifecycle/v1/legal-holds");
  });

  it("keeps an empty resourceId as a filter instead of listing every hold", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { items: [], next_cursor: null }));

    await client.lifecycle.listLegalHolds({ resourceId: "" });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/lifecycle/v1/legal-holds?filter.resource_id=");
  });
});

describe("BillingResource — checkQuota", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("calls POST /api/billing/v1/quota/check", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { allowed: true }));

    await client.billing.checkQuota({ dimension: "user_seats", requested: 5 });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/billing/v1/quota/check");

    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body["dimension"]).toBe("user_seats");
    expect(body["requested"]).toBe(5);
  });
});

describe("AuditResource — query", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("POSTs an AuditQuery for the context tenant to /api/audit/v1/events:query", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { items: [] }));

    await client.audit.query({ limit: 50, eventType: "user.login" });

    // There is no GET /events: the filters travel in the body, scoped to one tenant.
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/audit/v1/events:query");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      tenant_id: "tnt_001",
      event_type: "user.login",
      limit: 50,
    });
  });
});

describe("SecurityOpsResource — reportIncident", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: FoundationClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new FoundationClient({
      apiUrl: "http://api.test",
      apiToken: "tok",
      context: createContext({ tenantId: "tnt_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("POSTs to /api/security-ops/v1/incidents with correct body", async () => {
    fetchMock.mockResolvedValue(makeResponse(201, { id: "inc_001" }));

    await client.securityOps.reportIncident({
      severity: "HIGH",
      category: "DATA_BREACH",
      title: "Potential data leak",
      affectedTenants: ["tnt_001"],
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/security-ops/v1/incidents");

    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body["severity"]).toBe("HIGH");
    expect(body["category"]).toBe("DATA_BREACH");
    expect(body["affected_tenants"]).toEqual(["tnt_001"]);
  });
});
