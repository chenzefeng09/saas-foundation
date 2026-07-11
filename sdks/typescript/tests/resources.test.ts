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
      context: createContext({ tenantId: "tnt_001" }),
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("calls POST /api/authz/v1/check with correct body", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { allowed: true }));

    await client.authz.check({
      action: "session.read",
      resourceType: "Agent",
      resourceId: "agent_001",
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/authz/v1/check");
    expect(init.method).toBe("POST");

    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body["action"]).toBe("session.read");
    expect(body["resource_type"]).toBe("Agent");
    expect(body["resource_id"]).toBe("agent_001");
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

  it("calls GET /api/audit/v1/events with limit", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { items: [] }));

    await client.audit.query({ limit: 50, eventType: "user.login" });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/audit/v1/events");
    expect(url).toContain("limit=50");
    expect(url).toContain("event_type=user.login");
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
