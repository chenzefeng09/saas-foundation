/**
 * Tests for Transport — header injection and error parsing.
 * Uses global fetch mock (vitest provides globalThis.fetch mock via vi.stubGlobal).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Transport } from "../src/transport.js";
import { createContext, runWithContext } from "../src/context.js";
import { AuthError, ResourceNotFoundError } from "../src/errors.js";

function makeResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  const h = new Headers({ "content-type": "application/json", ...headers });
  return new Response(JSON.stringify(body), { status, headers: h });
}

describe("Transport — header injection", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("injects Authorization header with Bearer token", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { id: "usr_001" }));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok_abc" });
    await t.request("GET", "/api/identity/v1/users/usr_001", {
      ctx: createContext({ tenantId: "tnt_001" }),
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer tok_abc");
  });

  it("injects X-Tenant-Id from context", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await t.request("GET", "/api/identity/v1/users", {
      ctx: createContext({ tenantId: "tnt_foobar" }),
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Tenant-Id"]).toBe("tnt_foobar");
  });

  it("injects X-User-Id when userId is in context", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await t.request("GET", "/path", {
      ctx: createContext({ tenantId: "tnt_001", userId: "usr_xyz" }),
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-User-Id"]).toBe("usr_xyz");
  });

  it("injects X-Request-Id from context", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    const ctx = createContext({ tenantId: "tnt_001", requestId: "req_FIXED123" });
    await t.request("GET", "/path", { ctx });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Request-Id"]).toBe("req_FIXED123");
  });

  it("uses sticky context when no explicit ctx is passed", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const sticky = createContext({ tenantId: "tnt_sticky" });
    const t = new Transport({
      baseUrl: "http://api.test",
      apiToken: "tok",
      stickyContext: sticky,
    });
    await t.request("GET", "/path");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Tenant-Id"]).toBe("tnt_sticky");
  });

  it("explicit ctx overrides sticky context", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const sticky = createContext({ tenantId: "tnt_sticky" });
    const explicit = createContext({ tenantId: "tnt_explicit" });
    const t = new Transport({
      baseUrl: "http://api.test",
      apiToken: "tok",
      stickyContext: sticky,
    });
    await t.request("GET", "/path", { ctx: explicit });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Tenant-Id"]).toBe("tnt_explicit");
  });
});

describe("Transport — URL construction", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("builds correct URL with base + path", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await t.request("GET", "/api/identity/v1/users", {
      ctx: createContext({ tenantId: "tnt_001" }),
    });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/api/identity/v1/users");
  });

  it("appends query params correctly", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await t.request("GET", "/api/identity/v1/users", {
      ctx: createContext({ tenantId: "tnt_001" }),
      params: { limit: 20, cursor: "tok_abc" },
    });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("limit=20");
    expect(url).toContain("cursor=tok_abc");
  });

  it("omits null/undefined query params", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, {}));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await t.request("GET", "/path", {
      ctx: createContext({ tenantId: "tnt_001" }),
      params: { limit: 10, cursor: undefined },
    });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).not.toContain("cursor");
  });
});

describe("Transport — error parsing", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws AuthError on 401", async () => {
    fetchMock.mockResolvedValue(
      makeResponse(401, { code: "FOUNDATION.IDENTITY.AUTH.EXPIRED", title: "Unauthorized" }),
    );

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await expect(
      t.request("GET", "/path", { ctx: createContext({ tenantId: "tnt_001" }) }),
    ).rejects.toBeInstanceOf(AuthError);
  });

  it("throws ResourceNotFoundError on 404", async () => {
    fetchMock.mockResolvedValue(
      makeResponse(404, { title: "Not Found" }),
    );

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await expect(
      t.request("GET", "/path", { ctx: createContext({ tenantId: "tnt_001" }) }),
    ).rejects.toBeInstanceOf(ResourceNotFoundError);
  });

  it("returns empty object on 204", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    const result = await t.request("DELETE", "/path", {
      ctx: createContext({ tenantId: "tnt_001" }),
    });
    expect(result).toEqual({});
  });
});
