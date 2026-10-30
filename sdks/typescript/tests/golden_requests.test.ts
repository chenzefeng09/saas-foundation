/**
 * Every SDK method sends exactly the request pinned in contracts/sdk/<service>.json.
 *
 * Each service's tests/unit/test_sdk_requests.py checks the same requests against
 * its routes and its OpenAPI contract, so a path, parameter or field that changes
 * on one side only fails one of the two suites. When a method changes on purpose,
 * change its cases with it (see contracts/sdk/README.md).
 */

import { readdirSync, readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FoundationClient, createContext } from "../src/client.js";

interface WireRequest {
  method: string;
  path: string;
  query?: Record<string, string | string[]>;
  json?: unknown;
}

interface GoldenFile {
  service: string;
  context: { tenant_id: string; user_id: string };
  cases: Array<{
    id: string;
    typescript: Array<{ method: string; args: unknown[] }>;
    request: WireRequest;
  }>;
}

type Resource = Record<string, (...args: unknown[]) => Promise<unknown>>;

const GOLDEN = new URL("../../../contracts/sdk/", import.meta.url);
const files = readdirSync(GOLDEN)
  .filter((name) => name.endsWith(".json"))
  .sort()
  .map((name) => JSON.parse(readFileSync(new URL(name, GOLDEN), "utf8")) as GoldenFile);

function newClient(file: GoldenFile): FoundationClient {
  return new FoundationClient({
    apiUrl: "http://sdk.test",
    apiToken: "tok",
    context: createContext({ tenantId: file.context.tenant_id, userId: file.context.user_id }),
  });
}

/** The client's resource groups, keyed by service name ("apiPlatform" → "api-platform"). */
function resources(client: FoundationClient): Map<string, Resource> {
  const groups = new Map<string, Resource>();
  for (const [key, value] of Object.entries(client)) {
    if (value instanceof Object && value.constructor.name.endsWith("Resource")) {
      groups.set(key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`), value as Resource);
    }
  }
  return groups;
}

/** A fetch call written down the way the golden files write it. */
function wire(url: string, init: RequestInit): WireRequest {
  const parsed = new URL(url);
  const request: WireRequest = { method: init.method ?? "GET", path: parsed.pathname };
  const query: Record<string, string[]> = {};
  for (const [name, value] of parsed.searchParams) (query[name] ??= []).push(value);
  if (Object.keys(query).length > 0) {
    request.query = Object.fromEntries(
      Object.entries(query).map(([name, values]) => [name, values.length === 1 ? values[0]! : values]),
    );
  }
  if (init.body != null) request.json = JSON.parse(init.body as string);
  return request;
}

describe.each(files.map((file) => [file.service, file] as const))("%s", (_, file) => {
  afterEach(() => vi.unstubAllGlobals());

  const calls = file.cases.flatMap((c) =>
    c.typescript.map((call) => ({ ...call, id: c.id, request: c.request })),
  );

  it.each(calls)("$method sends the golden request $id", async ({ method, args, request }) => {
    const fetchMock = vi.fn(
      async (_url: string, _init: RequestInit) =>
        new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const resource = resources(newClient(file)).get(file.service)!;

    await resource[method]!(...args);

    expect(fetchMock.mock.calls.map(([url, init]) => wire(url, init))).toEqual([request]);
  });
});

it("pins a golden request for every public method", () => {
  const pinned = new Set(
    files.flatMap((file) => file.cases.flatMap((c) => c.typescript.map((call) => `${file.service}.${call.method}`))),
  );
  const methods = new Set<string>();
  for (const [service, resource] of resources(new FoundationClient())) {
    for (const name of Object.getOwnPropertyNames(Object.getPrototypeOf(resource))) {
      if (name !== "constructor") methods.add(`${service}.${name}`);
    }
  }

  expect([...methods].filter((m) => !pinned.has(m)).sort(), "methods without a case").toEqual([]);
  expect([...pinned].filter((m) => !methods.has(m)).sort(), "cases for methods the SDK does not have").toEqual([]);
});
