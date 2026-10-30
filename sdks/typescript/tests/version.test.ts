/**
 * The version package.json declares is the one the lockfile records and every request sends.
 */

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createContext } from "../src/context.js";
import { Transport } from "../src/transport.js";

interface PackageFile {
  version: string;
  packages?: Record<string, { version?: string }>;
}

function readPackageFile(name: string): PackageFile {
  return JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), "utf8")) as PackageFile;
}

const declared = readPackageFile("package.json").version;

describe("SDK version", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is the one package-lock.json records", () => {
    const lock = readPackageFile("package-lock.json");
    expect(lock.version).toBe(declared);
    expect(lock.packages?.[""]?.version).toBe(declared);
  });

  it("is sent in the User-Agent header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const t = new Transport({ baseUrl: "http://api.test", apiToken: "tok" });
    await t.request("GET", "/api/identity/v1/users", { ctx: createContext({ tenantId: "tnt_001" }) });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe(`foundation-sdk-typescript/${declared}`);
  });
});
