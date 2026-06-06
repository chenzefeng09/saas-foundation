/**
 * Tenant / user / request context propagation for the Foundation SDK.
 *
 * Python SDK counterpart: foundation_sdk/_context.py
 *
 * ## Why not Python-style ContextVar?
 *
 * Python uses `contextvars.ContextVar` which is automatically propagated through
 * asyncio tasks. Node.js has `AsyncLocalStorage` which is equivalent — it flows
 * through `async/await`, `Promise` chains, and `setTimeout` callbacks without
 * explicit passing.
 *
 * ## Choice: AsyncLocalStorage (server-side) + explicit ctx (browser)
 *
 * The SDK is designed to work in both environments:
 *
 * 1. **Server / Node.js (BFF, workers)**: Use `runWithContext()` which sets up
 *    AsyncLocalStorage scoping — the exact equivalent of Python's `with tenant_context()`.
 *    Every SDK call inside the callback automatically picks up the context.
 *
 * 2. **Browser (SPA, front-end agents)**: AsyncLocalStorage is unavailable in browsers.
 *    Instead, construct the client with an explicit `FoundationContext` object and pass
 *    it per-call, or set it once on the client via `client.setContext(ctx)`. This is
 *    the idiomatic browser pattern: no hidden ambient state.
 *
 * Both paths produce the same HTTP headers (X-Tenant-Id, X-Request-Id, X-User-Id).
 */

function generateRequestId(): string {
  // Mirrors Python: f"req_{uuid.uuid4().hex[:26].upper()}"
  const hex = Array.from({ length: 26 }, () =>
    Math.floor(Math.random() * 16).toString(16),
  )
    .join("")
    .toUpperCase();
  return `req_${hex}`;
}

export interface FoundationContext {
  readonly tenantId: string;
  readonly userId?: string;
  readonly requestId: string;
  readonly traceId?: string;
  readonly locale: string;
}

export function createContext(params: {
  tenantId: string;
  userId?: string;
  requestId?: string;
  traceId?: string;
  locale?: string;
}): FoundationContext {
  return {
    tenantId: params.tenantId,
    userId: params.userId,
    requestId: params.requestId ?? generateRequestId(),
    traceId: params.traceId,
    locale: params.locale ?? "zh-CN",
  };
}

// ─── AsyncLocalStorage (Node.js / server environments) ───────────────────────

/**
 * Lazily-created AsyncLocalStorage instance. We import it from 'node:async_hooks'
 * only when the module is first required in Node.js. In browser environments this
 * reference stays undefined and the server-side path is never entered.
 */
let _storage: { getStore(): FoundationContext | undefined; run<T>(store: FoundationContext, fn: () => T): T } | undefined;

function getStorage(): typeof _storage {
  if (_storage !== undefined) return _storage;
  try {
    // Dynamic require so the module is still valid in browser bundlers
    // (the require() call is tree-shaken / never reached in browser builds)
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    const { AsyncLocalStorage } = require("node:async_hooks") as typeof import("node:async_hooks");
    _storage = new AsyncLocalStorage<FoundationContext>();
  } catch {
    // Browser environment — AsyncLocalStorage not available
    _storage = undefined;
  }
  return _storage;
}

/**
 * Run `fn` with the given context active (Node.js / server).
 * Equivalent to Python's `with tenant_context(...)`.
 *
 * @example
 * ```ts
 * await runWithContext(
 *   createContext({ tenantId: "tnt_01J..." }),
 *   async () => {
 *     const user = await client.identity.getUser("usr_01J...");
 *   }
 * );
 * ```
 */
export function runWithContext<T>(ctx: FoundationContext, fn: () => T): T {
  const storage = getStorage();
  if (storage == null) {
    throw new Error(
      "runWithContext() requires Node.js (AsyncLocalStorage). " +
        "In browser environments, pass a FoundationContext to the client constructor or use client.setContext().",
    );
  }
  return storage.run(ctx, fn);
}

/**
 * Read the context set by the nearest enclosing `runWithContext` (Node.js).
 * Returns undefined if no context is active.
 */
export function currentContext(): FoundationContext | undefined {
  return getStorage()?.getStore();
}
