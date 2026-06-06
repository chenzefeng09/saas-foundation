/**
 * Tests for error parsing (fromProblem) and error hierarchy.
 * Verifies that RFC 9457 Problem Details are routed to the correct subclass.
 */

import { describe, it, expect } from "vitest";
import {
  fromProblem,
  FoundationError,
  AuthError,
  PolicyError,
  InputError,
  ValidationError,
  ResourceNotFoundError,
  ConflictError,
  RateLimitedError,
  DependencyError,
  InternalError,
  registerErrorClass,
} from "../src/errors.js";

describe("fromProblem — HTTP status routing", () => {
  it("routes 401 → AuthError", () => {
    const err = fromProblem(401, { title: "Unauthorized", detail: "Token expired" });
    expect(err).toBeInstanceOf(AuthError);
    expect(err).toBeInstanceOf(FoundationError);
    expect(err.httpStatus).toBe(401);
  });

  it("routes 403 → PolicyError", () => {
    const err = fromProblem(403, { title: "Forbidden" });
    expect(err).toBeInstanceOf(PolicyError);
    expect(err.httpStatus).toBe(403);
  });

  it("routes 400 → InputError", () => {
    const err = fromProblem(400, { title: "Bad Request" });
    expect(err).toBeInstanceOf(InputError);
  });

  it("routes 422 → ValidationError", () => {
    const err = fromProblem(422, { title: "Unprocessable" });
    expect(err).toBeInstanceOf(ValidationError);
  });

  it("routes 404 → ResourceNotFoundError", () => {
    const err = fromProblem(404, { title: "Not Found" });
    expect(err).toBeInstanceOf(ResourceNotFoundError);
  });

  it("routes 409 → ConflictError", () => {
    const err = fromProblem(409, { title: "Conflict" });
    expect(err).toBeInstanceOf(ConflictError);
  });

  it("routes 429 → RateLimitedError", () => {
    const err = fromProblem(429, { title: "Too Many Requests" });
    expect(err).toBeInstanceOf(RateLimitedError);
  });

  it("routes 502 → DependencyError", () => {
    const err = fromProblem(502, { title: "Bad Gateway" });
    expect(err).toBeInstanceOf(DependencyError);
  });

  it("routes 503 → DependencyError", () => {
    const err = fromProblem(503, {});
    expect(err).toBeInstanceOf(DependencyError);
  });

  it("routes 500 → InternalError", () => {
    const err = fromProblem(500, { title: "Internal Server Error" });
    expect(err).toBeInstanceOf(InternalError);
  });

  it("falls back to FoundationError for unknown status", () => {
    const err = fromProblem(418, { title: "I'm a teapot" });
    expect(err).toBeInstanceOf(FoundationError);
    expect(err.httpStatus).toBe(418);
  });
});

describe("fromProblem — field error parsing", () => {
  it("parses field errors from RFC 9457 errors array", () => {
    const body = {
      code: "FOUNDATION.IDENTITY.INPUT.INVALID",
      title: "Validation Failed",
      detail: "Email is required",
      errors: [
        { field: "email", code: "required", detail: "email is required", user_message: "请填写邮箱" },
        { field: "password", code: "too_short", detail: "min 8 chars" },
      ],
    };
    const err = fromProblem(400, body);
    expect(err.fieldErrors).toHaveLength(2);
    expect(err.fieldErrors[0]).toMatchObject({ field: "email", code: "required", userMessage: "请填写邮箱" });
    expect(err.fieldErrors[1]).toMatchObject({ field: "password", userMessage: undefined });
  });
});

describe("fromProblem — full properties", () => {
  it("copies all RFC 9457 fields", () => {
    const body = {
      code: "FOUNDATION.BILLING.QUOTA.EXCEEDED",
      title: "Quota Exceeded",
      detail: "Monthly seat limit reached",
      user_message: "您的配额已用尽",
      request_id: "req_ABC123",
      trace_id: "trace_XYZ",
      retry_after: 60,
      errors: [],
    };
    const err = fromProblem(429, body);
    expect(err.code).toBe("FOUNDATION.BILLING.QUOTA.EXCEEDED");
    expect(err.title).toBe("Quota Exceeded");
    expect(err.detail).toBe("Monthly seat limit reached");
    expect(err.userMessage).toBe("您的配额已用尽");
    expect(err.requestId).toBe("req_ABC123");
    expect(err.traceId).toBe("trace_XYZ");
    expect(err.retryAfter).toBe(60);
    expect(err.raw).toEqual(body);
  });
});

describe("fromProblem — code registry", () => {
  it("custom code takes precedence over status routing", () => {
    class MyCustomError extends FoundationError {}
    registerErrorClass(MyCustomError, "FOUNDATION.CUSTOM.THING.BOOM");

    const err = fromProblem(500, {
      code: "FOUNDATION.CUSTOM.THING.BOOM",
      title: "Custom error",
    });
    expect(err).toBeInstanceOf(MyCustomError);
  });
});

describe("FoundationError — Error subclassing", () => {
  it("has correct name property", () => {
    const err = new AuthError({ code: "FOUNDATION.IDENTITY.AUTH.EXPIRED" });
    expect(err.name).toBe("AuthError");
    expect(err instanceof Error).toBe(true);
  });

  it("message contains code and detail", () => {
    const err = new InputError({ code: "FOUNDATION.IDENTITY.INPUT.INVALID", detail: "bad email" });
    expect(err.message).toContain("FOUNDATION.IDENTITY.INPUT.INVALID");
    expect(err.message).toContain("bad email");
  });
});
