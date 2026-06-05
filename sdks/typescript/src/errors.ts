/**
 * Error hierarchy for Foundation SDK.
 *
 * Mirrors Python SDK foundation_sdk/errors.py:
 *   - FoundationError base class with RFC 9457 Problem Details fields
 *   - Subclasses keyed by HTTP status code
 *   - fromProblem() factory that routes to the correct subclass
 */

export interface FieldError {
  field: string;
  code: string;
  detail: string;
  userMessage?: string;
}

export interface ProblemDetails {
  code?: string;
  title?: string;
  detail?: string;
  user_message?: string;
  request_id?: string;
  trace_id?: string;
  retry_after?: number;
  errors?: Array<{
    field: string;
    code: string;
    detail: string;
    user_message?: string;
  }>;
  [key: string]: unknown;
}

export interface FoundationErrorParams {
  code?: string;
  httpStatus?: number;
  title?: string;
  detail?: string;
  userMessage?: string;
  requestId?: string;
  traceId?: string;
  retryAfter?: number;
  fieldErrors?: FieldError[];
  raw?: ProblemDetails;
}

/** Minimal constructor shape required for the error registry. */
export interface FoundationErrorConstructor {
  new (params: FoundationErrorParams): FoundationError;
}

export class FoundationError extends Error {
  readonly code: string;
  readonly httpStatus: number;
  readonly title: string;
  readonly detail: string;
  readonly userMessage: string | undefined;
  readonly requestId: string | undefined;
  readonly traceId: string | undefined;
  readonly retryAfter: number | undefined;
  readonly fieldErrors: FieldError[];
  readonly raw: ProblemDetails;

  constructor(params: FoundationErrorParams = {}) {
    const code = params.code ?? "FOUNDATION._.INTERNAL.UNEXPECTED";
    const detail = params.detail ?? params.title ?? code;
    super(`[${code}] ${detail}`);
    this.name = new.target.name;
    this.code = code;
    this.httpStatus = params.httpStatus ?? 500;
    this.title = params.title ?? "";
    this.detail = params.detail ?? "";
    this.userMessage = params.userMessage;
    this.requestId = params.requestId;
    this.traceId = params.traceId;
    this.retryAfter = params.retryAfter;
    this.fieldErrors = params.fieldErrors ?? [];
    this.raw = params.raw ?? {};
  }
}

export class AuthError extends FoundationError {}
export class PolicyError extends FoundationError {}
export class InputError extends FoundationError {}
export class ValidationError extends FoundationError {}
export class ResourceNotFoundError extends FoundationError {}
export class ConflictError extends FoundationError {}
export class QuotaExceededError extends FoundationError {}
export class RateLimitedError extends FoundationError {}
export class DependencyError extends FoundationError {}
export class ComplianceError extends FoundationError {}
export class InternalError extends FoundationError {}

const STATUS_TO_CLASS: Record<number, FoundationErrorConstructor> = {
  400: InputError,
  401: AuthError,
  403: PolicyError,
  404: ResourceNotFoundError,
  409: ConflictError,
  422: ValidationError,
  429: RateLimitedError,
  500: InternalError,
  502: DependencyError,
  503: DependencyError,
  504: DependencyError,
};

// Extensible registry: call registerErrorClass() to add custom mappings.
const codeToClass: Map<string, FoundationErrorConstructor> = new Map();

export function registerErrorClass(cls: FoundationErrorConstructor, code: string): void {
  codeToClass.set(code, cls);
}

/**
 * Parse an RFC 9457 Problem Details body into the appropriate FoundationError subclass.
 * Routing order: code registry → HTTP status → FoundationError base.
 */
export function fromProblem(status: number, body: ProblemDetails): FoundationError {
  const Cls: FoundationErrorConstructor =
    (body.code != null ? codeToClass.get(body.code) : undefined) ??
    STATUS_TO_CLASS[status] ??
    FoundationError;

  const fieldErrors: FieldError[] = (body.errors ?? []).map((fe) => ({
    field: fe.field,
    code: fe.code,
    detail: fe.detail,
    userMessage: fe.user_message,
  }));

  return new Cls({
    code: body.code,
    httpStatus: status,
    title: body.title ?? "",
    detail: body.detail ?? "",
    userMessage: body.user_message,
    requestId: body.request_id,
    traceId: body.trace_id,
    retryAfter: body.retry_after,
    fieldErrors,
    raw: body,
  });
}
