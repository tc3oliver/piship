import { redact, redactValue } from "./secret.js";

export const PISHIP_ERROR_CODES = [
  "CONFIG_INVALID",
  "CONFIG_UNAVAILABLE",
  "IDENTITY_REQUIRED",
  "IDENTITY_INVALID",
  "IDENTITY_EXPIRED",
  "CREDENTIAL_REQUIRED",
  "CREDENTIAL_ACQUIRE_FAILED",
  "CREDENTIAL_DENIED",
  "CREDENTIAL_EXPIRED",
  "CREDENTIAL_REVOKED",
  "SECRET_STORE_UNAVAILABLE",
  "GATEWAY_UNREACHABLE",
  "GATEWAY_RATE_LIMITED",
  "GATEWAY_PROTOCOL_ERROR",
  "MODEL_DENIED",
  "MODEL_UNAVAILABLE",
  "MODEL_INCOMPATIBLE",
  "NETWORK_DENIED",
  "TLS_POLICY_VIOLATION",
  "POLICY_DENIED",
  "MCP_DENIED",
  "MCP_UNHEALTHY",
  "SANDBOX_UNAVAILABLE",
  "AUDIT_UNAVAILABLE",
  "LOCK_INVALID",
  "INTEGRITY_FAILED",
  "UPDATE_FAILED",
  "ROLLBACK_FAILED",
] as const;
export type PiShipErrorCode = (typeof PISHIP_ERROR_CODES)[number];

export interface PiShipErrorOptions {
  readonly retryable?: boolean;
  readonly retryAfterMs?: number;
  readonly userAction?: string;
  readonly component?: string;
  readonly sanitizedDetail?: Record<string, unknown>;
  readonly cause?: unknown;
}

/** The public error contract. Message and detail are sanitized on construction. */
export class PiShipError extends Error {
  readonly code: PiShipErrorCode;
  readonly retryable: boolean;
  readonly retryAfterMs: number | undefined;
  readonly userAction: string | undefined;
  readonly component: string | undefined;
  readonly sanitizedDetail: Record<string, unknown> | undefined;
  constructor(
    code: PiShipErrorCode,
    message: string,
    options: PiShipErrorOptions = {},
  ) {
    super(redact(message));
    this.name = "PiShipError";
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.retryAfterMs = options.retryAfterMs;
    this.userAction = options.userAction && redact(options.userAction);
    this.component = options.component;
    this.sanitizedDetail =
      options.sanitizedDetail &&
      (redactValue(options.sanitizedDetail) as Record<string, unknown>);
  }
  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      ...(this.retryAfterMs === undefined
        ? {}
        : { retryAfterMs: this.retryAfterMs }),
      ...(this.userAction ? { userAction: this.userAction } : {}),
      ...(this.component ? { component: this.component } : {}),
      ...(this.sanitizedDetail ? { detail: this.sanitizedDetail } : {}),
    };
  }
}

export function isPiShipError(value: unknown): value is PiShipError {
  return value instanceof PiShipError;
}

/** Human-readable, single-block, redacted rendering for CLI output. */
export function formatError(error: unknown): string {
  if (error instanceof PiShipError)
    return redact(
      `${error.code}: ${error.message}${error.retryAfterMs !== undefined && error.retryAfterMs > 0 ? `\nRetry after: ${Math.ceil(error.retryAfterMs / 1000)} s` : ""}${error.userAction ? `\nAction: ${error.userAction}` : ""}`,
    );
  if (error instanceof Error) return redact(error.message);
  return redact(String(error));
}

/**
 * Parse an HTTP `Retry-After` value (RFC 9110: delay-seconds or an HTTP-date)
 * into a non-negative wait in milliseconds, or `undefined` when absent or
 * malformed.
 */
export function parseRetryAfter(
  header: string | null | undefined,
  now: number = Date.now(),
): number | undefined {
  const text = header?.trim();
  if (!text) return undefined;
  if (/^\d+(\.\d+)?$/.test(text)) return Math.round(Number(text) * 1000);
  // An HTTP-date names its weekday and month; bare numbers are not dates.
  if (!/[a-z]/i.test(text)) return undefined;
  const date = Date.parse(text);
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}
