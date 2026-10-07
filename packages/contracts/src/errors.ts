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
  "REQUEST_CANCELLED",
  "MODEL_DENIED",
  "MODEL_UNAVAILABLE",
  "MODEL_INCOMPATIBLE",
  "NETWORK_DENIED",
  "TLS_POLICY_VIOLATION",
  "POLICY_DENIED",
  "POLICY_UNENFORCEABLE",
  "RADIUS_PROVIDER_RESERVED",
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

/** What a file system error means and what to do, by Node error code. */
const SYSTEM_ERRORS: Readonly<
  Record<string, (path: string | undefined) => [string, string]>
> = {
  ENOENT: (path) => [
    `${path ?? "A path"} does not exist`,
    "Check the path, or pass an absolute path",
  ],
  EISDIR: (path) => [
    `${path ?? "A path"} is a directory where a file was expected`,
    "Pass the file, not the directory that holds it",
  ],
  ENOTDIR: (path) => [
    `${path ?? "A path"} is not a directory, or a part of it is a file`,
    "Check the path",
  ],
  EEXIST: (path) => [
    `${path ?? "A path"} already exists`,
    "Choose another path, or move the existing file away first",
  ],
  EACCES: (path) => [
    `Permission denied for ${path ?? "a path"}`,
    "Check the owner and permissions of the path and its directories",
  ],
  EPERM: (path) => [
    `Operation not permitted on ${path ?? "a path"}`,
    "Check the owner and permissions of the path and its directories",
  ],
  ENOSPC: (path) => [
    `The disk holding ${path ?? "this path"} is full`,
    "Free space on that disk, or set PISHIP_STATE_HOME or PISHIP_INSTALL_HOME to a disk with room",
  ],
  EROFS: (path) => [
    `${path ?? "This path"} is on a read-only file system`,
    "Set PISHIP_STATE_HOME (and PISHIP_INSTALL_HOME for an install) to a writable directory; HOME is read-only here",
  ],
  ENAMETOOLONG: (path) => [
    `The path ${path ? `${path} ` : ""}is too long for this file system`,
    "Use a shorter directory: set PISHIP_STATE_HOME or PISHIP_INSTALL_HOME to a short path, or move the project closer to the drive root",
  ],
  EBUSY: (path) => [
    `${path ?? "A path"} is in use by another program`,
    "Close other programs that may hold it open (an editor, a virus scanner, another PiShip session), then try again",
  ],
  EMFILE: () => [
    "This process has too many files open",
    "Close other programs, or raise the open-files limit (for example ulimit -n 4096), then try again",
  ],
};

/**
 * A PiShip error for a Node file system error (ENOENT, EISDIR, ENOTDIR,
 * EEXIST, EACCES, EPERM, ENOSPC, EROFS, ENAMETOOLONG, EBUSY, EMFILE): it names the path, says what to do, and keeps the
 * system code and call as sanitized detail. `undefined` for anything else.
 */
export function systemError(
  error: unknown,
  path?: string,
  userAction?: string,
): PiShipError | undefined {
  if (!(error instanceof Error) || error instanceof PiShipError)
    return undefined;
  const { code, syscall } = error as NodeJS.ErrnoException;
  const describe = code ? SYSTEM_ERRORS[code] : undefined;
  if (!code || !describe) return undefined;
  const [message, action] = describe(
    path ?? (error as NodeJS.ErrnoException).path,
  );
  return new PiShipError(
    "CONFIG_INVALID",
    `${message} (${code}${syscall ? ` from ${syscall}` : ""})`,
    {
      userAction: userAction ?? action,
      component: "filesystem",
      sanitizedDetail: { code, ...(syscall ? { syscall } : {}) },
      cause: error,
    },
  );
}

/** Human-readable, single-block, redacted rendering for CLI output. */
export function formatError(error: unknown): string {
  const system = systemError(error);
  if (system) return formatError(system);
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
