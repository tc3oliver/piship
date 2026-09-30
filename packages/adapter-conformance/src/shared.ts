// Helpers the kits share: how a check fails, how a call to the adapter is
// bounded, how an error or a value is searched for a secret, and how a
// failure is held to the error contract. Internal: the barrel does not
// export this module, and the package exports only its barrel.
import { inspect } from "node:util";
import {
  formatError,
  isPiShipError,
  type PiShipError,
  type PiShipErrorCode,
} from "@piship/adapter-sdk";

/** A failed sub-check: a short reason without any secret. */
export class Finding extends Error {}

/** Fail the check with `reason` unless `condition` holds. */
export function check(condition: unknown, reason: string): asserts condition {
  if (!condition) throw new Finding(reason);
}

/** How a bounded call to the adapter ended. */
export type Outcome<T> =
  | { readonly kind: "resolved"; readonly value: T }
  | { readonly kind: "rejected"; readonly error: unknown }
  | { readonly kind: "hung" };

/**
 * Settle `call`, or report it hung after `ms`; never rejects. A synchronous
 * throw is a rejection. When the call hangs and `release` is given, the kit
 * calls it to end whatever the call is waiting on, and waits up to a second
 * for the call to end, so nothing keeps running after the check.
 */
export async function settle<T>(
  call: () => T | Promise<T>,
  ms: number,
  release?: () => void,
): Promise<Outcome<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const hung = new Promise<"hung">((resolve) => {
    timer = setTimeout(() => resolve("hung"), ms);
  });
  const running = (async () => call())().then(
    (value): Outcome<T> => ({ kind: "resolved", value }),
    (error: unknown): Outcome<T> => ({ kind: "rejected", error }),
  );
  const first = await Promise.race([running, hung]);
  clearTimeout(timer);
  if (first !== "hung") return first;
  if (release) {
    release();
    await Promise.race([running, new Promise((r) => setTimeout(r, 1_000))]);
  }
  return { kind: "hung" };
}

/** The failure a call must end in, or a finding. */
export function rejection(outcome: Outcome<unknown>, what: string): unknown {
  check(
    outcome.kind !== "hung",
    `${what}: the call did not end within the kit's bound`,
  );
  check(
    outcome.kind === "rejected",
    `${what}: the call succeeded instead of failing`,
  );
  return outcome.error;
}

export interface Expected {
  readonly codes: readonly PiShipErrorCode[];
  readonly retryable?: boolean;
  /** An exact wait, or an inclusive range for an HTTP-date. */
  readonly retryAfterMs?: number | readonly [number, number];
}

/** Check a failure against the error contract. Reasons carry codes and numbers only. */
export function expectError(
  error: unknown,
  what: string,
  expected: Expected,
): PiShipError {
  check(
    isPiShipError(error),
    `${what}: the failure is not a PiShipError from @piship/adapter-sdk`,
  );
  check(
    expected.codes.includes(error.code),
    `${what}: expected ${expected.codes.join(" or ")}, got ${error.code}`,
  );
  if (expected.retryable !== undefined)
    check(
      error.retryable === expected.retryable,
      `${what}: expected retryable ${expected.retryable}, got ${error.retryable}`,
    );
  const wait = expected.retryAfterMs;
  if (typeof wait === "number")
    check(
      error.retryAfterMs === wait,
      `${what}: expected retryAfterMs ${wait}, got ${error.retryAfterMs ?? "none"}`,
    );
  else if (wait)
    check(
      error.retryAfterMs !== undefined &&
        error.retryAfterMs >= wait[0] &&
        error.retryAfterMs <= wait[1],
      `${what}: expected retryAfterMs between ${wait[0]} and ${wait[1]}, got ${error.retryAfterMs ?? "none"}`,
    );
  return error;
}

/** Every way a value can be shown: strings, JSON, inspection, and each cause. */
export function renderings(value: unknown): string {
  const parts: string[] = [];
  const safe = (render: () => unknown) => {
    try {
      parts.push(String(render()));
    } catch {
      // A rendering that throws shows nothing.
    }
  };
  let current: unknown = value;
  for (
    let depth = 0;
    depth < 6 && current !== undefined && current !== null;
    depth++
  ) {
    const item = current;
    safe(() => item);
    safe(() => JSON.stringify(item));
    safe(() => inspect(item, { depth: 10, showHidden: true }));
    if (item instanceof Error) {
      safe(() => item.message);
      safe(() => item.stack);
      safe(() => formatError(item));
    }
    if (isPiShipError(item)) {
      safe(() => item.userAction);
      safe(() => JSON.stringify(item.sanitizedDetail));
      safe(() => JSON.stringify(item.toJSON()));
    }
    current = (item as { cause?: unknown } | null)?.cause;
  }
  return parts.join("\n");
}

/** Whether any rendering of `value` shows one of `secrets`. */
export function secretsIn(value: unknown, secrets: readonly string[]): boolean {
  const text = renderings(value);
  return secrets.some((secret) => text.includes(secret));
}

/** What a SecretValue holds, or undefined for anything else. */
export function revealed(secret: unknown): string | undefined {
  try {
    const value = (secret as { reveal?: () => unknown } | null)?.reveal?.();
    return typeof value === "string" ? value : undefined;
  } catch {
    return undefined;
  }
}

/** A session's or a credential's `expiresAt` in milliseconds, if it has one. */
export function expiryOf(value: {
  readonly expiresAt?: unknown;
}): number | undefined {
  const expiresAt: unknown = value.expiresAt;
  if (expiresAt instanceof Date) return expiresAt.getTime();
  if (typeof expiresAt === "string") return Date.parse(expiresAt);
  return undefined;
}

/** A failure's code for a reason; never its message, which may hold a secret. */
export function codeOf(error: unknown): string {
  return isPiShipError(error)
    ? error.code
    : error instanceof Error
      ? `a ${error.name} that is not a PiShipError`
      : "a value that is not an error";
}

/** A service answer with `code`, the given headers, and a text body. */
export function answer(
  code: number,
  headers: Record<string, string> = {},
  body = "",
): Response {
  return new Response(body, { status: code, headers });
}

/** A request as one text: its decoded URL, its headers, and its body. */
export function requestText(request: {
  readonly url: string;
  readonly headers: Headers;
  readonly body: string;
}): string {
  return `${decodeURIComponent(request.url)}\n${[...request.headers].map(([k, v]) => `${k}: ${v}`).join("\n")}\n${request.body}`;
}

/** The `Retry-After` seconds the kits send with a 429. */
export const RETRY_AFTER_SECONDS = 7;
