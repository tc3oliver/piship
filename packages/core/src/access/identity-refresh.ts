import { PiShipError } from "@piship/contracts";

/** Refuse a known-expired token, including one another process just stored. */
export function requireUnexpiredIdentity<
  T extends { readonly expiresAt?: Date },
>(session: T, now: number): T {
  if (session.expiresAt && !Number.isFinite(session.expiresAt.getTime()))
    throw new PiShipError(
      "IDENTITY_INVALID",
      "Identity refresh returned an invalid expiry",
      { component: "identity", userAction: "Run login again" },
    );
  if (session.expiresAt && session.expiresAt.getTime() <= now)
    throw new PiShipError(
      "IDENTITY_EXPIRED",
      "Identity refresh returned an expired session",
      { component: "identity", userAction: "Run login again" },
    );
  return session;
}

const MAX_ATTEMPTS = 3;
const MAX_RETRY_AFTER_MS = 1_000;

/**
 * Retry only transient identity-provider failures. Invalid/revoked tokens,
 * cancellations and principal changes must never trigger another refresh.
 * In particular, do not hammer an IdP that requested a long rate-limit wait.
 */
export async function refreshWithRetry<T>(
  refresh: () => Promise<T>,
  options: {
    sleep?: (ms: number) => Promise<void>;
    random?: () => number;
  } = {},
): Promise<T> {
  const sleep =
    options.sleep ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const random = options.random ?? Math.random;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    try {
      return await refresh();
    } catch (error) {
      if (!(error instanceof PiShipError)) throw error;
      const retryAfter = error.retryAfterMs ?? 0;
      if (
        !error.retryable ||
        (error.code !== "GATEWAY_UNREACHABLE" &&
          error.code !== "GATEWAY_RATE_LIMITED") ||
        attempt === MAX_ATTEMPTS - 1 ||
        !Number.isFinite(retryAfter) ||
        retryAfter < 0 ||
        retryAfter > MAX_RETRY_AFTER_MS
      )
        throw error;
      const backoff = Math.max(100 * 2 ** attempt, retryAfter);
      await sleep(backoff + Math.floor(random() * 50));
    }
  }
  throw new Error("Unreachable identity refresh retry state");
}
