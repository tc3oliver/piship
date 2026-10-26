import { PiShipError } from "@piship/contracts";

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
      if (
        !(error instanceof PiShipError) ||
        !error.retryable ||
        (error.code !== "GATEWAY_UNREACHABLE" &&
          error.code !== "GATEWAY_RATE_LIMITED") ||
        attempt === MAX_ATTEMPTS - 1 ||
        (error.retryAfterMs ?? 0) > MAX_RETRY_AFTER_MS
      )
        throw error;
      const backoff = Math.max(100 * 2 ** attempt, error.retryAfterMs ?? 0);
      await sleep(backoff + Math.floor(random() * 50));
    }
  }
  throw new Error("Unreachable identity refresh retry state");
}
