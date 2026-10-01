// Deadlines for calls into a distribution's own adapter code: an identity
// or credential adapter, or a custom sandbox backend. PiShip's built-in
// clients bound every request themselves; adapter code is not PiShip's, so
// PiShip bounds each call from outside and stops waiting at the deadline,
// whether or not the adapter honors the signal it was given.

/**
 * How long one call into an adapter may take: twice the 30 s request
 * timeout of PiShip's built-in OIDC, broker, and remote sandbox clients, so
 * an adapter's own request timeout normally answers first and this deadline
 * only ends a call that would never settle.
 */
export const ADAPTER_CALL_TIMEOUT_MS = 60_000;

/**
 * How long an adapter call that waits for a person may take: an identity
 * adapter's `login()`, or a credential adapter given `readSecret`. The same
 * five minutes the built-in OIDC sign-in waits for the browser.
 */
export const ADAPTER_INTERACTIVE_TIMEOUT_MS = 300_000;

export interface DeadlineOptions<T> {
  readonly timeoutMs: number;
  /** The caller's cancellation. It composes with the deadline. */
  readonly signal?: AbortSignal;
  /** The failure when the deadline passes first. */
  readonly timedOut: () => unknown;
  /** The failure when `signal` aborts first, or was aborted already. */
  readonly cancelled: () => unknown;
  /**
   * Receives a value the call resolved after it was abandoned (at the
   * deadline or on cancellation), which no caller sees otherwise. A throw
   * here is ignored.
   */
  readonly onLate?: (value: T) => void;
}

/**
 * Run `call` with a deadline. It receives a signal that aborts at the
 * deadline (reason: a `TimeoutError`) or when `options.signal` does. The
 * returned promise settles by then even if the call never does: with
 * `timedOut()` or `cancelled()`, or with the call's own result if it
 * settled first. A signal that is already aborted fails at once, without
 * calling.
 */
export function callWithDeadline<T>(
  call: (signal: AbortSignal) => T | PromiseLike<T>,
  options: DeadlineOptions<T>,
): Promise<T> {
  const caller = options.signal;
  if (caller?.aborted) return Promise.reject(options.cancelled());
  const deadline = new AbortController();
  const signal = caller
    ? AbortSignal.any([caller, deadline.signal])
    : deadline.signal;
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (): boolean => {
      if (settled) return false;
      settled = true;
      clearTimeout(timer);
      caller?.removeEventListener("abort", onAbort);
      return true;
    };
    const onAbort = () => {
      if (finish()) reject(options.cancelled());
    };
    const timer = setTimeout(() => {
      if (!finish()) return;
      reject(options.timedOut());
      deadline.abort(
        new DOMException(
          "The adapter call ran past its deadline",
          "TimeoutError",
        ),
      );
    }, options.timeoutMs);
    caller?.addEventListener("abort", onAbort, { once: true });
    let running: PromiseLike<T>;
    try {
      running = Promise.resolve(call(signal));
    } catch (error) {
      running = Promise.reject(error);
    }
    running.then(
      (value) => {
        if (finish()) resolve(value);
        else
          try {
            options.onLate?.(value);
          } catch {
            // A late value has no caller left to fail.
          }
      },
      (error: unknown) => {
        if (finish()) reject(error);
      },
    );
  });
}
