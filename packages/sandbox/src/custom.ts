// Custom backends: a company's own sandbox or remote execution service,
// shipped as a module in the distribution. PiShip checks the shape of what
// the module returns and keeps the provider fixed to `custom`; it trusts
// nothing the module declares until activation checked it.
import {
  ADAPTER_CALL_TIMEOUT_MS,
  callWithDeadline,
  type ManagedFetch,
  PiShipError,
} from "@piship/contracts";
import { SANDBOX_ADAPTER_IDS } from "./adapter.js";
import {
  isBackendId,
  SANDBOX_PROVIDERS,
  type SandboxBackend,
  type SandboxInstance,
} from "./backend.js";

/** What a custom adapter module's default-export factory receives. */
export interface CustomBackendContext {
  readonly distributionId: string;
  /** PiShip's managed fetch: proxy, CA, and private-only policy applied. */
  readonly fetch: ManagedFetch;
  /** The resolved `sandbox.endpoint`, when declared. */
  readonly endpoint?: string;
  /**
   * The credential for one request: the runtime credential (`runtime`, when
   * the endpoint is on its origin), the stored sandbox credential (`stored`,
   * for the origins it was stored for), or the adapter module's own
   * `sandboxCredential` export (held in memory), read per request.
   */
  readonly credential?: () => Promise<string | undefined>;
  /**
   * The origins (scheme://host:port) the credential may be sent to: the
   * origins a stored credential was stored for, or the declared endpoint's
   * for the runtime credential and the adapter's own `sandboxCredential`.
   */
  readonly credentialOrigins?: readonly string[];
  /**
   * Report an authentication rejection (HTTP 401) from one of those
   * origins; an authorization denial (403) is not one. Resolves true when a
   * renewed credential is ready for one retry of a request that created
   * nothing.
   */
  readonly credentialRejected?: () => Promise<boolean>;
}

/**
 * How long a custom backend's `prepare()` may take: as long as the built-in
 * Kubernetes backend may, its 120 s readiness wait plus its 30 s requests.
 */
export const CUSTOM_PREPARE_TIMEOUT_MS = 180_000;
/** How long an instance's `dispose()` may take: one 30 s request of a built-in remote backend. */
export const CUSTOM_DISPOSE_TIMEOUT_MS = 30_000;

/** The deadlines `customBackend` applies (tests shorten them). */
export interface CustomBackendDeadlines {
  /** `available()`. Default `ADAPTER_CALL_TIMEOUT_MS`. */
  readonly availableMs?: number;
  /** `prepare()`. Default `CUSTOM_PREPARE_TIMEOUT_MS`. */
  readonly prepareMs?: number;
  /** An instance's `dispose()`. Default `CUSTOM_DISPOSE_TIMEOUT_MS`. */
  readonly disposeMs?: number;
  /**
   * Told when a `dispose()` ran past its deadline, which never fails the
   * caller (a dispose must not throw). Default: one line on stderr.
   */
  readonly notify?: (message: string) => void;
}

const RESERVED = new Set<string>([
  ...SANDBOX_ADAPTER_IDS,
  ...SANDBOX_PROVIDERS,
]);

function invalid(reason: string): Error {
  return new Error(`The custom sandbox adapter is invalid: ${reason}`);
}

/** The retryable failure of a custom backend call that ran past its deadline. */
function timedOut(id: string, phase: string, timeoutMs: number): PiShipError {
  return new PiShipError(
    "SANDBOX_UNAVAILABLE",
    `the ${id} sandbox backend did not answer ${phase}() within ${Math.ceil(timeoutMs / 1000)} s`,
    {
      component: "sandbox",
      retryable: true,
      sanitizedDetail: { adapter: id, phase, reason: "timeout", timeoutMs },
    },
  );
}

function cancelled(id: string, phase: string): PiShipError {
  return new PiShipError(
    "SANDBOX_UNAVAILABLE",
    `the ${id} sandbox backend's ${phase}() was cancelled`,
    {
      component: "sandbox",
      sanitizedDetail: { adapter: id, phase, reason: "cancelled" },
    },
  );
}

function checkInstance(
  value: unknown,
  id: string,
  deadlines: CustomBackendDeadlines,
): SandboxInstance {
  const instance = value as Partial<SandboxInstance> | null;
  if (
    !instance ||
    typeof instance !== "object" ||
    typeof instance.exec !== "function" ||
    typeof instance.dispose !== "function" ||
    (instance.wrap !== undefined && typeof instance.wrap !== "function") ||
    (instance.epoch !== undefined && typeof instance.epoch !== "function")
  )
    throw invalid("prepare() must return an object with exec() and dispose()");
  const exec = instance.exec.bind(instance);
  const dispose = instance.dispose.bind(instance);
  const wrap = instance.wrap?.bind(instance);
  const epoch = instance.epoch?.bind(instance);
  const disposeMs = deadlines.disposeMs ?? CUSTOM_DISPOSE_TIMEOUT_MS;
  const notify =
    deadlines.notify ??
    ((message: string) => process.stderr.write(`${message}\n`));
  return {
    exec: (request, io) => exec(request, io),
    // Bounded, so a hung dispose never hangs quit. At the deadline it
    // resolves, since a dispose must not throw, and says so.
    dispose: async (options) => {
      let late = false;
      await callWithDeadline((signal) => dispose({ signal }), {
        timeoutMs: disposeMs,
        ...(options?.signal ? { signal: options.signal } : {}),
        timedOut: () => {
          late = true;
          return timedOut(id, "dispose", disposeMs);
        },
        cancelled: () => cancelled(id, "dispose"),
      }).catch((error: unknown) => {
        if (!late) throw error;
        try {
          notify(
            `PiShip stopped waiting: ${(error as Error).message}; what the sandbox holds may remain until the backend's service removes it`,
          );
        } catch {
          // A diagnostic never fails the dispose.
        }
      });
    },
    ...(wrap ? { wrap: (command) => wrap(command) } : {}),
    ...(epoch
      ? {
          epoch: () => {
            const value: unknown = epoch();
            return typeof value === "string" ? value : undefined;
          },
        }
      : {}),
  };
}

/**
 * Check a custom adapter's backend object and fix its provider to `custom`.
 *
 * `available()`, `prepare()`, and an instance's `dispose()` are the
 * distribution's code, so each runs with a deadline and a signal that
 * aborts at it, and PiShip stops waiting there even if the backend ignores
 * the signal: `available()` and `prepare()` then fail retryably with
 * `SANDBOX_UNAVAILABLE` naming the backend and the call, and `dispose()`
 * resolves and reports it through `deadlines.notify`. An instance that
 * `prepare()` returns after its deadline is disposed.
 */
export function customBackend(
  value: unknown,
  deadlines: CustomBackendDeadlines = {},
): SandboxBackend {
  const backend = value as Partial<SandboxBackend> | null;
  if (!backend || typeof backend !== "object")
    throw invalid("the factory returned no backend object");
  if (!isBackendId(backend.id))
    throw invalid("id must be a short lowercase identifier");
  if (RESERVED.has(backend.id))
    throw invalid(`id ${backend.id} is reserved for a built-in backend`);
  for (const method of ["available", "capabilities", "prepare"] as const)
    if (typeof backend[method] !== "function")
      throw invalid(`${method}() is missing`);
  const source = backend as SandboxBackend;
  const id = source.id;
  const availableMs = deadlines.availableMs ?? ADAPTER_CALL_TIMEOUT_MS;
  const prepareMs = deadlines.prepareMs ?? CUSTOM_PREPARE_TIMEOUT_MS;
  return {
    id,
    provider: "custom",
    available: (options) =>
      callWithDeadline((signal) => source.available({ signal }), {
        timeoutMs: availableMs,
        ...(options?.signal ? { signal: options.signal } : {}),
        timedOut: () => timedOut(id, "available", availableMs),
        cancelled: () => cancelled(id, "available"),
      }),
    capabilities: () => source.capabilities(),
    prepare: async (request) =>
      checkInstance(
        await callWithDeadline(
          (signal) => source.prepare({ ...request, signal }),
          {
            timeoutMs: prepareMs,
            ...(request.signal ? { signal: request.signal } : {}),
            timedOut: () => timedOut(id, "prepare", prepareMs),
            cancelled: () => cancelled(id, "prepare"),
            // Nobody holds an instance that arrives late: release it.
            onLate: (late) => {
              try {
                void checkInstance(late, id, deadlines)
                  .dispose()
                  .catch(() => undefined);
              } catch {
                // Not an instance: nothing to release.
              }
            },
          },
        ),
        id,
        deadlines,
      ),
  };
}
