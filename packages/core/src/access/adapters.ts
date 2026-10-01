import { existsSync } from "node:fs";
import { resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
  ADAPTER_CALL_TIMEOUT_MS,
  ADAPTER_INTERACTIVE_TIMEOUT_MS,
  type AdapterContext,
  type CredentialContext,
  type CredentialProvider,
  callWithDeadline,
  PiShipError,
  type RuntimeCredential,
} from "@piship/contracts";

// Defined in @piship/contracts so the adapter SDK can name it without core.
export type { AdapterContext };

export async function loadAdapter<T>(
  distributionDir: string,
  path: string,
  kind: string,
  context: AdapterContext,
  timeoutMs: number = ADAPTER_CALL_TIMEOUT_MS,
): Promise<T> {
  const base = resolve(distributionDir, "resources");
  const absolute = resolve(base, ...path.slice(2).split("/"));
  if (!absolute.startsWith(`${base}${sep}`) || !existsSync(absolute))
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter is missing from the verified payload: ${path}`,
      {
        component: kind,
      },
    );
  // Importing the module and running its factory are the adapter's code: a
  // top-level await or a factory that never settles must not hang PiShip.
  const instance = await callWithDeadline(
    async () => {
      const module = (await import(pathToFileURL(absolute).href)) as {
        default?: unknown;
      };
      if (typeof module.default !== "function")
        throw new PiShipError(
          "CONFIG_INVALID",
          `The ${kind} adapter must default-export a factory function`,
          {
            component: kind,
          },
        );
      return (module.default as (context: AdapterContext) => unknown)(context);
    },
    {
      timeoutMs,
      timedOut: () =>
        new PiShipError(
          "CONFIG_UNAVAILABLE",
          `The ${kind} adapter ${path} did not load within ${Math.ceil(timeoutMs / 1000)} s`,
          {
            component: kind,
            retryable: true,
            sanitizedDetail: {
              adapter: path,
              phase: "load",
              reason: "timeout",
              timeoutMs,
            },
          },
        ),
      // No caller signal: never called.
      cancelled: () => undefined,
    },
  );
  if (!instance || typeof instance !== "object")
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter factory returned no provider`,
      { component: kind },
    );
  return instance as T;
}

/** The deadlines `boundedCredentialProvider` applies (tests shorten them). */
export interface CredentialAdapterDeadlines {
  /** `acquire()`, `refresh()`, and `revoke()`. */
  readonly timeoutMs?: number;
  /** An `acquire()` or `refresh()` given `readSecret`, which may wait for a person. */
  readonly interactiveTimeoutMs?: number;
}

type CredentialPhase = "acquire" | "refresh" | "revoke";

/**
 * Bound every call into a credential adapter (`name`, its path in the
 * manifest). Each call gets `ctx.signal` composed with a deadline
 * (`ADAPTER_CALL_TIMEOUT_MS`, or `ADAPTER_INTERACTIVE_TIMEOUT_MS` when the
 * adapter may prompt through `readSecret`), and PiShip stops waiting at the
 * deadline even if the adapter never settles: the call fails retryably as
 * the built-in broker's timeout does (`CREDENTIAL_ACQUIRE_FAILED`, or
 * `CREDENTIAL_REVOKED` for a revocation, with `outcome: unknown`), so a
 * caller holding the credential lock releases it and a pending issuance
 * keeps its idempotency key.
 *
 * A credential the adapter still returns after PiShip stopped waiting is
 * never stored or used. When the call carried an idempotency key it is left
 * to that key: the next attempt repeats it, and an adapter that honors it
 * returns that same credential, as a broker does for an answer that was
 * lost. Without a key nothing could recover it, so it is revoked through the
 * adapter's `revoke()`, when it has one, with the same deadline.
 */
export function boundedCredentialProvider(
  provider: CredentialProvider,
  name: string,
  deadlines: CredentialAdapterDeadlines = {},
): CredentialProvider {
  const callMs = deadlines.timeoutMs ?? ADAPTER_CALL_TIMEOUT_MS;
  const interactiveMs =
    deadlines.interactiveTimeoutMs ?? ADAPTER_INTERACTIVE_TIMEOUT_MS;
  const failure = (
    phase: CredentialPhase,
    reason: "timeout" | "cancelled",
    outcome: "unknown" | "not-sent",
    timeoutMs: number,
  ) =>
    new PiShipError(
      phase === "revoke" ? "CREDENTIAL_REVOKED" : "CREDENTIAL_ACQUIRE_FAILED",
      reason === "timeout"
        ? `The credential adapter ${name} did not answer ${phase}() within ${Math.ceil(timeoutMs / 1000)} s`
        : `The credential adapter ${name}'s ${phase}() was cancelled`,
      {
        component: "credential",
        retryable: reason === "timeout",
        sanitizedDetail: {
          adapter: name,
          operation: phase === "revoke" ? "revoke" : "acquire",
          phase,
          reason,
          outcome,
          ...(reason === "timeout" ? { timeoutMs } : {}),
        },
      },
    );
  const revoke = provider.revoke?.bind(provider);
  const bounded = <T>(
    phase: CredentialPhase,
    ctx: CredentialContext,
    call: (ctx: CredentialContext) => Promise<T>,
    onLate?: (value: T) => void,
  ): Promise<T> => {
    const timeoutMs =
      phase !== "revoke" && ctx.readSecret ? interactiveMs : callMs;
    // A signal that is already aborted never reaches the adapter.
    const outcome = ctx.signal?.aborted ? "not-sent" : "unknown";
    return callWithDeadline((signal) => call({ ...ctx, signal }), {
      timeoutMs,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
      timedOut: () => failure(phase, "timeout", "unknown", timeoutMs),
      cancelled: () => failure(phase, "cancelled", outcome, timeoutMs),
      ...(onLate ? { onLate } : {}),
    });
  };
  // A credential that arrives after PiShip stopped waiting, for a request
  // no idempotency key can repeat.
  const late =
    (ctx: CredentialContext) => (credential: RuntimeCredential | null) => {
      if (!credential || ctx.idempotencyKey || !revoke) return;
      void bounded("revoke", { distributionId: ctx.distributionId }, (keyed) =>
        revoke(credential, keyed),
      ).catch(() => undefined);
    };
  const refresh = provider.refresh?.bind(provider);
  const wrapped: CredentialProvider & { revocable?: unknown } = {
    mode: provider.mode,
    requiresIdentity: provider.requiresIdentity,
    acquire: (identity, ctx) =>
      bounded(
        "acquire",
        ctx,
        (bound) => provider.acquire(identity, bound),
        late(ctx),
      ),
    ...(refresh
      ? {
          refresh: (identity, current, ctx) =>
            bounded(
              "refresh",
              ctx,
              (bound) => refresh(identity, current, bound),
              late(ctx),
            ),
        }
      : {}),
    ...(revoke
      ? {
          revoke: (credential, ctx) =>
            bounded("revoke", ctx, (bound) => revoke(credential, bound)),
        }
      : {}),
  };
  const revocable = (provider as { revocable?: unknown }).revocable;
  if (revocable !== undefined) wrapped.revocable = revocable;
  return wrapped;
}
