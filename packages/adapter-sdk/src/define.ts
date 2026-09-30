// The define* helpers. Each one returns what PiShip's loader expects from an
// adapter module's default export, so an adapter file is
// `export default defineXAdapter(...)`. They add types and, for sandboxes,
// the same shape check the loader applies; they hold no other logic.
import type {
  AdapterContext,
  AuditSink,
  CredentialProvider,
  IdentityProvider,
} from "@piship/contracts";
import {
  type CustomBackendContext,
  customBackend,
  type SandboxBackend,
} from "@piship/sandbox";

/** The default export of an identity or credential adapter module. */
export type AdapterFactory<T> = (context: AdapterContext) => T | Promise<T>;

/** An identity adapter (`identity.mode: adapter`). Returns the factory unchanged. */
export function defineIdentityAdapter<T extends IdentityProvider>(
  factory: AdapterFactory<T>,
): AdapterFactory<T> {
  return factory;
}

/** A credential adapter (`credential.provider: adapter`). Returns the factory unchanged. */
export function defineCredentialAdapter<T extends CredentialProvider>(
  factory: AdapterFactory<T>,
): AdapterFactory<T> {
  return factory;
}

/**
 * What a sandbox adapter's factory builds. PiShip fixes `provider` to
 * `custom`, so the adapter does not declare it.
 */
export type SandboxBackendDefinition = Omit<SandboxBackend, "provider">;

/** The default export of a sandbox adapter module (`sandbox.provider: custom`). */
export type SandboxAdapterFactory = (
  context: CustomBackendContext,
) => Promise<SandboxBackend>;

/**
 * A custom sandbox backend. The returned factory passes what `factory`
 * builds through `customBackend()`, the check PiShip's loader applies, so a
 * malformed backend fails in the adapter's own tests too. This is a
 * `SandboxBackend`, not the native OS `SandboxAdapter` of `@piship/sandbox`.
 */
export function defineSandboxAdapter(
  factory: (
    context: CustomBackendContext,
  ) => SandboxBackendDefinition | Promise<SandboxBackendDefinition>,
): SandboxAdapterFactory {
  return async (context) => customBackend(await factory(context));
}

/**
 * An audit sink: what receives `piship-audit-batch/v1` batches. Distributions
 * deliver audit to a collector through the built-in `http` sink; this types a
 * collector's receiving side or a test double. Returns the sink unchanged.
 */
export function defineAuditSink<T extends AuditSink>(sink: T): T {
  return sink;
}

/**
 * A signal that aborts when `signal` does or after `timeoutMs`, whichever
 * comes first. The timeout composes with the caller's cancellation and never
 * replaces it. After an abort, `signal?.aborted` tells a cancellation (not
 * retryable) from a timeout (retryable).
 */
export function withTimeout(
  timeoutMs: number,
  signal?: AbortSignal,
): AbortSignal {
  const deadline = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, deadline]) : deadline;
}
