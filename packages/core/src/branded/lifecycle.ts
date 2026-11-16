import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { LocalMetrics } from "@piship/audit";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  isLoopbackHost,
  type NetworkPolicy,
  PiShipError,
  type ResolvedEndpoints,
  type SecretStore,
  formatError,
} from "@piship/contracts";
import {
  createSecretStore,
  type SecretStoreProvider,
} from "@piship/credentials";
import { plainHttpUpdateAllowed, resolveTemplate } from "@piship/schema";
import {
  accessStatePaths,
  networkPolicyFor,
  resolveAdditionalCA,
  resolveRuntimeReferences,
} from "../access/index.js";
import {
  type AccessEvent,
  diffLocks,
  formatGovernanceSummary,
  formatMigrationSummary,
  progressReporter,
  readInstallReceipt,
  rollbackDistribution,
  updateDistribution,
} from "../index.js";
import { writeJsonAtomic } from "../access/state.js";
import { activeLock } from "../install/receipt.js";
import { runtimeLeases } from "../install/runtime-lease.js";
import { shellArg } from "../invocation.js";
import {
  type BrandedContext,
  auditAccess,
  governedLock,
  openAccess,
  recordAudit,
} from "./context.js";

/** The installed receipt when this payload is the active installed release. */
export function installedHere(ctx: BrandedContext) {
  try {
    const receipt = readInstallReceipt(ctx.metadata.app.id);
    // Compare real paths: on macOS the install home may sit behind /var.
    return realpathSync(receipt.payload) === realpathSync(ctx.distributionDir)
      ? receipt
      : null;
  } catch {
    return null;
  }
}

export function requireInstalled(ctx: BrandedContext, command: string): void {
  if (!installedHere(ctx))
    throw new PiShipError(
      "CONFIG_INVALID",
      `${command} works on an installed distribution; this ${ctx.metadata.app.name} runs from ${ctx.distributionDir}. Install it first: node ${shellArg(join(ctx.distributionDir, "piship.mjs"))} install ${shellArg(ctx.distributionDir)}`,
    );
}

/**
 * Best-effort remote revocation, by this (the switching) release, of a
 * runtime credential a target release cannot read. The outcome is audited;
 * local clearing happens whatever it is.
 */
function credentialRevoker(ctx: BrandedContext) {
  if (!ctx.metadata.access) return undefined;
  return async () => {
    const events: AccessEvent[] = [];
    const access = openAccess(ctx, (event) => events.push(event));
    try {
      return await access.revokeCredential();
    } finally {
      // Reported, not thrown: the switch is under way. A required sink that
      // is still down also fails the runtime.update or runtime.rollback
      // record at the end of the command.
      await auditAccess(ctx, access, null, events).catch((error) =>
        ctx.err(`Error: ${formatError(error)}`),
      );
    }
  };
}

/**
 * The secret store of this distribution's credentials, for deleting those a
 * target release cannot read. It is selected from the lock alone, like the
 * store sign-in wrote to, so it needs no runtime variable; a store that
 * cannot delete fails the switch instead of leaving secrets behind.
 */
function secretStore(ctx: BrandedContext): SecretStore {
  return storeOf(
    ctx,
    ctx.metadata.access?.credential.storage.provider ?? "system",
  );
}

/** The store of `provider`, which credential metadata may record instead. */
function storeOf(
  ctx: BrandedContext,
  provider: SecretStoreProvider,
): SecretStore {
  return createSecretStore({
    provider,
    fileDirectory: accessStatePaths(ctx.stateDir).secrets,
  });
}

/**
 * The network policy of update and rollback's own requests (the update
 * channel and HTTP audit sinks): the launch's policy. When an endpoint
 * reference does not resolve (a gateway variable unset in the shell that runs
 * update), it comes from the manifest alone: the declared proxy setting,
 * private-only, and allowHosts apply as they do at launch, and the hosts of
 * the endpoints are not added. That policy is never wider than the launch's.
 * A declared CA bundle is never left out: an unset variable in
 * network.tls.additionalCA throws CONFIG_UNAVAILABLE naming it, as launch
 * does, before any request is attempted.
 */
export function lifecycleNetwork(ctx: BrandedContext): NetworkPolicy {
  const access = ctx.metadata.access;
  if (!access) return DEFAULT_NETWORK_POLICY;
  const additionalCA = resolveAdditionalCA(access);
  let endpoints: ResolvedEndpoints;
  try {
    endpoints = resolveRuntimeReferences(access);
  } catch {
    endpoints = { additionalCA };
  }
  return networkPolicyFor(access, endpoints, ctx.mode);
}

/**
 * runtime.update and runtime.rollback at their activation boundary. Best
 * effort for optional sinks; throws AUDIT_UNAVAILABLE when a required sink
 * does not take the event (see recordAudit).
 */
export async function auditLifecycle(
  ctx: BrandedContext,
  event: "runtime.update" | "runtime.rollback",
  decision: "allowed" | "denied",
  detail: Record<string, string>,
): Promise<void> {
  if (!governedLock(ctx)) return;
  await recordAudit(ctx, lifecycleNetwork(ctx), [
    {
      event,
      user: null,
      session: null,
      resource: ctx.metadata.app.id,
      decision,
      detail,
    },
  ]);
}

/**
 * Record a refusal while its error is propagating: an audit failure is
 * printed so it is not lost, and the refusal stays the command's error.
 */
async function auditRefusal(
  ctx: BrandedContext,
  event: "runtime.update" | "runtime.rollback",
  detail: Record<string, string>,
): Promise<void> {
  await auditLifecycle(ctx, event, "denied", detail).catch((error) =>
    ctx.err(`Error: ${formatError(error)}`),
  );
}

/** Sessions started before a switch keep the release they started with. */
function reportRunningSessions(
  ctx: BrandedContext,
  from: string,
  to: string,
): void {
  let running = 0;
  try {
    running = runtimeLeases(ctx.metadata.app.id).filter(
      (lease) => lease.live && !lease.self && lease.version === from,
    ).length;
  } catch {
    // Only a hint: the switch is committed.
  }
  if (running)
    ctx.out(
      `${running} running ${ctx.metadata.app.name} session(s) still use ${from}; restart them to use ${to}.`,
    );
}

function recordLifecycleMetric(
  ctx: BrandedContext,
  kind: "update" | "check" | "rollback",
  outcome: string,
): void {
  try {
    const metrics = LocalMetrics.load(ctx.stateDir);
    metrics.recordLifecycle(kind, outcome);
    metrics.save();
  } catch {
    // Local metrics never block a lifecycle operation.
  }
}

const FAILED_ATTEMPT_SCHEMA = "piship-update-failure/v1";

/** The last update or check that failed, kept beside the metrics. */
export interface FailedAttempt {
  readonly kind: "update" | "check";
  readonly time: string;
  readonly code: string;
  readonly reason: string;
}

function failedAttemptPath(stateDir: string): string {
  return join(stateDir, "logs", "update-failure.json");
}

/**
 * A failed attempt is recorded here, not in the receipt, which a failure
 * leaves unchanged; doctor shows it while it is newer than the last check.
 */
function recordFailedAttempt(
  ctx: BrandedContext,
  kind: FailedAttempt["kind"],
  code: string,
  error: unknown,
): void {
  try {
    // A PiShipError message is already redacted.
    const message =
      error instanceof PiShipError ? error.message : "unexpected error";
    writeJsonAtomic(failedAttemptPath(ctx.stateDir), {
      schema: FAILED_ATTEMPT_SCHEMA,
      kind,
      time: new Date().toISOString(),
      code,
      reason: message.slice(0, 500),
    });
  } catch {
    // Never blocks the error the person is about to see.
  }
}

/** The recorded failed attempt; anything unreadable counts as none. */
export function readFailedAttempt(stateDir: string): FailedAttempt | undefined {
  try {
    const value = JSON.parse(
      readFileSync(failedAttemptPath(stateDir), "utf8"),
    ) as Record<string, unknown>;
    if (
      value.schema !== FAILED_ATTEMPT_SCHEMA ||
      (value.kind !== "update" && value.kind !== "check") ||
      typeof value.time !== "string" ||
      Number.isNaN(Date.parse(value.time)) ||
      typeof value.code !== "string" ||
      typeof value.reason !== "string"
    )
      return undefined;
    return {
      kind: value.kind,
      time: value.time,
      code: value.code,
      reason: value.reason,
    };
  } catch {
    return undefined;
  }
}

/** The declared update source, when it resolves to a URL. */
function declaredSourceUrl(ctx: BrandedContext): URL | null {
  const template = ctx.metadata.updates?.source;
  if (!template) return null;
  try {
    const source = resolveTemplate(
      "updates.source",
      template,
      ctx.metadata.access?.variables ?? [],
      process.env,
    );
    return /^https?:\/\//.test(source) ? new URL(source) : null;
  } catch {
    return null;
  }
}

/**
 * Whether this update reads its channel over plain HTTP from a non-loopback
 * host (allowed unless `updates.transport: https`), from `--from` or the
 * declared source. Audit records it as `transport: http`.
 */
function overPlainHttp(ctx: BrandedContext, from: string | undefined): boolean {
  let url: URL | null;
  try {
    url = from === undefined ? declaredSourceUrl(ctx) : new URL(from);
  } catch {
    return false;
  }
  return url?.protocol === "http:" && !isLoopbackHost(url.hostname);
}

/** The options `update` accepts, as its usage and the branded help print them. */
export const UPDATE_OPTIONS =
  "[--channel <name>] [--from <dir|url>] [--check] [--accept-review]";

export async function runUpdate(
  ctx: BrandedContext,
  args: readonly string[],
): Promise<void> {
  const { app } = ctx.metadata;
  const usage = `Usage: ${app.command} update ${UPDATE_OPTIONS}`;
  const options: { channel?: string; source?: string } = {};
  const flags = new Set<string>();
  if (args.includes("--help") || args.includes("-h")) {
    ctx.out(usage);
    return;
  }
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];
    if ((arg === "--channel" || arg === "--from") && value !== undefined) {
      if (arg === "--channel") options.channel = value;
      else options.source = value;
      index += 1;
    } else if (arg === "--check" || arg === "--accept-review") flags.add(arg);
    else throw new PiShipError("CONFIG_INVALID", usage);
  }
  requireInstalled(ctx, `${app.command} update`);
  const check = flags.has("--check");
  const before = readInstallReceipt(app.id);
  const followed = before.channel ?? ctx.metadata.updates?.channel;
  const revokeCredential = credentialRevoker(ctx);
  const network = lifecycleNetwork(ctx);
  // Proxy, CA, and TLS policy apply. Only the update host the distribution
  // declares is added to the allowed hosts; a --from URL gets no exception.
  // Plain HTTP beyond loopback only to a private or internal host, unless
  // updates.transport is https, and only on this fetch.
  const declaredHost = declaredSourceUrl(ctx)?.hostname;
  const transport = ctx.metadata.updates?.transport;
  const fetcher = createManagedFetch(
    {
      ...network,
      allowHosts: declaredHost
        ? [...network.allowHosts, declaredHost]
        : network.allowHosts,
    },
    "update",
    { plainHttp: (target) => plainHttpUpdateAllowed(target, transport) },
  ) as typeof fetch;
  // Checks are audited only when they read the channel over plain HTTP.
  const http = overPlainHttp(ctx, options.source);
  const viaHttp: Record<string, string> = http ? { transport: "http" } : {};
  let result: Awaited<ReturnType<typeof updateDistribution>>;
  try {
    const progress = progressReporter(ctx.err);
    result = await updateDistribution(app.id, {
      ...options,
      ...(progress ? { progress } : {}),
      check,
      acceptReview: flags.has("--accept-review"),
      fetcher,
      secretStore: secretStore(ctx),
      secretStoreFor: (provider) => storeOf(ctx, provider),
      ...(revokeCredential && !check ? { revokeCredential } : {}),
    });
  } catch (error) {
    const code = error instanceof PiShipError ? error.code : "UPDATE_FAILED";
    recordLifecycleMetric(ctx, check ? "check" : "update", code);
    recordFailedAttempt(ctx, check ? "check" : "update", code, error);
    if (!check || http)
      await auditRefusal(ctx, "runtime.update", {
        from: app.version,
        code,
        ...(check ? { check: "failed" } : {}),
        ...viaHttp,
      });
    throw error;
  }
  recordLifecycleMetric(ctx, check ? "check" : "update", "ok");
  for (const notice of result.notices) ctx.err(`Notice: ${notice}`);
  if (check && http)
    await auditLifecycle(ctx, "runtime.update", "allowed", {
      from: result.from,
      ...(result.to ? { to: result.to } : {}),
      channel: result.channel,
      key: result.keyId ?? "",
      check: result.status,
      ...viaHttp,
    });
  // A check reports without switching; an update saves the channel it used.
  const switched =
    !check && followed !== undefined && followed !== result.channel
      ? `Now following ${result.channel} (was ${followed}); run ${app.command} update --channel ${followed} to return.`
      : undefined;
  if (result.status === "up-to-date") {
    ctx.out(
      `${app.name} ${result.from} is up to date on the ${result.channel} channel.`,
    );
    if (switched) ctx.out(switched);
    return;
  }
  if (result.migration) ctx.out(formatMigrationSummary(result.migration));
  if (result.status === "available") {
    // Only a rollback retains a release newer than the active one.
    const rolledBack =
      result.to === before.previous
        ? " (you rolled back from this version)"
        : "";
    ctx.out(
      `${app.name} ${result.to}${rolledBack} is available on the ${result.channel} channel (signed by ${result.keyId}); run ${app.command} update${check && result.channel !== followed ? ` --channel ${result.channel}` : ""} to install it.`,
    );
    return;
  }
  await auditLifecycle(ctx, "runtime.update", "allowed", {
    from: result.from,
    to: result.to ?? "",
    channel: result.channel,
    key: result.keyId ?? "",
    ...viaHttp,
  });
  ctx.out(
    `Updated ${app.name} ${result.from} -> ${result.to} (${result.channel}, signed by ${result.keyId}). ${result.from} is kept for ${app.command} rollback; sessions and settings were preserved.`,
  );
  if (switched) ctx.out(switched);
  reportRunningSessions(ctx, result.from, result.to ?? "");
  // Best effort: the update is committed whatever this summary does.
  try {
    const summary = formatGovernanceSummary(
      diffLocks(ctx.metadata, activeLock(readInstallReceipt(app.id))),
      app.command,
    );
    if (summary) ctx.out(summary);
  } catch {
    // No summary.
  }
}

export async function runRollback(ctx: BrandedContext): Promise<void> {
  const { app } = ctx.metadata;
  requireInstalled(ctx, `${app.command} rollback`);
  const revokeCredential = credentialRevoker(ctx);
  let result: Awaited<ReturnType<typeof rollbackDistribution>>;
  try {
    const progress = progressReporter(ctx.err);
    result = await rollbackDistribution(app.id, {
      ...(progress ? { progress } : {}),
      secretStore: secretStore(ctx),
      secretStoreFor: (provider) => storeOf(ctx, provider),
      ...(revokeCredential ? { revokeCredential } : {}),
    });
  } catch (error) {
    const code = error instanceof PiShipError ? error.code : "ROLLBACK_FAILED";
    recordLifecycleMetric(ctx, "rollback", code);
    await auditRefusal(ctx, "runtime.rollback", { from: app.version, code });
    throw error;
  }
  recordLifecycleMetric(ctx, "rollback", "ok");
  await auditLifecycle(ctx, "runtime.rollback", "allowed", {
    from: result.from,
    to: result.to,
  });
  for (const notice of result.notices) ctx.err(`Notice: ${notice}`);
  const access = ctx.metadata.access;
  // A cleared credential is reported as a notice, so the claim is made only without one.
  const signIn =
    result.notices.length === 0 &&
    ((access?.identity?.mode !== undefined &&
      access.identity.mode !== "none") ||
      (access?.credential?.provider !== undefined &&
        access.credential.provider !== "pi-native" &&
        access.credential.provider !== "none"));
  ctx.out(
    `Rolled back ${app.name} ${result.from} -> ${result.to}. Sessions and settings were preserved${signIn ? "; your sign-in was left as it is" : ""}.`,
  );
  reportRunningSessions(ctx, result.from, result.to);
}
