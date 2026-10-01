import { realpathSync } from "node:fs";
import { LocalMetrics } from "@piship/audit";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
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
import { resolveTemplate } from "@piship/schema";
import {
  accessStatePaths,
  networkPolicyFor,
  resolveRuntimeReferences,
} from "../access/index.js";
import {
  type AccessEvent,
  formatMigrationSummary,
  progressReporter,
  readInstallReceipt,
  rollbackDistribution,
  updateDistribution,
} from "../index.js";
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

function requireInstalled(ctx: BrandedContext, command: string): void {
  if (!installedHere(ctx))
    throw new PiShipError(
      "CONFIG_INVALID",
      `${command} works on an installed distribution; this ${ctx.metadata.app.name} runs from ${ctx.distributionDir}. Install it with piship install first`,
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
 * channel and HTTP audit sinks): the launch's policy. When a runtime
 * reference does not resolve (a gateway variable unset in the shell that runs
 * update), it comes from the manifest alone: the declared proxy setting,
 * private-only, and allowHosts apply as they do at launch, the hosts of the
 * endpoints are not added, and a CA bundle whose path does not resolve is
 * left out. That policy is never wider than the launch's.
 */
export function lifecycleNetwork(ctx: BrandedContext): NetworkPolicy {
  const access = ctx.metadata.access;
  if (!access) return DEFAULT_NETWORK_POLICY;
  let endpoints: ResolvedEndpoints;
  try {
    endpoints = resolveRuntimeReferences(access);
  } catch {
    endpoints = {
      additionalCA: access.network.tls.additionalCA.flatMap((path, index) => {
        try {
          return [
            resolveTemplate(
              `network.tls.additionalCA[${index}]`,
              path,
              access.variables,
              process.env,
            ),
          ];
        } catch {
          return [];
        }
      }),
    };
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

/** Host of the declared update source, when it resolves to a URL. */
function updateSourceHost(ctx: BrandedContext): string | null {
  const template = ctx.metadata.updates?.source;
  if (!template) return null;
  try {
    const source = resolveTemplate(
      "updates.source",
      template,
      ctx.metadata.access?.variables ?? [],
      process.env,
    );
    return /^https?:\/\//.test(source) ? new URL(source).hostname : null;
  } catch {
    return null;
  }
}

export async function runUpdate(
  ctx: BrandedContext,
  args: readonly string[],
): Promise<void> {
  const { app } = ctx.metadata;
  const usage = `Usage: ${app.command} update [--channel <name>] [--from <dir|url>] [--check] [--accept-review]`;
  const options: { channel?: string; source?: string } = {};
  const flags = new Set<string>();
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
  const revokeCredential = credentialRevoker(ctx);
  const network = lifecycleNetwork(ctx);
  // Proxy, CA, and TLS policy apply. Only the update host the distribution
  // declares is added to the allowed hosts; a --from URL gets no exception.
  const declaredHost = updateSourceHost(ctx);
  const fetcher = createManagedFetch(
    {
      ...network,
      allowHosts: declaredHost
        ? [...network.allowHosts, declaredHost]
        : network.allowHosts,
    },
    "update",
  ) as typeof fetch;
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
    if (!check)
      await auditRefusal(ctx, "runtime.update", { from: app.version, code });
    throw error;
  }
  recordLifecycleMetric(ctx, check ? "check" : "update", "ok");
  for (const notice of result.notices) ctx.err(`Notice: ${notice}`);
  if (result.status === "up-to-date") {
    ctx.out(
      `${app.name} ${result.from} is up to date on the ${result.channel} channel.`,
    );
    return;
  }
  if (result.migration) ctx.out(formatMigrationSummary(result.migration));
  if (result.status === "available") {
    ctx.out(
      `${app.name} ${result.to} is available on the ${result.channel} channel (signed by ${result.keyId}); run ${app.command} update to install it.`,
    );
    return;
  }
  await auditLifecycle(ctx, "runtime.update", "allowed", {
    from: result.from,
    to: result.to ?? "",
    channel: result.channel,
    key: result.keyId ?? "",
  });
  ctx.out(
    `Updated ${app.name} ${result.from} -> ${result.to} (${result.channel}, signed by ${result.keyId}). ${result.from} is kept for ${app.command} rollback; sessions and settings were preserved.`,
  );
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
  ctx.out(
    `Rolled back ${app.name} ${result.from} -> ${result.to}. Sessions and settings were preserved; credentials were not restored.`,
  );
}
