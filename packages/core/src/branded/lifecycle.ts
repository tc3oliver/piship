import { realpathSync } from "node:fs";
import { AuditLog, LocalMetrics } from "@piship/audit";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  PiShipError,
  formatError,
} from "@piship/contracts";
import { resolveTemplate } from "@piship/schema";
import {
  type AccessEvent,
  formatMigrationReport,
  readInstallReceipt,
  rollbackDistribution,
  updateDistribution,
} from "../index.js";
import {
  type BrandedContext,
  auditAccess,
  governedLock,
  openAccess,
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
      await auditAccess(ctx, access, null, events);
    }
  };
}

/** Deletes secret-store entries for credentials a target release cannot read. */
function secretDeleter(ctx: BrandedContext) {
  if (!ctx.metadata.access) return undefined;
  try {
    const store = openAccess(ctx).store;
    return store ? (ref: string) => store.delete(ref) : undefined;
  } catch {
    return undefined;
  }
}

/** runtime.update and runtime.rollback at their activation boundary; best effort. */
async function auditLifecycle(
  ctx: BrandedContext,
  event: "runtime.update" | "runtime.rollback",
  decision: "allowed" | "denied",
  detail: Record<string, string>,
): Promise<void> {
  const lock = governedLock(ctx);
  if (!lock) return;
  try {
    let network = DEFAULT_NETWORK_POLICY;
    try {
      if (ctx.metadata.access) network = openAccess(ctx).network;
    } catch {
      // The default policy still applies to an HTTP sink.
    }
    const log = await AuditLog.open({
      config: lock.governance.manifest.audit,
      distribution: lock.app.id,
      stateDir: ctx.stateDir,
      fetch: createManagedFetch(network, "audit"),
      resolveUrl: (template) =>
        resolveTemplate(
          "audit.sinks.url",
          template,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
    });
    log.emit({
      event,
      user: null,
      session: null,
      resource: ctx.metadata.app.id,
      decision,
      detail,
    });
    await log.close();
  } catch (error) {
    ctx.err(`Warning: audit events were not recorded: ${formatError(error)}`);
  }
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
  const deleteSecret = secretDeleter(ctx);
  const revokeCredential = credentialRevoker(ctx);
  let network = DEFAULT_NETWORK_POLICY;
  try {
    if (ctx.metadata.access) network = openAccess(ctx).network;
  } catch {
    // Proxy and CA settings default when access cannot be resolved.
  }
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
    result = await updateDistribution(app.id, {
      ...options,
      check,
      acceptReview: flags.has("--accept-review"),
      fetcher,
      ...(deleteSecret ? { deleteSecret } : {}),
      ...(revokeCredential && !check ? { revokeCredential } : {}),
    });
  } catch (error) {
    const code = error instanceof PiShipError ? error.code : "UPDATE_FAILED";
    recordLifecycleMetric(ctx, check ? "check" : "update", code);
    if (!check)
      await auditLifecycle(ctx, "runtime.update", "denied", {
        from: app.version,
        code,
      });
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
  if (result.migration) ctx.out(formatMigrationReport(result.migration));
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
  const deleteSecret = secretDeleter(ctx);
  const revokeCredential = credentialRevoker(ctx);
  let result: Awaited<ReturnType<typeof rollbackDistribution>>;
  try {
    result = await rollbackDistribution(app.id, {
      ...(deleteSecret ? { deleteSecret } : {}),
      ...(revokeCredential ? { revokeCredential } : {}),
    });
  } catch (error) {
    const code = error instanceof PiShipError ? error.code : "ROLLBACK_FAILED";
    recordLifecycleMetric(ctx, "rollback", code);
    await auditLifecycle(ctx, "runtime.rollback", "denied", {
      from: app.version,
      code,
    });
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
