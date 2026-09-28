// Shared context of the branded management commands a built distribution
// runs (login, logout, config, update, rollback, and parts of doctor). None
// of these need the Pi runtime; the Pi integration adds its runtime state.
import { AuditLog, type LocalMetrics } from "@piship/audit";
import { createManagedFetch, formatError } from "@piship/contracts";
import { resolveTemplate } from "@piship/schema";
import {
  type AccessEvent,
  DistributionAccess,
  type DistributionLock,
  type GovernanceLock,
} from "../index.js";

export interface BrandedContext {
  readonly metadata: DistributionLock;
  readonly distributionDir: string;
  readonly stateDir: string;
  readonly mode: "personal" | "managed";
  readonly out: (message: string) => void;
  readonly err: (message: string) => void;
}

/** One doctor report line: a label and its value. */
export type DoctorLine = (label: string, value: string) => void;

/** A lock that declares governance (piship/v1alpha3 and later). */
export type GovernedLock = DistributionLock & {
  readonly governance: GovernanceLock;
};

export function governedLock(ctx: BrandedContext): GovernedLock | null {
  return ctx.metadata.governance ? (ctx.metadata as GovernedLock) : null;
}

export function openAccess(
  ctx: BrandedContext,
  onEvent?: (event: AccessEvent) => void,
  metrics?: LocalMetrics,
): DistributionAccess {
  const capabilities = ctx.metadata.governance?.manifest.capabilities;
  return DistributionAccess.open({
    app: ctx.metadata.app,
    mode: ctx.mode,
    access: ctx.metadata.access,
    stateDir: ctx.stateDir,
    distributionDir: ctx.distributionDir,
    ...(capabilities ? { capabilities } : {}),
    ...(onEvent ? { onEvent } : {}),
    ...(metrics ? { metrics } : {}),
  });
}

/** Local metrics never block a launch or a command. */
export function saveMetrics(metrics: LocalMetrics | undefined): void {
  try {
    metrics?.save();
  } catch {
    // Best effort.
  }
}

/**
 * Identity lifecycle events outside a session. Best effort: signing out must
 * work while the company sink is down, so a failure is reported, not fatal.
 */
export async function auditAccess(
  ctx: BrandedContext,
  access: DistributionAccess,
  user: string | null,
  events: readonly AccessEvent[],
): Promise<void> {
  const lock = governedLock(ctx);
  if (!lock || !events.length) return;
  try {
    const log = await AuditLog.open({
      config: lock.governance.manifest.audit,
      distribution: lock.app.id,
      stateDir: ctx.stateDir,
      fetch: createManagedFetch(access.network, "audit"),
      resolveUrl: (template) =>
        resolveTemplate(
          "audit.sinks.url",
          template,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
    });
    for (const event of events)
      log.emit({
        event: event.event,
        user,
        session: null,
        detail: { mode: access.credentialMode, ...event.detail },
      });
    await log.close();
  } catch (error) {
    ctx.err(`Warning: audit events were not recorded: ${formatError(error)}`);
  }
}
