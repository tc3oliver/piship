// Shared context of the branded management commands a built distribution
// runs (login, logout, config, update, rollback, and parts of doctor). None
// of these need the Pi runtime; the Pi integration adds its runtime state.
import {
  type AuditEmitInput,
  AuditLog,
  type AuditStatus,
  type LocalMetrics,
  requiredAuditLoss,
} from "@piship/audit";
import {
  createManagedFetch,
  formatError,
  type NetworkPolicy,
  PiShipError,
  plainHttpOrigins,
} from "@piship/contracts";
import { resolveTemplate } from "@piship/schema";
import { auditRotation } from "../data/lifecycle.js";
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
  /** Test seam: how long the final audit flush may retry a required sink. */
  readonly auditCloseDeadlineMs?: number;
  /**
   * Set only by a launch that may prompt: a launch that finds no usable
   * sign-in runs this login on its access instead of failing with "Run
   * <command> login". Absent for every command and launch that must not
   * prompt, which then keep the failure.
   */
  readonly loginInline?: (access: DistributionAccess) => Promise<void>;
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
  const loginInline = ctx.loginInline;
  const access: DistributionAccess = DistributionAccess.open({
    app: ctx.metadata.app,
    mode: ctx.mode,
    access: ctx.metadata.access,
    stateDir: ctx.stateDir,
    distributionDir: ctx.distributionDir,
    ...(capabilities ? { capabilities } : {}),
    ...(onEvent ? { onEvent } : {}),
    ...(metrics ? { metrics } : {}),
    ...(loginInline ? { loginInline: () => loginInline(access) } : {}),
  });
  return access;
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
 * Record audit events of a command that runs outside a governed session
 * (login, logout, update, rollback). The events describe an operation that
 * has already happened, so recording never undoes it. Optional sinks stay
 * best effort: a failure is a warning. A required sink must take every
 * event: when it cannot be opened or does not take them all, this throws
 * AUDIT_UNAVAILABLE and the command fails. A caller that records before
 * the operation, and does not run it when this throws, passes a `prefix`
 * that says so.
 */
export async function recordAudit(
  ctx: BrandedContext,
  network: NetworkPolicy,
  events: readonly AuditEmitInput[],
  prefix = "The operation completed, but its audit was not recorded",
): Promise<void> {
  const lock = governedLock(ctx);
  if (!lock || !events.length) return;
  const config = lock.governance.manifest.audit;
  const required = config.enabled && config.sinks.some((sink) => sink.required);
  let status: AuditStatus;
  try {
    const log = await AuditLog.open({
      config,
      distribution: lock.app.id,
      stateDir: ctx.stateDir,
      rotation: auditRotation(lock),
      fetch: createManagedFetch(network, "audit"),
      // A sink not set to httpTransport: https: plain HTTP to its own
      // origin only.
      plainHttpFetch: (url) => {
        const plainHttp = plainHttpOrigins([url]);
        return createManagedFetch(
          network,
          "audit",
          plainHttp ? { plainHttp } : {},
        );
      },
      resolveUrl: (template) =>
        resolveTemplate(
          "audit.sinks.url",
          template,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
    });
    for (const event of events) log.emit(event);
    status = await log.close(ctx.auditCloseDeadlineMs);
  } catch (error) {
    if (!required) {
      ctx.err(`Warning: audit events were not recorded: ${formatError(error)}`);
      return;
    }
    throw new PiShipError(
      "AUDIT_UNAVAILABLE",
      `${prefix}: ${error instanceof PiShipError ? error.message : formatError(error)}`,
      {
        component: "audit",
        userAction:
          "Restore the required audit sink and report the unrecorded activity to the distribution administrator",
      },
    );
  }
  const loss = requiredAuditLoss(status, prefix);
  if (loss) throw loss;
}

/**
 * An access event's audit detail with the runtime credential's mode, except
 * for a sandbox credential event, which names its purpose and source instead.
 */
export function eventDetail(
  mode: string,
  detail: AccessEvent["detail"],
): AccessEvent["detail"] {
  return detail.purpose === "sandbox" ? detail : { mode, ...detail };
}

/** Identity and credential lifecycle events outside a session. */
export async function auditAccess(
  ctx: BrandedContext,
  access: DistributionAccess,
  user: string | null,
  events: readonly AccessEvent[],
): Promise<void> {
  await recordAudit(
    ctx,
    access.network,
    events.map((event) => ({
      event: event.event,
      user,
      session: null,
      detail: eventDetail(access.credentialMode, event.detail),
    })),
  );
}
