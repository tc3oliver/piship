// Everything doctor reports, gathered once. Collection does the I/O (access
// status, activation, the gateway probe, the governance inspection, and one
// governed session); the group files only format it. The data holds no
// credential value or identity claim, and audit sinks only by host.
import { VERSION } from "@earendil-works/pi-coding-agent";
import {
  type AuditStatus,
  LocalMetrics,
  type MetricsSnapshot,
} from "@piship/audit";
import {
  type ApprovedNetworkEnvironment,
  applyProcessNetworkPolicy,
  approvedNetworkEnvironment,
  assertTlsVerificationEnabled,
  formatError,
  isNetworkEnvironmentName,
  PiShipError,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import {
  type ActivatedAccess,
  type DistributionAccess,
  effectivePrivateOnly,
  governedLock,
  openAccess,
  undeclaredGovernanceHosts,
} from "@piship/core";
import type { GovernanceManifest } from "@piship/schema";
import {
  type GovernanceInspection,
  type GovernanceSession,
  inspectGovernance,
} from "../governance-session.js";
import { AccessEvents, type LaunchContext } from "../launch/context.js";
import { governanceOptions, openGovernance } from "../launch/governance.js";
import { saveMetrics } from "../launch-metrics.js";
import { type AuditSinkTarget, auditSinkTargets } from "./audit.js";
import { type WorkspaceData, workspaceData } from "./workspace.js";

type AccessStatus = Awaited<ReturnType<DistributionAccess["status"]>>;

/** How commands of an enforced sandbox are isolated from this host. */
export type SandboxIsolation = "local" | "remote" | "none";

export interface AccessData {
  readonly manifest: NonNullable<LaunchContext["metadata"]["access"]>;
  /** The access configuration could not be opened. */
  readonly configError?: string;
  /** TLS verification is disabled in the launch environment. */
  readonly tlsError?: string;
  /** Whether an identity session is stored; never its claims. */
  readonly signedIn: boolean;
  /**
   * The identity is a workload identity, obtained per run and never stored:
   * a stored session says nothing about it.
   */
  readonly workload?: boolean;
  /** Why the activation could not obtain the identity, when it could not. */
  readonly identityError?: string;
  /**
   * Remote revocations that failed at a sign-in or user switch: counts and
   * ages only, never a credential identifier or secret.
   */
  readonly pendingRevocations?: {
    readonly readable: boolean;
    readonly count: number;
    readonly dropped: number;
    readonly oldestAgeSeconds: number | null;
  };
  /** The configured issuer, from the manifest (not from a token). */
  readonly issuer?: string;
  readonly store?: { readonly kind: string; readonly description: string };
  readonly credential?: Pick<
    AccessStatus["credential"],
    "state" | "remainingSeconds"
  >;
  readonly activation?: {
    readonly runtime: ActivatedAccess["runtime"]["kind"];
    /** Origin of the managed endpoint, when there is one. */
    readonly gatewayOrigin?: string;
    readonly allowedModels: number;
    readonly selectedModel?: string;
  };
  readonly activationError?: string;
  readonly gateway?: { readonly listed?: number; readonly error?: string };
  readonly network: NetworkData;
  /** Ambient variables removed from the managed environment, by name. */
  readonly removedEnvironment: readonly string[];
}

export interface NetworkData {
  /** Private-only as the managed fetch enforces it. */
  readonly privateOnly: boolean;
  readonly allowHosts: readonly string[];
  /** Governance endpoints a private-only policy would refuse. */
  readonly undeclared: readonly { label: string; host: string }[];
  readonly inheritProxy: boolean;
  readonly caBundles: number;
  /**
   * The approved network environment derived from the policy: the proxy
   * PiShip's own clients use and what the agent's commands may receive
   * (MCP stdio servers get only their own `env.allow`). Absent
   * when the access configuration could not be opened.
   */
  readonly approved?: ApprovedNetworkEnvironment;
  /**
   * Whether the agent's commands receive only `approved` (managed mode). In
   * personal mode they keep the environment of the user's shell.
   */
  readonly childrenRestricted: boolean;
  /**
   * Proxy, CA, and TLS variables in the launch environment that restricted
   * children do not receive and that `approved.withheld` does not name.
   */
  readonly notApproved: readonly string[];
}

export interface GovernanceData {
  readonly manifest: GovernanceManifest;
  readonly inspection?: GovernanceInspection;
  readonly inspectionError?: string;
  /** The containment report's isolation kind; `none` when nothing is enforced. */
  readonly isolation?: SandboxIsolation;
  readonly workspace: WorkspaceData;
  /** Undefined when the governed session did not open. */
  readonly mcp?: GovernanceSession["mcpReports"];
  /** Why the governed session did not open, when it is not an audit failure. */
  readonly sessionError?: string;
  /** Stopping MCP servers or disposing the sandbox failed at session end. */
  readonly shutdownError?: string;
  readonly audit: AuditData;
}

export interface AuditData {
  /** The final status, after the session closed; absent if it never opened. */
  readonly status?: AuditStatus;
  /** A required sink could not be opened: the session did not start. */
  readonly openError?: string;
  /** Closing the session found events a required sink did not take. */
  readonly closeError?: string;
  readonly targets: readonly AuditSinkTarget[];
}

export interface DoctorData {
  readonly ctx: LaunchContext;
  readonly piVersion: string;
  /** Undefined for a Pi-native distribution without an access manifest. */
  readonly access?: AccessData;
  /** Undefined for a distribution that declares no governance. */
  readonly governance?: GovernanceData;
  /** Local metrics after every check ran. */
  readonly metrics: MetricsSnapshot;
}

/**
 * How commands of the sandbox are isolated: the isolation kind an enforced
 * containment report names, or `none`. A remote backend with a shared
 * workspace claims no `host-filesystem-isolation`, so the planes cannot tell.
 */
export function sandboxIsolation(
  report: GovernanceInspection["sandbox"],
): SandboxIsolation {
  if (report.level !== "enforced" || !report.isolation) return "none";
  return report.isolation;
}

function origin(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

function networkData(
  ctx: LaunchContext,
  access: AccessData["manifest"],
  opened: DistributionAccess | undefined,
): NetworkData {
  const privateOnly = opened
    ? opened.network.privateOnly
    : effectivePrivateOnly(access, ctx.mode);
  const allowHosts = opened?.network.allowHosts ?? [];
  // The environment has already been sanitized, as at launch. Only a managed
  // distribution narrows what child processes receive.
  const approved = opened
    ? approvedNetworkEnvironment(opened.network)
    : undefined;
  const childrenRestricted = ctx.mode === "managed";
  const named = new Set(
    [
      ...Object.keys(approved?.variables ?? {}),
      ...(approved?.withheld ?? []).map((item) => item.name),
    ].map((name) => name.toUpperCase()),
  );
  const notApproved =
    approved && childrenRestricted
      ? [
          ...new Set(
            Object.keys(process.env)
              .filter(
                (name) =>
                  process.env[name] !== undefined &&
                  isNetworkEnvironmentName(name) &&
                  !named.has(name.toUpperCase()),
              )
              .map((name) => name.toUpperCase()),
          ),
        ].sort()
      : [];
  return {
    privateOnly,
    allowHosts,
    undeclared:
      privateOnly && opened ? undeclaredGovernanceHosts(ctx, allowHosts) : [],
    inheritProxy: access.network.proxy.inheritEnvironment,
    caBundles: access.network.tls.additionalCA.length,
    ...(approved ? { approved } : {}),
    childrenRestricted,
    notApproved,
  };
}

async function collectAccess(
  ctx: LaunchContext,
  manifest: AccessData["manifest"],
  metrics: LocalMetrics,
  events: AccessEvents,
): Promise<{
  data: AccessData;
  opened?: DistributionAccess;
  activated?: ActivatedAccess;
}> {
  // Checked before the managed environment is sanitized, which removes the
  // variable; a real launch refuses in this state, so doctor must too.
  let tlsError: string | undefined;
  try {
    assertTlsVerificationEnabled();
  } catch (error) {
    tlsError = formatError(error);
  }
  let opened: DistributionAccess | undefined;
  let configError: string | undefined;
  let removedEnvironment: string[] = [];
  try {
    opened = openAccess(ctx, events.listener, metrics);
    if (ctx.mode === "managed")
      removedEnvironment = sanitizeManagedEnvironment(
        process.env,
        opened.network,
        manifest.variables,
      );
  } catch (error) {
    configError = formatError(error);
  }
  const workload = opened
    ? await opened.usesWorkloadIdentity().catch(() => false)
    : false;
  const status = opened
    ? await opened.status().catch(() => undefined)
    : undefined;
  let pendingRevocations: AccessData["pendingRevocations"];
  if (opened?.store)
    try {
      const { readable, count, dropped, oldestAgeSeconds } =
        opened.pendingRevocations();
      pendingRevocations = { readable, count, dropped, oldestAgeSeconds };
    } catch {
      pendingRevocations = {
        readable: false,
        count: 0,
        dropped: 0,
        oldestAgeSeconds: null,
      };
    }
  let activated: ActivatedAccess | undefined;
  let activationError: string | undefined;
  let identityError: string | undefined;
  let gateway: AccessData["gateway"];
  if (opened && !tlsError)
    try {
      // As at launch: a managed distribution's children receive only the
      // approved network environment, including the MCP stdio servers the
      // governed session below starts.
      applyProcessNetworkPolicy(opened.network, {
        restrictChildren: ctx.mode === "managed",
      });
      activated = await opened.activate();
      if (activated.runtime.kind === "managed-endpoint")
        try {
          const listed = await opened.probeGateway();
          if (listed) gateway = { listed: listed.length };
        } catch (error) {
          gateway = { error: formatError(error) };
        }
    } catch (error) {
      activationError = formatError(error);
      if (error instanceof PiShipError && error.component === "identity")
        identityError = activationError;
    }
  if (opened) saveMetrics(metrics);
  const gatewayOrigin = origin(activated?.runtime.baseUrl);
  const data: AccessData = {
    manifest,
    ...(configError ? { configError } : {}),
    ...(tlsError ? { tlsError } : {}),
    signedIn: !!status?.identity,
    ...(workload ? { workload } : {}),
    ...(identityError ? { identityError } : {}),
    ...(pendingRevocations ? { pendingRevocations } : {}),
    ...(opened?.endpoints.issuer ? { issuer: opened.endpoints.issuer } : {}),
    ...(opened?.store
      ? {
          store: {
            kind: opened.store.kind,
            description: opened.store.description,
          },
        }
      : {}),
    ...(status
      ? {
          credential: {
            state: status.credential.state,
            ...(status.credential.remainingSeconds !== undefined
              ? { remainingSeconds: status.credential.remainingSeconds }
              : {}),
          },
        }
      : {}),
    ...(activated
      ? {
          activation: {
            runtime: activated.runtime.kind,
            ...(gatewayOrigin ? { gatewayOrigin } : {}),
            allowedModels: activated.config.allowedModels.length,
            ...(activated.selectedModel
              ? { selectedModel: activated.selectedModel }
              : {}),
          },
        }
      : {}),
    ...(activationError ? { activationError } : {}),
    ...(gateway ? { gateway } : {}),
    network: networkData(ctx, manifest, opened),
    removedEnvironment,
  };
  return {
    data,
    ...(opened ? { opened } : {}),
    ...(activated ? { activated } : {}),
  };
}

/**
 * Open one governed session as a launch would, to start MCP servers and
 * deliver its startup events to the audit sinks, then close it. The session
 * is recorded in audit (`session.start`, `policy.loaded`, the resource,
 * provider, and MCP decisions, `session.end`) under the signed-in principal:
 * doctor starts the same processes a launch does, and delivering real events
 * is what shows that the sinks work. Closing can report AUDIT_UNAVAILABLE;
 * that becomes a line of the Audit group, never a lost report.
 */
async function collectSession(
  ctx: LaunchContext,
  prepared: Parameters<typeof openGovernance>[1],
): Promise<
  Pick<GovernanceData, "mcp" | "sessionError" | "shutdownError"> & {
    audit: Omit<AuditData, "targets">;
  }
> {
  let session: GovernanceSession | null = null;
  let mcp: GovernanceData["mcp"];
  let sessionError: string | undefined;
  let openError: string | undefined;
  let closeError: string | undefined;
  let status: AuditStatus | undefined;
  try {
    session = await openGovernance(ctx, prepared, false);
    if (session) {
      mcp = session.mcpReports;
      await session.audit.flush();
    }
  } catch (error) {
    if (error instanceof PiShipError && error.code === "AUDIT_UNAVAILABLE")
      openError = formatError(error);
    else sessionError = formatError(error);
  }
  let shutdownError: string | undefined;
  if (session)
    try {
      status = await session.close();
    } catch (error) {
      // close() has finished every cleanup step and closed the audit log
      // before it throws; the audit error outranks a cleanup error.
      if (error instanceof PiShipError && error.code === "AUDIT_UNAVAILABLE")
        closeError = formatError(error);
      else shutdownError = formatError(error);
      status = session.audit.status();
    }
  return {
    ...(mcp ? { mcp } : {}),
    ...(sessionError ? { sessionError } : {}),
    ...(shutdownError ? { shutdownError } : {}),
    audit: {
      ...(status ? { status } : {}),
      ...(openError ? { openError } : {}),
      ...(closeError ? { closeError } : {}),
    },
  };
}

export async function collectDoctorData(
  ctx: LaunchContext,
): Promise<DoctorData> {
  const metrics = LocalMetrics.load(ctx.stateDir);
  const events = new AccessEvents();
  let access: AccessData | undefined;
  let opened: DistributionAccess | undefined;
  let activated: ActivatedAccess | undefined;
  if (ctx.metadata.access) {
    const collected = await collectAccess(
      ctx,
      ctx.metadata.access,
      metrics,
      events,
    );
    access = collected.data;
    opened = collected.opened;
    activated = collected.activated;
  }
  const lock = governedLock(ctx);
  let governance: GovernanceData | undefined;
  if (lock) {
    const prepared = {
      metrics,
      access: opened ?? null,
      activated: activated ?? null,
      removedEnvironment: access?.removedEnvironment ?? [],
      events,
    };
    const manifest = lock.governance.manifest;
    let inspection: GovernanceInspection | undefined;
    let inspectionError: string | undefined;
    try {
      inspection = await inspectGovernance(
        governanceOptions(ctx, lock, prepared, false),
      );
    } catch (error) {
      inspectionError = formatError(error);
    }
    // Without a policy there is nothing a session could enforce.
    const session = inspection
      ? await collectSession(ctx, prepared)
      : { audit: {} };
    governance = {
      manifest,
      ...(inspection ? { inspection } : {}),
      ...(inspectionError ? { inspectionError } : {}),
      ...(inspection
        ? { isolation: sandboxIsolation(inspection.sandbox) }
        : {}),
      workspace: workspaceData(inspection),
      ...session,
      audit: { ...session.audit, targets: auditSinkTargets(ctx, manifest) },
    };
  }
  return {
    ctx,
    piVersion: VERSION,
    ...(access ? { access } : {}),
    ...(governance ? { governance } : {}),
    metrics: LocalMetrics.load(ctx.stateDir).snapshot(),
  };
}
