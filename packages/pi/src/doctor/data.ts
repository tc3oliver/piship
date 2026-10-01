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
  checkProxyConnection,
  countCertificates,
  createManagedFetch,
  formatError,
  isNetworkEnvironmentName,
  type ManagedFetch,
  type NetworkPolicy,
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
import {
  type SandboxCredentialData,
  sandboxCredentialData,
} from "./sandbox.js";
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
  /**
   * The runtime credential's unresolved acquire or renewal, when one is
   * recorded; `stale` once it is past the broker's idempotency retention.
   */
  readonly pendingIssuance?: {
    readonly idempotencyKey: string;
    readonly stale: boolean;
  };
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
  /**
   * Each proxy PiShip's clients use, as `scheme://host:port`, and the code
   * when a connection to it did not open. Absent when not checked.
   */
  readonly proxyChecks?: readonly NetworkProxyCheck[];
  /** Certificates loaded from the declared CA bundles. */
  readonly caCertificates?: number;
  /** Why the declared CA bundles could not be loaded. */
  readonly caError?: string;
  /**
   * Each managed endpoint requested through the network policy (proxy, CA,
   * private-only): the HTTP status it answered with, or the failure, which
   * names the hop (proxy, TLS chain, or endpoint). By host only.
   */
  readonly paths?: readonly NetworkPathCheck[];
}

export interface NetworkProxyCheck {
  readonly proxy: string;
  readonly error?: string;
}

export interface NetworkPathCheck {
  readonly label: string;
  readonly host: string;
  readonly status?: number;
  /** The PiShip error code of the failure, when there is one. */
  readonly code?: string;
  readonly error?: string;
}

const PATH_TIMEOUT_MS = 5_000;

/**
 * Check the network path doctor reports: whether each proxy accepts a
 * connection, whether the declared CA bundles load, and whether each managed
 * endpoint answers through the same managed fetch PiShip's clients use. Any
 * HTTP answer proves the proxy, the TLS chain, and the route; nothing is sent
 * but an unauthenticated GET.
 */
export async function networkChecks(
  policy: NetworkPolicy,
  endpoints: readonly { label: string; url: string | undefined }[],
): Promise<
  Pick<NetworkData, "proxyChecks" | "caCertificates" | "caError" | "paths">
> {
  const { http, https } = approvedNetworkEnvironment(policy).proxy;
  const proxies = [
    ...new Set([http, https].filter((proxy): proxy is string => !!proxy)),
  ];
  const proxyChecks = await Promise.all(
    proxies.map(async (proxy) => {
      const error = await checkProxyConnection(proxy);
      return error ? { proxy, error } : { proxy };
    }),
  );
  let caCertificates: number | undefined;
  try {
    if (policy.additionalCA.length)
      caCertificates = countCertificates(policy.additionalCA);
  } catch (error) {
    return { proxyChecks, caError: formatError(error) };
  }
  const fetch = createManagedFetch(policy, "doctor");
  const paths = await Promise.all(
    endpoints.flatMap(({ label, url }) =>
      url ? [checkPath(fetch, label, url)] : [],
    ),
  );
  return {
    proxyChecks,
    ...(caCertificates === undefined ? {} : { caCertificates }),
    paths,
  };
}

async function checkPath(
  fetch: ManagedFetch,
  label: string,
  url: string,
): Promise<NetworkPathCheck> {
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    return { label, host: "(invalid URL)", error: "not a valid URL" };
  }
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(PATH_TIMEOUT_MS),
    });
    await response.body?.cancel().catch(() => {});
    return { label, host, status: response.status };
  } catch (error) {
    if ((error as Error)?.name === "TimeoutError")
      return {
        label,
        host,
        error: `no answer within ${PATH_TIMEOUT_MS / 1000} s`,
      };
    return {
      label,
      host,
      ...(error instanceof PiShipError ? { code: error.code } : {}),
      error: formatError(error),
    };
  }
}

export interface GovernanceData {
  readonly manifest: GovernanceManifest;
  readonly inspection?: GovernanceInspection;
  readonly inspectionError?: string;
  /** The containment report's isolation kind; `none` when nothing is enforced. */
  readonly isolation?: SandboxIsolation;
  readonly workspace: WorkspaceData;
  /** The stored sandbox credential, when the manifest declares one. */
  readonly sandboxCredential?: SandboxCredentialData;
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
  const pending = opened
    ? await opened
        .credentialManager()
        .then((manager) => manager.pendingIssuance())
        .catch(() => null)
    : null;
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
  // Checked whether or not activation succeeded: when it failed, these say
  // which hop (the proxy, a TLS chain, an endpoint) is at fault.
  const checks =
    opened && !tlsError
      ? await networkChecks(opened.network, [
          { label: "identity", url: opened.endpoints.issuer },
          { label: "broker", url: opened.endpoints.brokerEndpoint },
          {
            label: "broker revoke",
            url: opened.endpoints.brokerRevokeEndpoint,
          },
          { label: "gateway", url: opened.endpoints.baseUrl },
        ])
      : {};
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
    ...(pending
      ? {
          pendingIssuance: {
            idempotencyKey: pending.idempotencyKey,
            stale: pending.stale,
          },
        }
      : {}),
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
    network: { ...networkData(ctx, manifest, opened), ...checks },
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
    // After the session, so a rejection it met is shown.
    const sandboxCredential = sandboxCredentialData({
      ctx,
      sandbox: manifest.sandbox,
      ...(opened ? { access: opened } : {}),
      ...(activated ? { activated } : {}),
      ...(access?.workload ? { workload: true } : {}),
    });
    governance = {
      manifest,
      ...(inspection ? { inspection } : {}),
      ...(inspectionError ? { inspectionError } : {}),
      ...(inspection
        ? { isolation: sandboxIsolation(inspection.sandbox) }
        : {}),
      workspace: workspaceData(inspection),
      ...(sandboxCredential ? { sandboxCredential } : {}),
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
