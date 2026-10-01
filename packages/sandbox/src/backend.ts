// The sandbox backend contract. PiShip owns policy, governance, audit,
// credentials, and the timeout and cancellation of every command; a backend
// owns execution isolation. A backend never decides policy and never sees
// more than the one command, working directory, and approved environment
// PiShip hands it.
import type {
  AdapterAvailability,
  SandboxCommand,
  WrappedCommand,
} from "./adapter.js";
import { CONTAINMENT_PLANES } from "./probe.js";
import type { SandboxProfile } from "./profile.js";

export const SANDBOX_PROVIDERS = [
  "native",
  "custom",
  "e2b-compatible",
  "kubernetes-agent-sandbox",
] as const;
export type SandboxProvider = (typeof SANDBOX_PROVIDERS)[number];

/**
 * A remote-only guarantee: commands run on another machine or VM, so the
 * host's files are not reachable at all. It says nothing about PiShip's
 * path policy (`filesystem.read.deny`, `filesystem.write.allow`), which only
 * the `filesystem-*` planes claim. A remote backend whose workspace is
 * `shared` or `synchronized` reaches the host's files through that
 * workspace, so it must not claim this guarantee.
 */
export const HOST_FILESYSTEM_ISOLATION = "host-filesystem-isolation";

/**
 * A remote-only guarantee for a `shared` or `synchronized` workspace: this
 * host's files are reachable from the sandbox only through the workspace
 * (the project root mapped at the backend's working directory), by mount or
 * by sync. Attested by the backend; the workspace check proves only that the
 * workspace is reachable, not that nothing else is.
 */
export const WORKSPACE_CONFINEMENT = "workspace-confinement";

/**
 * The paths in `profile.writeProtect` (the project's git control files, the
 * git config the user's machine adds to them, and the `hooks` and `info`
 * trees) cannot be changed from inside the sandbox,
 * also not through a sync engine. Live-probed for local backends; checked
 * from outside for remote ones with a shared or synchronized workspace.
 */
export const GIT_CONTROL_PROTECTION = "git-control-protection";

/** Everything a backend can claim: PiShip's planes plus the remote guarantees. */
export const SANDBOX_GUARANTEES = [
  ...CONTAINMENT_PLANES,
  HOST_FILESYSTEM_ISOLATION,
  WORKSPACE_CONFINEMENT,
] as const;
export type SandboxGuarantee = (typeof SANDBOX_GUARANTEES)[number];

/**
 * How the sandbox sees the workspace. `shared`: the sandbox and PiShip's
 * file tools touch the same files (a mount). `synchronized`: different
 * stores a backend-owned engine keeps in step both ways within
 * `propagationMs`. `snapshot`: anything else (a template, an image, a
 * clone, a one-time upload).
 */
export const WORKSPACE_MODES = ["snapshot", "synchronized", "shared"] as const;
export type WorkspaceMode = (typeof WORKSPACE_MODES)[number];

/** The default and the bounds of `SandboxWorkspaceDeclaration.propagationMs`. */
export const DEFAULT_PROPAGATION_MS = 10_000;
const MAX_PROPAGATION_MS = 60_000;

/** How the sandbox sees the workspace. Omitted in `capabilities()` means snapshot. */
export interface SandboxWorkspaceDeclaration {
  readonly mode: WorkspaceMode;
  /**
   * `synchronized` only: the longest propagation delay the backend
   * promises, in milliseconds (1 to 60000, default 10000).
   */
  readonly propagationMs?: number;
  /**
   * `shared` or `synchronized` only: a workspace-relative POSIX directory
   * the backend guarantees is visible and writable from both sides; PiShip
   * uses `<sentinelDir>/piship-workspace` for its workspace check. Default:
   * `.git/piship-workspace` when `.git` is a real directory. A directory in
   * the working tree (not under `.git`) is used only in company-origin
   * projects.
   */
  readonly sentinelDir?: string;
}

/**
 * A TCP endpoint for PiShip's network denial check. The backend or its
 * operator controls it (the operator's own endpoint on the execution
 * network, for example) and guarantees that a sandbox of this backend with
 * the network allowed can connect to it; with the network denied it must
 * not. Never a public address the operator does not control, and never a
 * secret: it is sent to the sandbox inside the check command.
 */
export interface SandboxNetworkProbe {
  /** A hostname, IPv4, or IPv6 address, without brackets or a port. */
  readonly host: string;
  /** 1 to 65535. */
  readonly port: number;
}

/** What a backend declares it can enforce. PiShip checks it before use. */
export interface SandboxCapabilities {
  /**
   * `local`: commands run as processes on this host inside the mechanism.
   * `remote`: commands run in another machine or VM; host files, host
   * loopback services, and the host environment are not reachable.
   */
  readonly isolation: "local" | "remote";
  /**
   * Guarantees the backend enforces. Claim `filesystem-read-deny` and
   * `filesystem-write-allowlist` only when the backend applies the profile's
   * `readDeny` and `writeAllow` paths itself; a remote backend that merely
   * cannot see the host claims `host-filesystem-isolation` instead.
   */
  readonly planes: readonly SandboxGuarantee[];
  /** Network modes the backend can enforce. */
  readonly network: readonly ("deny" | "allow")[];
  /**
   * Whether `wrap` can contain long-lived local processes with stdio pipes,
   * such as MCP stdio servers. Requires `isolation: "local"`.
   */
  readonly localProcesses: boolean;
  /**
   * Local backends only: whether the isolator keeps a protected file that
   * does not exist yet (`.git/commondir`, `.git/config.worktree`) from being
   * created or renamed into place. Omitted or false means it cannot, which is
   * true of bubblewrap (a mount needs a path that exists): git control is
   * then reported not verified while such a file lies where the sandbox may
   * write, because a command could create one and redirect the next git
   * command. True (Seatbelt) still leaves a file whose directory can be
   * swapped (neither a writable root nor holding an existing protected path)
   * not verified, since the rule covers the path and not the directory. PiShip
   * does not create placeholder files in the project instead.
   */
  readonly guardsMissingFiles?: boolean;
  /**
   * Remote backends only: how the sandbox sees the workspace. Omitted means
   * `snapshot`. A local backend runs commands against this host's files, so
   * its workspace is `shared` by construction and this field is ignored.
   */
  readonly workspace?: SandboxWorkspaceDeclaration;
  /**
   * Remote backends only, optional: the target of the network denial check.
   * With the network denied, PiShip connects to it from the session's
   * sandbox (it must fail; a connection fails the activation closed) and,
   * when `network` also lists `allow`, from a temporary allow-mode sandbox
   * of this backend (it must succeed). Only when the same target is
   * reachable with the network allowed and blocked with it denied is
   * network denial reported `verified`; otherwise, and without a probe, it
   * is attested by the backend. A local backend is live-probed and this
   * field is ignored.
   */
  readonly networkProbe?: SandboxNetworkProbe;
}

export interface SandboxPrepareRequest {
  /** The resolved policy: paths, network mode, and environment allowlist. */
  readonly profile: SandboxProfile;
  /**
   * Aborts when PiShip stops waiting for the sandbox. A custom backend's
   * `prepare()` always gets one, which also aborts at PiShip's deadline.
   */
  readonly signal?: AbortSignal;
}

/** What PiShip passes to a backend's `available()` and an instance's `dispose()`. */
export interface SandboxCallOptions {
  /**
   * Aborts when PiShip stops waiting for the call: at its deadline for a
   * custom backend. Optional to honor; PiShip stops waiting either way.
   */
  readonly signal?: AbortSignal;
}

export interface SandboxExecRequest {
  /** A shell command line; the backend chooses the shell. */
  readonly command: string;
  /** The working directory on this host (absolute). */
  readonly cwd: string;
  /**
   * The working directory relative to the workspace, with `/` separators
   * (`.` for the root), or undefined when it is outside the workspace.
   * Remote backends map it onto their own workspace directory.
   */
  readonly workspacePath: string | undefined;
  /** The approved environment, already filtered by PiShip. Pass it as is. */
  readonly env: Readonly<Record<string, string>>;
}

export interface SandboxExecIO {
  /**
   * Aborted when PiShip times out or cancels the command. The backend must
   * stop the command and settle promptly; PiShip reports the outcome.
   */
  readonly signal: AbortSignal;
  readonly onStdout: (chunk: Buffer) => void;
  readonly onStderr: (chunk: Buffer) => void;
}

export interface SandboxExecResult {
  readonly exitCode: number | null;
  readonly signal?: NodeJS.Signals | null;
}

/** One prepared sandbox for one session (created by `prepare`). */
export interface SandboxInstance {
  exec(
    request: SandboxExecRequest,
    io: SandboxExecIO,
  ): Promise<SandboxExecResult>;
  /**
   * Local backends only: wrap a command so that spawning the result on this
   * host runs it contained. Required for `localProcesses` and for PiShip's
   * live probe.
   */
  wrap?(command: SandboxCommand): WrappedCommand;
  /** Release everything the instance holds. Called once; must not throw. */
  dispose(options?: SandboxCallOptions): Promise<void>;
  /**
   * Optional: an opaque id of the environment the last command ran in, such
   * as a Kubernetes claim name. A change makes PiShip check a shared or
   * synchronized workspace again before the next command. Never a secret.
   */
  epoch?(): string | undefined;
}

export interface SandboxBackend {
  /** A short identifier such as `linux-bubblewrap` or `acme-sandbox`. */
  readonly id: string;
  readonly provider: SandboxProvider;
  /** Whether the mechanism or service can be used now. */
  available(options?: SandboxCallOptions): Promise<AdapterAvailability>;
  capabilities(): SandboxCapabilities;
  /** Create or prepare an isolated environment for a session. */
  prepare(request: SandboxPrepareRequest): Promise<SandboxInstance>;
}

const IDENTIFIER = /^[a-z][a-z0-9-]{0,62}$/;

/** A backend id is safe to show in reports, metrics, and audit. */
export function isBackendId(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function sentinelDirProblem(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > 256)
    return "sentinelDir must be a non-empty string";
  if (value.startsWith("/")) return "sentinelDir must be workspace-relative";
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what this rejects
  if (/[\\\u0000-\u001f]/.test(value))
    return "sentinelDir must use / separators and no control characters";
  if (value.split("/").includes("..")) return "sentinelDir must not contain ..";
  return undefined;
}

/**
 * The workspace declaration after validation. A local backend is `shared`
 * by construction whatever it declares; an omitted declaration is
 * `snapshot`. A malformed declaration yields the reason instead.
 */
export function workspaceDeclaration(
  capabilities: SandboxCapabilities,
):
  | { readonly declaration: SandboxWorkspaceDeclaration }
  | { readonly invalid: string } {
  if (capabilities?.isolation === "local")
    return { declaration: { mode: "shared" } };
  const raw: unknown = capabilities?.workspace;
  if (raw === undefined) return { declaration: { mode: "snapshot" } };
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    return { invalid: "the workspace declaration is not an object" };
  const { mode, propagationMs, sentinelDir } =
    raw as Partial<SandboxWorkspaceDeclaration>;
  if (!WORKSPACE_MODES.includes(mode as WorkspaceMode))
    return {
      invalid: "the workspace mode is not snapshot, synchronized, or shared",
    };
  if (propagationMs !== undefined) {
    if (mode !== "synchronized")
      return {
        invalid: "propagationMs applies only to a synchronized workspace",
      };
    if (
      !Number.isInteger(propagationMs) ||
      propagationMs < 1 ||
      propagationMs > MAX_PROPAGATION_MS
    )
      return {
        invalid: `propagationMs must be an integer from 1 to ${MAX_PROPAGATION_MS}`,
      };
  }
  if (sentinelDir !== undefined) {
    if (mode === "snapshot")
      return { invalid: "sentinelDir does not apply to a snapshot workspace" };
    const problem = sentinelDirProblem(sentinelDir);
    if (problem) return { invalid: problem };
  }
  return {
    declaration: {
      mode: mode as WorkspaceMode,
      ...(propagationMs !== undefined ? { propagationMs } : {}),
      ...(sentinelDir !== undefined ? { sentinelDir } : {}),
    },
  };
}

// Letters, digits, dots, hyphens, and colons only: the host is placed in a
// shell command, so nothing else may reach it.
const PROBE_HOST = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$/;

/**
 * The network probe after validation: undefined when none applies (none
 * declared, or a local backend), or the reason a declared one is malformed.
 */
export function networkProbe(
  capabilities: SandboxCapabilities,
):
  | { readonly probe: SandboxNetworkProbe }
  | { readonly invalid: string }
  | undefined {
  if (capabilities?.isolation !== "remote") return undefined;
  const raw: unknown = capabilities.networkProbe;
  if (raw === undefined) return undefined;
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    return { invalid: "the network probe is not an object" };
  const { host, port } = raw as Partial<SandboxNetworkProbe>;
  if (typeof host !== "string" || !PROBE_HOST.test(host))
    return {
      invalid:
        "the network probe host must be a hostname or an IP address without brackets or a port",
    };
  if (
    !Number.isInteger(port) ||
    (port as number) < 1 ||
    (port as number) > 65535
  )
    return {
      invalid: "the network probe port must be an integer from 1 to 65535",
    };
  return { probe: { host, port: port as number } };
}

/** The declared workspace mode; malformed counts as snapshot here. */
function declaredMode(capabilities: SandboxCapabilities): WorkspaceMode {
  const result = workspaceDeclaration(capabilities);
  return "declaration" in result ? result.declaration.mode : "snapshot";
}

/**
 * Guarantees a required sandbox must enforce. A local backend runs commands
 * against the host's files, so it must apply PiShip's path policy. A remote
 * backend with a snapshot workspace must keep the host's files out of reach;
 * one with a shared or synchronized workspace must confine the sandbox to
 * that workspace and keep the host's git control files read-only. PiShip's
 * path rules still govern the local file tools, not the remote sandbox.
 *
 * `git-control-protection` is live-probed for local backends but not yet
 * required of them: it becomes required once the probe has passed on Linux
 * and macOS CI. Until then a local backend that fails it is reported with a
 * warning.
 */
export function requiredPlanes(
  network: "deny" | "allow",
  isolation: "local" | "remote" = "local",
  workspace: WorkspaceMode = "snapshot",
): readonly SandboxGuarantee[] {
  const filesystem =
    isolation === "local"
      ? (["filesystem-read-deny", "filesystem-write-allowlist"] as const)
      : workspace === "snapshot"
        ? ([HOST_FILESYSTEM_ISOLATION] as const)
        : ([WORKSPACE_CONFINEMENT, GIT_CONTROL_PROTECTION] as const);
  return [
    ...filesystem,
    ...(network === "deny" ? (["network-deny"] as const) : []),
    "environment-filter",
  ];
}

/** The planes that together enforce PiShip's path policy. */
export const PATH_POLICY_PLANES = [
  "filesystem-read-deny",
  "filesystem-write-allowlist",
] as const;

/**
 * Whether `sandbox.filesystem` path rules are enforced by the backend: only
 * with both path planes. One plane alone (possible for a custom remote
 * backend) is a partial guarantee and never counts as the whole policy.
 */
export function enforcesPathPolicy(
  planes: readonly string[] | undefined,
): boolean {
  return PATH_POLICY_PLANES.every((plane) => planes?.includes(plane) ?? false);
}

/**
 * The guarantees a report may show: those declared, known, meaningful for
 * the isolation kind (a local backend cannot isolate the host filesystem or
 * confine a remote workspace; a remote backend with a shared or synchronized
 * workspace does not isolate the host filesystem), and, for `network-deny`,
 * only when the policy denies the network.
 */
export function claimedGuarantees(
  capabilities: SandboxCapabilities,
  network: "deny" | "allow",
): SandboxGuarantee[] {
  const declared = Array.isArray(capabilities?.planes)
    ? capabilities.planes
    : [];
  const remote = capabilities?.isolation === "remote";
  const snapshot = remote && declaredMode(capabilities) === "snapshot";
  return SANDBOX_GUARANTEES.filter(
    (plane) =>
      declared.includes(plane) &&
      (plane !== HOST_FILESYSTEM_ISOLATION || snapshot) &&
      (plane !== WORKSPACE_CONFINEMENT || remote) &&
      (plane !== "network-deny" || network === "deny"),
  );
}

/**
 * Why the declared capabilities cannot enforce a policy, or undefined when
 * they can. Malformed declarations count as missing capabilities.
 */
export function capabilityMismatch(
  capabilities: SandboxCapabilities,
  network: "deny" | "allow",
): string | undefined {
  if (
    capabilities?.isolation !== "local" &&
    capabilities?.isolation !== "remote"
  )
    return "it declares no isolation kind";
  const workspace = workspaceDeclaration(capabilities);
  if ("invalid" in workspace)
    return `it declares a malformed workspace: ${workspace.invalid}`;
  const probe = networkProbe(capabilities);
  if (probe && "invalid" in probe)
    return `it declares a malformed network probe: ${probe.invalid}`;
  const mode = workspace.declaration.mode;
  if (
    capabilities.isolation === "remote" &&
    mode !== "snapshot" &&
    Array.isArray(capabilities.planes) &&
    capabilities.planes.includes(HOST_FILESYSTEM_ISOLATION)
  )
    return `it claims ${HOST_FILESYSTEM_ISOLATION} although its workspace is ${mode}, which reaches this host's files`;
  const planes = claimedGuarantees(capabilities, network);
  const modes = Array.isArray(capabilities?.network)
    ? capabilities.network
    : [];
  const missing: string[] = requiredPlanes(
    network,
    capabilities.isolation,
    mode,
  ).filter((plane) => !planes.includes(plane));
  if (network === "deny" && !modes.includes("deny"))
    if (!missing.includes("network-deny")) missing.push("network-deny");
  if (missing.length) return `it does not provide ${missing.join(", ")}`;
  return undefined;
}
