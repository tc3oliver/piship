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
import type { ContainmentPlane } from "./probe.js";
import type { SandboxProfile } from "./profile.js";

export const SANDBOX_PROVIDERS = [
  "native",
  "custom",
  "e2b-compatible",
  "kubernetes-agent-sandbox",
] as const;
export type SandboxProvider = (typeof SANDBOX_PROVIDERS)[number];

/** What a backend declares it can enforce. PiShip checks it before use. */
export interface SandboxCapabilities {
  /**
   * `local`: commands run as processes on this host inside the mechanism.
   * `remote`: commands run in another machine or VM; host files, host
   * loopback services, and the host environment are not reachable.
   */
  readonly isolation: "local" | "remote";
  /** Containment planes the backend enforces. */
  readonly planes: readonly ContainmentPlane[];
  /** Network modes the backend can enforce. */
  readonly network: readonly ("deny" | "allow")[];
  /**
   * Whether `wrap` can contain long-lived local processes with stdio pipes,
   * such as MCP stdio servers. Requires `isolation: "local"`.
   */
  readonly localProcesses: boolean;
}

export interface SandboxPrepareRequest {
  /** The resolved policy: paths, network mode, and environment allowlist. */
  readonly profile: SandboxProfile;
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
  dispose(): Promise<void>;
}

export interface SandboxBackend {
  /** A short identifier such as `linux-bubblewrap` or `acme-sandbox`. */
  readonly id: string;
  readonly provider: SandboxProvider;
  /** Whether the mechanism or service can be used now. */
  available(): Promise<AdapterAvailability>;
  capabilities(): SandboxCapabilities;
  /** Create or prepare an isolated environment for a session. */
  prepare(request: SandboxPrepareRequest): Promise<SandboxInstance>;
}

const IDENTIFIER = /^[a-z][a-z0-9-]{0,62}$/;

/** A backend id is safe to show in reports, metrics, and audit. */
export function isBackendId(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

/** Planes a required sandbox must enforce for a network mode. */
export function requiredPlanes(
  network: "deny" | "allow",
): readonly ContainmentPlane[] {
  return [
    "filesystem-read-deny",
    "filesystem-write-allowlist",
    ...(network === "deny" ? (["network-deny"] as const) : []),
    "environment-filter",
  ];
}

/**
 * Why the declared capabilities cannot enforce a policy, or undefined when
 * they can. Malformed declarations count as missing capabilities.
 */
export function capabilityMismatch(
  capabilities: SandboxCapabilities,
  network: "deny" | "allow",
): string | undefined {
  const planes = Array.isArray(capabilities?.planes) ? capabilities.planes : [];
  const modes = Array.isArray(capabilities?.network)
    ? capabilities.network
    : [];
  const missing = requiredPlanes(network).filter(
    (plane) => !planes.includes(plane),
  );
  if (network === "deny" && !modes.includes("deny"))
    if (!missing.includes("network-deny")) missing.push("network-deny");
  if (
    capabilities?.isolation !== "local" &&
    capabilities?.isolation !== "remote"
  )
    return "it declares no isolation kind";
  if (missing.length) return `it does not provide ${missing.join(", ")}`;
  return undefined;
}
