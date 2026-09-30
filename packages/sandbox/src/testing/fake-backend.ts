// Fake sandbox backends shared by the sandbox test suites. Test-only: this
// directory is excluded from the package build and never reaches `dist`.
import { SANDBOX_READY_MARKER } from "../activate.js";
import type {
  SandboxAdapter,
  SandboxCommand,
  WrappedCommand,
} from "../adapter.js";
import type {
  SandboxBackend,
  SandboxCapabilities,
  SandboxExecIO,
  SandboxExecRequest,
  SandboxExecResult,
  SandboxInstance,
} from "../backend.js";
import { customBackend } from "../custom.js";
import type { SandboxProfile } from "../profile.js";

/** What a remote backend that only cannot see the host declares. */
export const REMOTE_CAPABILITIES: SandboxCapabilities = {
  isolation: "remote",
  planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
  network: ["deny", "allow"],
  localProcesses: false,
};

/** PiShip's two filesystem path planes, spelled out independently of the source. */
export const PATH_PLANES = [
  "filesystem-read-deny",
  "filesystem-write-allowlist",
] as const;

const LOCAL_CAPABILITIES: SandboxCapabilities = {
  isolation: "local",
  planes: [...PATH_PLANES, "network-deny", "environment-filter"],
  network: ["deny", "allow"],
  localProcesses: true,
};

/**
 * A network probe the fakes' allow-mode sandboxes reach. `.test` is
 * reserved, so it names nothing real.
 */
export const TEST_PROBE = { host: "probe.sandbox.test", port: 8443 } as const;

/** REMOTE_CAPABILITIES with TEST_PROBE declared as the network probe. */
export const PROBED_CAPABILITIES: SandboxCapabilities = {
  ...REMOTE_CAPABILITIES,
  networkProbe: TEST_PROBE,
};

/**
 * How the fakes' network behaves: with the network allowed, a connection
 * reaches exactly the `reachable` targets (`host:port`); with it denied,
 * none. A check that asks about another target, or answers regardless of
 * the mode, cannot come out verified.
 */
export interface FakeNetwork {
  readonly reachable: readonly string[];
}

const DEFAULT_NETWORK: FakeNetwork = {
  reachable: [`${TEST_PROBE.host}:${TEST_PROBE.port}`],
};

/** The line a contained shell prints for PiShip's connection check, if any. */
export function connectionAnswer(
  command: string,
  mode: "deny" | "allow",
  network: FakeNetwork = DEFAULT_NETWORK,
): string {
  const target = /\/dev\/tcp\/([^/']+)\/(\d+)'/.exec(command);
  if (!target) return "";
  const reached =
    mode === "allow" && network.reachable.includes(`${target[1]}:${target[2]}`);
  return `piship-network-${reached ? "reachable" : "blocked"}\n`;
}

/** Answer PiShip's check command the way a contained shell would. */
export function answerCheck(
  request: SandboxExecRequest,
  io: SandboxExecIO,
  mode: "deny" | "allow",
  network?: FakeNetwork,
): void {
  io.onStdout(
    Buffer.from(
      `${SANDBOX_READY_MARKER} ${request.env.PISHIP_PROBE_UNLISTED ?? "unset"}\n${connectionAnswer(request.command, mode, network)}`,
    ),
  );
}

export interface FakeBackendOptions {
  capabilities?: SandboxCapabilities;
  available?: () => Promise<
    { available: true } | { available: false; reason: string }
  >;
  prepare?: () => Promise<void>;
  exec?: (
    request: SandboxExecRequest,
    io: SandboxExecIO,
  ) => Promise<SandboxExecResult>;
  /** Answers the check command; default `answerCheck` with `network`. */
  check?: (
    request: SandboxExecRequest,
    io: SandboxExecIO,
    mode: "deny" | "allow",
  ) => void;
  network?: FakeNetwork;
  /** Called with the profile of each `prepare`. */
  onPrepare?: (profile: SandboxProfile) => void;
}

export interface FakeBackend {
  readonly backend: SandboxBackend;
  /** Lifecycle calls in order: available, capabilities, prepare, check, exec, dispose. */
  readonly events: string[];
  /** Every command the backend received, including PiShip's check commands. */
  readonly requests: SandboxExecRequest[];
}

/** A company backend as a custom adapter module would return it. */
export function fakeBackend(options: FakeBackendOptions = {}): FakeBackend {
  const events: string[] = [];
  const requests: SandboxExecRequest[] = [];
  const raw = {
    id: "acme-sandbox",
    available: async () => {
      events.push("available");
      return options.available
        ? options.available()
        : { available: true as const };
    },
    capabilities: () => {
      events.push("capabilities");
      return options.capabilities ?? REMOTE_CAPABILITIES;
    },
    prepare: async ({
      profile,
    }: {
      profile: SandboxProfile;
    }): Promise<SandboxInstance> => {
      events.push("prepare");
      options.onPrepare?.(profile);
      await options.prepare?.();
      return {
        exec: async (request, io) => {
          requests.push(request);
          if (request.command.includes(SANDBOX_READY_MARKER)) {
            events.push("check");
            if (options.check) options.check(request, io, profile.network);
            else answerCheck(request, io, profile.network, options.network);
            return { exitCode: 0 };
          }
          events.push("exec");
          if (options.exec) return options.exec(request, io);
          io.onStdout(Buffer.from(`ran ${request.command}\n`));
          return { exitCode: 0 };
        },
        dispose: async () => {
          events.push("dispose");
        },
      };
    },
  };
  return { backend: customBackend(raw), events, requests };
}

/**
 * A company wrapper around a local mechanism. With `contain` the command runs
 * through `native`; without it the command is wrapped as itself, contained by
 * nothing. With `ignoreWriteProtect` it contains everything except the
 * profile's protected paths, as an adapter that never reads `writeProtect`.
 * `guardsMissingFiles` is what the wrapper declares about a protected file
 * that does not exist yet; omitted, it declares nothing.
 */
export function fakeWrappingBackend(
  native: Pick<SandboxAdapter, "wrap">,
  contain: boolean,
  options: { ignoreWriteProtect?: boolean; guardsMissingFiles?: boolean } = {},
): SandboxBackend {
  return customBackend({
    id: "acme-local",
    available: async () => ({ available: true }),
    capabilities: () => ({
      ...LOCAL_CAPABILITIES,
      ...(options.guardsMissingFiles === undefined
        ? {}
        : { guardsMissingFiles: options.guardsMissingFiles }),
    }),
    prepare: async ({ profile }: { profile: SandboxProfile }) => ({
      wrap: (command: SandboxCommand): WrappedCommand =>
        contain
          ? native.wrap(
              options.ignoreWriteProtect
                ? { ...profile, writeProtect: { files: [], directories: [] } }
                : profile,
              command,
            )
          : { ...command, args: [...command.args] },
      exec: async () => ({ exitCode: 0 }),
      dispose: async () => {},
    }),
  });
}
