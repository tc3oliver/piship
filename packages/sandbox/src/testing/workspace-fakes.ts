// Fake remote backends with a real workspace behind them, for the workspace
// verification tests. Commands run in `/bin/sh` on this host: in the
// workspace itself (shared), in a separate directory a timer-driven copier
// keeps in step (synchronized), or in a copy made once (snapshot). Test-only:
// this directory never reaches `dist`.
import { spawn } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { SANDBOX_READY_MARKER } from "../activate.js";
import type {
  SandboxBackend,
  SandboxCapabilities,
  SandboxExecIO,
  SandboxExecRequest,
  SandboxExecResult,
  SandboxWorkspaceDeclaration,
} from "../backend.js";
import { customBackend } from "../custom.js";
import type { SandboxProfile } from "../profile.js";
import { WORKSPACE_MARKER } from "../workspace.js";
import { answerCheck } from "./fake-backend.js";

/** What a remote backend with a mounted or synced workspace declares. */
export function workspaceCapabilities(
  workspace: SandboxWorkspaceDeclaration,
): SandboxCapabilities {
  return {
    isolation: "remote",
    planes: [
      "workspace-confinement",
      "git-control-protection",
      "network-deny",
      "environment-filter",
    ],
    network: ["deny", "allow"],
    localProcesses: false,
    workspace,
  };
}

/** Run a command with `/bin/sh` in `root` (plus the request's workspace path). */
export function runShell(
  root: string,
  request: SandboxExecRequest,
  io: SandboxExecIO,
): Promise<SandboxExecResult> {
  const cwd =
    request.workspacePath && request.workspacePath !== "."
      ? join(root, ...request.workspacePath.split("/"))
      : root;
  return new Promise((resolvePromise, reject) => {
    const child = spawn("/bin/sh", ["-c", request.command], {
      cwd,
      // The sandbox's own environment: a remote never receives the host PATH.
      env: { ...request.env, PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const onAbort = () => child.kill("SIGKILL");
    io.signal.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", io.onStdout);
    child.stderr.on("data", io.onStderr);
    child.once("error", reject);
    child.once("close", (code, signal) => {
      io.signal.removeEventListener("abort", onAbort);
      resolvePromise({ exitCode: code, signal });
    });
  });
}

export interface WorkspaceFakeOptions {
  /** Default: shared for `sharedBackend`, synchronized for `syncedBackend`. */
  readonly declaration?: SandboxWorkspaceDeclaration;
  /** Replaces the default capabilities (for malformed declarations). */
  readonly capabilities?: SandboxCapabilities;
  /** Handle PiShip's workspace check command instead of running it. */
  readonly check?: (
    request: SandboxExecRequest,
    io: SandboxExecIO,
  ) => Promise<SandboxExecResult>;
  /** The instance's epoch, read on every call. */
  readonly epoch?: () => string | undefined;
}

export interface WorkspaceFake {
  readonly backend: SandboxBackend;
  /** Every command the backend received, including PiShip's own. */
  readonly requests: SandboxExecRequest[];
  /** Commands that were not PiShip's check or workspace check. */
  readonly commands: () => string[];
  /** The sandbox side's directory (synchronized and snapshot fakes). */
  readonly remote: () => string | undefined;
  /** How often `prepare` ran. */
  readonly prepared: () => number;
}

const isWorkspaceCheck = (request: SandboxExecRequest) =>
  request.command.includes(`echo ${WORKSPACE_MARKER} done`);

function fake(
  id: string,
  capabilities: SandboxCapabilities,
  options: WorkspaceFakeOptions,
  start: (profile: SandboxProfile) => {
    root: string;
    stop?: () => void;
  },
): WorkspaceFake {
  const requests: SandboxExecRequest[] = [];
  let remote: string | undefined;
  let prepared = 0;
  const backend = customBackend({
    id,
    available: async () => ({ available: true }),
    capabilities: () => options.capabilities ?? capabilities,
    prepare: async ({ profile }: { profile: SandboxProfile }) => {
      prepared++;
      const side = start(profile);
      remote = side.root === profile.workspace ? undefined : side.root;
      return {
        exec: async (request: SandboxExecRequest, io: SandboxExecIO) => {
          requests.push(request);
          if (request.command.includes(SANDBOX_READY_MARKER)) {
            answerCheck(request, io);
            return { exitCode: 0 };
          }
          if (isWorkspaceCheck(request) && options.check)
            return options.check(request, io);
          return runShell(side.root, request, io);
        },
        ...(options.epoch ? { epoch: options.epoch } : {}),
        dispose: async () => {
          side.stop?.();
          if (remote) rmSync(remote, { recursive: true, force: true });
        },
      };
    },
  });
  return {
    backend,
    requests,
    commands: () =>
      requests
        .filter(
          (request) =>
            !request.command.includes(SANDBOX_READY_MARKER) &&
            !isWorkspaceCheck(request),
        )
        .map((request) => request.command),
    remote: () => remote,
    prepared: () => prepared,
  };
}

/**
 * A shared workspace: commands run in the workspace itself, so both sides
 * are literally the same files. It protects nothing by itself; a test that
 * needs protected git control files makes them read-only on disk.
 */
export function sharedBackend(
  options: WorkspaceFakeOptions = {},
): WorkspaceFake {
  const declaration = options.declaration ?? { mode: "shared" };
  return fake(
    "acme-shared",
    workspaceCapabilities(declaration),
    options,
    (profile) => ({
      root: profile.workspace,
    }),
  );
}

/** Regular files below `root`, as relative paths; links are skipped. */
function files(root: string, prefix = ""): string[] {
  const output: string[] = [];
  let names: string[];
  try {
    names = readdirSync(join(root, prefix));
  } catch {
    return output;
  }
  for (const name of names) {
    const rel = prefix ? join(prefix, name) : name;
    const stat = lstatSync(join(root, rel), { throwIfNoEntry: false });
    if (!stat || stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) output.push(...files(root, rel));
    else if (stat.isFile()) output.push(rel);
  }
  return output;
}

/**
 * Copy files that are new on one side to the other once they have existed
 * for `delayMs`, and remove a file the other side deleted after both had it.
 * Existing files are never overwritten, so the two directions cannot fight
 * over one file.
 */
function copier(from: string, to: string, delayMs: number): () => void {
  const seen = new Map<string, number>();
  const both = new Set<string>();
  return () => {
    const now = Date.now();
    for (const rel of files(from)) {
      const target = join(to, rel);
      if (existsSync(target)) {
        seen.delete(rel);
        both.add(rel);
        continue;
      }
      if (both.has(rel)) {
        // The other side deleted it.
        rmSync(join(from, rel), { force: true });
        both.delete(rel);
        continue;
      }
      const first = seen.get(rel);
      if (first === undefined) {
        seen.set(rel, now);
        continue;
      }
      if (now - first < delayMs) continue;
      try {
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, readFileSync(join(from, rel)));
        both.add(rel);
      } catch {
        // the source went away mid-copy; the next tick decides again
      }
      seen.delete(rel);
    }
  };
}

export interface SyncOptions extends WorkspaceFakeOptions {
  /** How long a new file takes to appear on the other side. */
  readonly delayMs: number;
  /** Which directions the copier runs. Default both. */
  readonly toSandbox?: boolean;
  readonly toHost?: boolean;
}

/**
 * A synchronized workspace: a separate directory, seeded with a copy of the
 * workspace, and a small copier that moves new files across after `delayMs`.
 */
export function syncedBackend(options: SyncOptions): WorkspaceFake {
  const declaration = options.declaration ?? {
    mode: "synchronized",
    propagationMs: 2000,
  };
  return fake(
    "acme-synced",
    workspaceCapabilities(declaration),
    options,
    (profile) => {
      const root = mkdtempSync(join(tmpdir(), "piship-synced-"));
      cpSync(profile.workspace, root, { recursive: true });
      const toSandbox = copier(profile.workspace, root, options.delayMs);
      const toHost = copier(root, profile.workspace, options.delayMs);
      const timer = setInterval(() => {
        if (options.toSandbox !== false) toSandbox();
        if (options.toHost !== false) toHost();
      }, 25);
      timer.unref();
      return { root, stop: () => clearInterval(timer) };
    },
  );
}

/** A snapshot: a copy of the workspace made once at prepare, never synced. */
export function snapshotBackend(
  options: WorkspaceFakeOptions = {},
): WorkspaceFake {
  const capabilities: SandboxCapabilities = {
    isolation: "remote",
    planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
    network: ["deny", "allow"],
    localProcesses: false,
    ...(options.declaration ? { workspace: options.declaration } : {}),
  };
  return fake("acme-snapshot", capabilities, options, (profile) => {
    const root = mkdtempSync(join(tmpdir(), "piship-snapshot-"));
    cpSync(profile.workspace, root, { recursive: true });
    return { root };
  });
}
