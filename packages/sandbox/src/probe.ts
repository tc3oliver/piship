// Live verification: an adapter is only reported as enforcing a plane after a
// real child inside it failed to cross that plane.
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createTemporaryDirectory,
  reclaimTemporaryDirectories,
  type TemporaryDirectory,
} from "@piship/contracts";
import type {
  SandboxAdapter,
  SandboxCommand,
  WrappedCommand,
} from "./adapter.js";
import { sanitizeStderr } from "./environment.js";
import { spawnManaged } from "./process.js";
import { isWithin, realpathNearest, type SandboxProfile } from "./profile.js";

export const CONTAINMENT_PLANES = [
  "filesystem-read-deny",
  "filesystem-write-allowlist",
  "network-deny",
  "environment-filter",
  "git-control-protection",
] as const;
export type ContainmentPlane = (typeof CONTAINMENT_PLANES)[number];

export type ProbeResult =
  | {
      readonly ok: true;
      readonly planes: readonly ContainmentPlane[];
      /**
       * Checks that failed without failing the probe: only
       * `git-control-protection`, which is probed and reported but not yet
       * required of local backends.
       */
      readonly warnings?: readonly string[];
    }
  | { readonly ok: false; readonly reason: string };

export interface ProbeOptions {
  /** The exact environment the probe child receives (already filtered). */
  readonly env: Readonly<Record<string, string>>;
  /** Names the child may see besides `profile.environmentAllow`. */
  readonly injected?: readonly string[];
  readonly timeoutMs?: number;
  /** External address that must be unreachable in network deny mode. */
  readonly externalHost?: string;
}

interface ProbeReport {
  readonly outsideWrite: boolean;
  readonly insideWrite: boolean;
  readonly deniedDirWrite: boolean;
  readonly deniedDirLeak: boolean;
  readonly deniedFileLeak: boolean;
  readonly configuredLeaks: readonly string[];
  readonly env: readonly string[];
  readonly external: boolean;
  readonly loopback: boolean;
  readonly protectedFileWrite: boolean;
  readonly protectedDirWrite: boolean;
  readonly pinnedRename: boolean;
}

// Runs inside the sandbox; reports only booleans and names, never contents.
const PROBE_SCRIPT = `
const fs = require("node:fs");
const net = require("node:net");
const c = JSON.parse(process.argv[1]);
const write = (p) => { try { fs.writeFileSync(p, "probe"); return true; } catch { return false; } };
const dirLeaks = (p) => { try { return fs.readdirSync(p).length > 0; } catch { return false; } };
const fileLeaks = (p) => { try { return fs.readFileSync(p).length > 0; } catch { return false; } };
const rename = (from, to) => { try { fs.renameSync(from, to); return true; } catch { return false; } };
const connect = (host, port) => new Promise((done) => {
  const socket = net.connect({ host, port });
  const timer = setTimeout(() => { socket.destroy(); done(false); }, c.connectTimeoutMs);
  socket.once("connect", () => { clearTimeout(timer); socket.destroy(); done(true); });
  socket.once("error", () => { clearTimeout(timer); done(false); });
});
(async () => {
  const report = {
    outsideWrite: write(c.outsideFile),
    insideWrite: write(c.insideFile),
    deniedDirWrite: write(c.deniedDirWriteFile),
    deniedDirLeak: dirLeaks(c.deniedDir) || fileLeaks(c.deniedDirFile),
    deniedFileLeak: fileLeaks(c.deniedFile),
    configuredLeaks: c.configured.filter((p) => dirLeaks(p) || fileLeaks(p)),
    env: Object.keys(process.env),
    external: c.network ? await connect(c.externalHost, 443) : false,
    loopback: c.network ? await connect("127.0.0.1", c.loopbackPort) : false,
    protectedFileWrite: write(c.protectedFile),
    protectedDirWrite: write(c.protectedDirFile),
    pinnedRename: rename(c.pinnedDir, c.pinnedMoved),
  };
  process.stdout.write(JSON.stringify(report));
})();
`;

function outsideLocation(
  profile: SandboxProfile,
): TemporaryDirectory | undefined {
  const candidates = ["/var/tmp", tmpdir(), profile.homeDir];
  for (const candidate of candidates) {
    const real = realpathNearest(candidate);
    if (profile.writeAllow.some((path) => isWithin(real, path))) continue;
    try {
      // A probe killed before it cleaned up left its directory here.
      reclaimTemporaryDirectories(real, ["probe"]);
      return createTemporaryDirectory(real, "probe");
    } catch {
      // not writable on the host; try the next one
    }
  }
  return undefined;
}

function listen(): Promise<{
  server: Server;
  port: number;
  hits: () => number;
}> {
  let hits = 0;
  const server = createServer((socket) => {
    hits++;
    socket.destroy();
  });
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolvePromise({ server, port, hits: () => hits });
    });
  });
}

function evaluate(
  report: ProbeReport,
  paths: {
    outsideFile: string;
    insideFile: string;
    deniedDirWriteFile: string;
  },
  profile: SandboxProfile,
  allowedNames: ReadonlySet<string>,
  loopbackHits: number,
): string[] {
  const failures: string[] = [];
  if (report.outsideWrite || existsSync(paths.outsideFile))
    failures.push("a write outside the allowed paths succeeded");
  if (!report.insideWrite || !existsSync(paths.insideFile))
    failures.push("a write inside an allowed path failed");
  if (report.deniedDirWrite || existsSync(paths.deniedDirWriteFile))
    failures.push(
      "a write into a denied directory inside an allowed path succeeded",
    );
  if (report.deniedDirLeak) failures.push("a denied directory was readable");
  if (report.deniedFileLeak) failures.push("a denied file was readable");
  for (const path of report.configuredLeaks)
    failures.push(`configured read-denied path ${path} was readable`);
  const extra = report.env.filter((name) => !allowedNames.has(name));
  if (extra.length)
    failures.push(
      `unapproved environment variables reached the child: ${extra.join(", ")}`,
    );
  if (profile.network === "deny") {
    if (report.external)
      failures.push("an external network connection succeeded");
    if (report.loopback || loopbackHits > 0)
      failures.push("a connection to a host loopback listener succeeded");
  }
  return failures;
}

/** Why `git-control-protection` does not hold, from the probe's own protected paths. */
function gitControlFailures(
  report: ProbeReport,
  paths: {
    protectedFile: string;
    protectedDirFile: string;
    pinnedDir: string;
    pinnedMoved: string;
  },
): string[] {
  const failures: string[] = [];
  let intact = false;
  try {
    intact = readFileSync(paths.protectedFile, "utf8") === PROTECTED_CONTENT;
  } catch {
    // missing counts as changed
  }
  if (report.protectedFileWrite || !intact)
    failures.push("a protected file inside an allowed path was writable");
  if (report.protectedDirWrite || existsSync(paths.protectedDirFile))
    failures.push("a file could be created in a protected directory");
  if (
    report.pinnedRename ||
    !existsSync(paths.pinnedDir) ||
    existsSync(paths.pinnedMoved)
  )
    failures.push("the directory holding a protected file could be renamed");
  return failures;
}

const PROTECTED_CONTENT = "protected";

/**
 * Something the probe can run a child in: an adapter, or a backend that
 * prepares a wrapping instance for the probe's own profile.
 */
export interface ProbeTarget {
  prepare(profile: SandboxProfile): Promise<{
    wrap(command: SandboxCommand): WrappedCommand;
    dispose(): Promise<void>;
  }>;
}

/** Spawn a real child inside the adapter and verify every claimed plane. */
export async function probeSandbox(
  target: SandboxAdapter | ProbeTarget,
  profile: SandboxProfile,
  options: ProbeOptions,
): Promise<ProbeResult> {
  const secret = randomBytes(12).toString("hex");
  mkdirSync(profile.tmpDir, { recursive: true, mode: 0o700 });
  reclaimTemporaryDirectories(profile.tmpDir, ["probe"]);
  const probe = createTemporaryDirectory(profile.tmpDir, "probe");
  const probeDir = probe.path;
  const outside = outsideLocation(profile);
  const outsideDir = outside?.path;
  const listener = profile.network === "deny" ? await listen() : undefined;
  try {
    if (!outsideDir)
      return {
        ok: false,
        reason:
          "no host location outside the write allowlist is available to verify write denial",
      };
    const allowedDir = join(probeDir, "allowed");
    const deniedDir = join(allowedDir, "denied-dir");
    const deniedFile = join(allowedDir, "denied-file");
    mkdirSync(deniedDir, { recursive: true });
    writeFileSync(join(deniedDir, "secret"), secret);
    writeFileSync(deniedFile, secret);
    // git-control-protection: a protected file, a protected directory, and
    // a protected file whose parent directory must stay pinned in place.
    const protectedFile = join(allowedDir, "protected-file");
    const protectedDir = join(allowedDir, "protected-dir");
    const pinnedDir = join(allowedDir, "pinned");
    const pinnedFile = join(pinnedDir, "control");
    mkdirSync(protectedDir);
    mkdirSync(pinnedDir);
    writeFileSync(protectedFile, PROTECTED_CONTENT);
    writeFileSync(pinnedFile, PROTECTED_CONTENT);
    const probeProfile: SandboxProfile = {
      ...profile,
      writeAllow: [...profile.writeAllow, allowedDir],
      readDeny: [...profile.readDeny, deniedDir, deniedFile],
      writeProtect: {
        files: [...profile.writeProtect.files, protectedFile, pinnedFile],
        directories: [...profile.writeProtect.directories, protectedDir],
      },
    };
    const paths = {
      outsideFile: join(outsideDir, "write-probe"),
      insideFile: join(allowedDir, "write-probe"),
      deniedDirWriteFile: join(deniedDir, "write-probe"),
    };
    const gitPaths = {
      protectedFile,
      protectedDirFile: join(protectedDir, "write-probe"),
      pinnedDir,
      pinnedMoved: join(allowedDir, "pinned-moved"),
    };
    const input = JSON.stringify({
      ...paths,
      ...gitPaths,
      deniedDir,
      deniedDirFile: join(deniedDir, "secret"),
      deniedFile,
      configured: profile.readDeny.filter((path) => existsSync(path)),
      network: profile.network === "deny",
      externalHost: options.externalHost ?? "1.1.1.1",
      loopbackPort: listener?.port ?? 0,
      connectTimeoutMs: 3000,
    });
    const instance =
      "wrap" in target
        ? {
            wrap: (command: SandboxCommand) =>
              target.wrap(probeProfile, command),
            dispose: async () => {},
          }
        : await target.prepare(probeProfile);
    let wrapped: WrappedCommand;
    try {
      wrapped = instance.wrap({
        file: process.execPath,
        args: ["-e", PROBE_SCRIPT, input],
        cwd: allowedDir,
        env: options.env,
      });
    } catch (error) {
      await instance.dispose();
      throw error;
    }
    let stdout = "";
    let stderr = "";
    const child = spawnManaged({
      file: wrapped.file,
      args: wrapped.args,
      cwd: wrapped.cwd,
      env: wrapped.env,
      timeoutMs: options.timeoutMs ?? 20_000,
      graceMs: 500,
      onStdout: (chunk) => {
        stdout += chunk.toString("utf8");
      },
      onStderr: (chunk) => {
        stderr += chunk.toString("utf8");
      },
    });
    const exit = await child.exited;
    await instance.dispose();
    let report: ProbeReport;
    try {
      report = JSON.parse(stdout) as ProbeReport;
    } catch {
      const why =
        exit.error ??
        (exit.timedOut ? "timed out" : `exit ${exit.code ?? exit.signal}`);
      return {
        ok: false,
        reason: `the probe child did not run inside the sandbox (${why}): ${sanitizeStderr(stderr.trim(), 400)}`,
      };
    }
    const allowedNames = new Set([
      ...profile.environmentAllow,
      ...(options.injected ?? []),
    ]);
    const failures = evaluate(
      report,
      paths,
      profile,
      allowedNames,
      listener?.hits() ?? 0,
    );
    if (failures.length)
      return {
        ok: false,
        reason: `sandbox probe failed: ${failures.join("; ")}`,
      };
    const planes: ContainmentPlane[] = [
      "filesystem-read-deny",
      "filesystem-write-allowlist",
    ];
    if (profile.network === "deny") planes.push("network-deny");
    planes.push("environment-filter");
    const git = gitControlFailures(report, gitPaths);
    if (!git.length) planes.push("git-control-protection");
    return {
      ok: true,
      planes,
      ...(git.length
        ? {
            warnings: [
              `git-control-protection is not proven, so the project's git control files and hooks may be writable from sandboxed commands: ${git.join("; ")}`,
            ],
          }
        : {}),
    };
  } finally {
    listener?.server.close();
    probe.remove();
    outside?.remove();
  }
}
