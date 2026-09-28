// Live verification: an adapter is only reported as enforcing a plane after a
// real child inside it failed to cross that plane.
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SandboxAdapter } from "./adapter.js";
import { sanitizeStderr } from "./environment.js";
import { spawnManaged } from "./process.js";
import { isWithin, realpathNearest, type SandboxProfile } from "./profile.js";

export const CONTAINMENT_PLANES = [
  "filesystem-read-deny",
  "filesystem-write-allowlist",
  "network-deny",
  "environment-filter",
] as const;
export type ContainmentPlane = (typeof CONTAINMENT_PLANES)[number];

export type ProbeResult =
  | { readonly ok: true; readonly planes: readonly ContainmentPlane[] }
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
}

// Runs inside the sandbox; reports only booleans and names, never contents.
const PROBE_SCRIPT = `
const fs = require("node:fs");
const net = require("node:net");
const c = JSON.parse(process.argv[1]);
const write = (p) => { try { fs.writeFileSync(p, "probe"); return true; } catch { return false; } };
const dirLeaks = (p) => { try { return fs.readdirSync(p).length > 0; } catch { return false; } };
const fileLeaks = (p) => { try { return fs.readFileSync(p).length > 0; } catch { return false; } };
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
  };
  process.stdout.write(JSON.stringify(report));
})();
`;

function outsideLocation(profile: SandboxProfile): string | undefined {
  const candidates = ["/var/tmp", tmpdir(), profile.homeDir];
  for (const candidate of candidates) {
    const real = realpathNearest(candidate);
    if (profile.writeAllow.some((path) => isWithin(real, path))) continue;
    try {
      return mkdtempSync(join(real, ".piship-probe-"));
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

/** Spawn a real child inside the adapter and verify every claimed plane. */
export async function probeSandbox(
  adapter: SandboxAdapter,
  profile: SandboxProfile,
  options: ProbeOptions,
): Promise<ProbeResult> {
  const secret = randomBytes(12).toString("hex");
  mkdirSync(profile.tmpDir, { recursive: true, mode: 0o700 });
  const probeDir = mkdtempSync(join(profile.tmpDir, ".piship-probe-"));
  const outsideDir = outsideLocation(profile);
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
    const probeProfile: SandboxProfile = {
      ...profile,
      writeAllow: [...profile.writeAllow, allowedDir],
      readDeny: [...profile.readDeny, deniedDir, deniedFile],
    };
    const paths = {
      outsideFile: join(outsideDir, "write-probe"),
      insideFile: join(allowedDir, "write-probe"),
      deniedDirWriteFile: join(deniedDir, "write-probe"),
    };
    const input = JSON.stringify({
      ...paths,
      deniedDir,
      deniedDirFile: join(deniedDir, "secret"),
      deniedFile,
      configured: profile.readDeny.filter((path) => existsSync(path)),
      network: profile.network === "deny",
      externalHost: options.externalHost ?? "1.1.1.1",
      loopbackPort: listener?.port ?? 0,
      connectTimeoutMs: 3000,
    });
    const wrapped = adapter.wrap(probeProfile, {
      file: process.execPath,
      args: ["-e", PROBE_SCRIPT, input],
      cwd: allowedDir,
      env: options.env,
    });
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
    return { ok: true, planes };
  } finally {
    listener?.server.close();
    rmSync(probeDir, { recursive: true, force: true });
    if (outsideDir) rmSync(outsideDir, { recursive: true, force: true });
  }
}
