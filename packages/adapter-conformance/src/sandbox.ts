// The sandbox conformance kit. It runs a sandbox backend the way PiShip
// does, through `available`, `capabilities`, `prepare`, `exec`, and
// `dispose`, and checks every claim by running commands inside the backend:
// a file planted on this host must stay out of reach, a loopback listener
// must stay unreachable, a planted launcher secret must not arrive, and a
// timed-out or cancelled command must not write the marker it would write
// later. For a shared or synchronized workspace it runs PiShip's two-way
// sentinel and the git control probe from outside. A behavior that needs
// something only the adapter author can provide (a count of live sandboxes,
// a way to replace the environment) takes a hook and is skipped without it,
// never passed. The kit imports only @piship/adapter-sdk and `node:`
// built-ins.
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type CustomBackendContext,
  HOST_FILESYSTEM_ISOLATION,
  isPiShipError,
  type ManagedFetch,
  redact,
  SANDBOX_GUARANTEES,
  type SandboxAdapterFactory,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxExecResult,
  type SandboxGuarantee,
  type SandboxInstance,
  type SandboxProfile,
} from "@piship/adapter-sdk";
import type { ConformanceReport, ConformanceResult } from "./index.js";
import { check, Finding, type Outcome, renderings, settle } from "./shared.js";

/**
 * What the sandbox kit checks, in report order, each with the contract
 * statement it holds the backend to.
 */
export const SANDBOX_CONTRACT = [
  {
    behavior: "availability",
    statement:
      "available() resolves {available: true} where the backend can be used, and {available: false, reason} with a non-empty reason where it cannot, such as when its service is unreachable; it never throws",
  },
  {
    behavior: "capabilities",
    statement:
      "capabilities() is well formed and stable: an isolation kind, known guarantees, network modes it can enforce, localProcesses only for a local backend, a valid workspace declaration, and the guarantees a required sandbox needs for its isolation and workspace; a remote backend with a shared or synchronized workspace never claims host-filesystem-isolation",
  },
  {
    behavior: "prepare",
    statement:
      "prepare(profile) resolves an instance with exec() and dispose() (and wrap() when it declares localProcesses), and every call creates its own sandbox: disposing one instance leaves another working",
  },
  {
    behavior: "execute",
    statement:
      "exec() runs the command at the workspace path it was given, passes the environment through as given, streams stdout to onStdout and stderr to onStderr, and resolves with the command's exit code",
  },
  {
    behavior: "environment filtering",
    statement:
      "a command receives exactly the environment in the request: a variable from the launcher's own environment never reaches it, and an allowlisted variable has the approved value, not the launcher's",
  },
  {
    behavior: "secret leakage",
    statement:
      "the credential in the context never appears in available(), capabilities(), epoch(), a command's environment or output, an error, or a line the backend logs, also when a request fails with a transport error or a 401 that quotes it, and it is sent only to the endpoint's origin",
  },
  {
    behavior: "filesystem claims",
    statement:
      "every filesystem guarantee the backend claims holds for a command run inside it: host-filesystem-isolation and workspace-confinement keep a file on this host outside the workspace unreadable and unwritable, filesystem-read-deny keeps readDeny paths unreadable, filesystem-write-allowlist allows writes in the workspace and nowhere else, and a local backend's git-control-protection keeps the protected paths read-only",
  },
  {
    behavior: "network claims",
    statement:
      "with the profile's network denied, a command inside the sandbox cannot connect to a listener that it reaches when the network is allowed; a remote backend's declared networkProbe is that listener unless networkTarget is given, and it must be reachable with the network allowed",
  },
  {
    behavior: "timeout",
    statement:
      "when io.signal aborts because a command that is running and streaming output exceeded its timeout, exec() settles within the settle time, the command and the processes it started are stopped, so the marker it would write after the timeout never appears, and the instance runs the next command",
  },
  {
    behavior: "cancellation",
    statement:
      "an aborted io.signal stops the command, also when the abort arrives while the backend is still starting it or before it printed anything; a backend that cannot stop it within the settle time is retired (disposed), and dispose() then stops it",
  },
  {
    behavior: "cleanup",
    statement:
      "dispose() removes what prepare() created: the backend holds no more sandboxes after dispose() than before prepare()",
  },
  {
    behavior: "dispose",
    statement:
      "dispose() stops a command that is still running, resolves without throwing, resolves again when called a second time, and the instance runs no command afterwards",
  },
  {
    behavior: "fail-closed behavior",
    statement:
      "the backend never reports a result it did not observe: a command that cannot run inside the sandbox does not exit 0, and PiShip's own sandbox check is run like any other command, never answered by the backend",
  },
  {
    behavior: "workspace consistency",
    statement:
      "a declared shared or synchronized workspace passes PiShip's two-way sentinel on the first command: a file the host writes reaches the sandbox and a file the sandbox writes reaches the host, both at once for shared and within propagationMs for synchronized",
  },
  {
    behavior: "git control protection",
    statement:
      "with a shared or synchronized workspace, the protected git control files and directories cannot be changed from inside the sandbox: appending zero bytes to a protected file and creating a file in a protected directory both fail, and the check command itself completes",
  },
  {
    behavior: "workspace re-check",
    statement:
      "the workspace stays consistent across a session: the sentinel passes again once PiShip's 30-minute validity window has passed (on the kit's injected clock), epoch() returns a stable non-secret string or undefined, and after the environment is replaced it changes and the sentinel passes in the new environment",
  },
] as const;

export type SandboxBehavior = (typeof SANDBOX_CONTRACT)[number]["behavior"];

/** The behaviors the sandbox kit reports, in report order. */
export const SANDBOX_BEHAVIORS: readonly SandboxBehavior[] =
  SANDBOX_CONTRACT.map((entry) => entry.behavior);

export interface SandboxKitOptions {
  /**
   * Merged into the context the adapter factory receives. `fetch` is the
   * client the backend uses for its service (default: the global fetch);
   * the kit wraps it to watch where the credential goes and to simulate an
   * unreachable service. `endpoint` is the backend's service URL.
   */
  readonly context?: Partial<
    Pick<CustomBackendContext, "distributionId" | "endpoint" | "fetch">
  >;
  /**
   * An empty directory the backend's sandbox sees as its workspace, for a
   * backend that mounts or syncs a host directory. The kit writes its
   * fixture (a `.git` directory and its own scratch directory) there and
   * removes it afterwards. Default: a new temporary directory.
   */
  readonly workspace?: string;
  /**
   * How long the backend has to settle after the kit aborted `io.signal`,
   * in milliseconds. Default 5000, PiShip's own.
   */
  readonly settleMs?: number;
  /**
   * The longest one backend call may take before the kit reports it hung,
   * in milliseconds. Default 30 000.
   */
  readonly callTimeoutMs?: number;
  /**
   * The window a declared `shared` workspace gets per direction before the
   * kit counts it missing, in milliseconds. Default 10 000, PiShip's own. A
   * `synchronized` workspace gets its `propagationMs`.
   */
  readonly sharedWindowMs?: number;
  /**
   * How many sandboxes the backend's service holds now (sessions, pods,
   * VMs, temporary roots). Enables `cleanup`; without it `cleanup` is
   * skipped.
   */
  readonly sandboxes?: () => number | Promise<number>;
  /**
   * Move `instance` to a new environment behind its back, as a service does
   * when it replaces an expired pod or VM. Enables the epoch part of
   * `workspace re-check`.
   */
  readonly replaceEnvironment?: (
    instance: SandboxInstance,
  ) => void | Promise<void>;
  /**
   * A TCP listener the sandbox would reach if its network were allowed.
   * Default: a listener the kit runs on this host's loopback, which a
   * remote sandbox cannot reach (its loopback is its own).
   */
  readonly networkTarget?: { readonly host: string; readonly port: number };
  /**
   * Run only these behaviors, to iterate on one; every other behavior is
   * reported `skipped` as not selected, never passed. Default: all.
   */
  readonly only?: readonly SandboxBehavior[];
}

/** What the kit tests: an adapter module's default export, or a backend. */
export type SandboxAdapterUnderTest = SandboxAdapterFactory | SandboxBackend;

type WorkspaceDeclaration = NonNullable<SandboxCapabilities["workspace"]>;

// ------------------------------------------------------------- constants

/** PiShip's validity window for a workspace verification. */
const VALIDITY_MS = 30 * 60_000;
const DEFAULT_PROPAGATION_MS = 10_000;
const POLL_MS = 200;
/** A marker command writes its marker after `sleep 1`. */
const LATE_MS = 1_000;
/** How long after that the kit looks for the marker. */
const MARGIN_MS = 800;
/** How long a command runs before the kit's timeout aborts it. */
const RUNNING_MS = 200;
const WS = "piship-ws";
const READY = "piship-sandbox-ready";
const UNLISTED = "PISHIP_PROBE_UNLISTED";
/** The sandbox's own PATH a local backend's command receives. */
const LOCAL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";
const PROTECTED_FILES = [".git/config"];
const PROTECTED_DIRECTORIES = [".git/hooks", ".git/info"];

const ENV = {
  value: "PISHIP_CONFORMANCE_VALUE",
  approved: "PISHIP_CONFORMANCE_APPROVED",
  hostToken: "PISHIP_CONFORMANCE_HOST_TOKEN",
  hostOnly: "PISHIP_CONFORMANCE_HOST_ONLY",
} as const;

// ------------------------------------------------------------ utilities

const quote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, ms)));

function sha256(path: string): string | undefined {
  try {
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  } catch {
    return undefined;
  }
}

function listing(path: string): string {
  try {
    return readdirSync(path).sort().join("\n");
  } catch {
    return "(missing)";
  }
}

// Lines the backend logs while the leakage check runs. One interceptor for
// the whole process, so concurrent kit runs never restore each other's. A
// line that holds a watched credential is counted and passed on with the
// credential removed, so the kit's own sentinel never reaches a terminal.
// A stream write may hold only part of a credential, so each stream keeps
// back a tail shorter than the longest credential until the next write (or
// until the watch ends) and looks for credentials across the two.
const logWatchers = new Map<string, () => void>();
let restoreLogs: (() => void) | undefined;
const REDACTED = Buffer.from("[redacted]");

/**
 * The bytes of `pending` and `chunk` that can be passed on, with every
 * watched credential that starts in them removed, and the tail to keep.
 * At the end of the watch (`final`) nothing is kept.
 */
function scrubStream(
  bytes: Buffer,
  final: boolean,
): { output: Buffer; tail: Buffer } {
  const secrets = [...logWatchers].map(
    ([secret, onLeak]) => [Buffer.from(secret), onLeak] as const,
  );
  const longest = Math.max(0, ...secrets.map(([secret]) => secret.length));
  // A credential that starts at or after `limit` may still be incomplete.
  const limit = final ? bytes.length : bytes.length - (longest - 1);
  const parts: Buffer[] = [];
  let from = 0;
  for (;;) {
    let found: { at: number; secret: Buffer; onLeak: () => void } | undefined;
    for (const [secret, onLeak] of secrets) {
      const at = bytes.indexOf(secret, from);
      if (at !== -1 && at < limit && (!found || at < found.at))
        found = { at, secret, onLeak };
    }
    if (!found) break;
    found.onLeak();
    parts.push(bytes.subarray(from, found.at), REDACTED);
    from = found.at + found.secret.length;
  }
  const cut = Math.max(from, limit);
  parts.push(bytes.subarray(from, cut));
  return { output: Buffer.concat(parts), tail: bytes.subarray(cut) };
}

/** The line with every watched credential removed, or undefined when it holds none. */
function scrubLogged(text: string): string | undefined {
  let output = text;
  for (const [secret, onLeak] of logWatchers)
    if (output.includes(secret)) {
      onLeak();
      output = output.split(secret).join("[redacted]");
    }
  return output === text ? undefined : output;
}

function watchLogs(secret: string, onLeak: () => void): () => void {
  logWatchers.set(secret, onLeak);
  if (!restoreLogs) {
    const methods = ["log", "info", "warn", "error", "debug"] as const;
    const original = methods.map((method) => console[method]);
    methods.forEach((method, index) => {
      const previous = original[index] as (...args: unknown[]) => void;
      console[method] = (...args: unknown[]) => {
        const scrubbed = scrubLogged(
          args.map((arg) => renderings(arg)).join(" "),
        );
        if (scrubbed === undefined) previous.apply(console, args);
        else previous.call(console, scrubbed);
      };
    });
    const streams = [process.stdout, process.stderr];
    const writes = streams.map((stream) => stream.write);
    const tails = streams.map(() => Buffer.alloc(0));
    streams.forEach((stream, index) => {
      const previous = writes[index] as (...args: unknown[]) => boolean;
      stream.write = ((chunk: unknown, ...rest: unknown[]) => {
        const encoding = typeof rest[0] === "string" ? rest[0] : undefined;
        const done = rest.find((arg) => typeof arg === "function") as
          | ((error?: Error | null) => void)
          | undefined;
        let bytes: Buffer;
        if (typeof chunk === "string")
          bytes = Buffer.from(chunk, encoding as BufferEncoding | undefined);
        else if (chunk instanceof Uint8Array)
          bytes = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.length);
        // Not something a stream writes: the stream reports the error.
        else return previous.call(stream, chunk, ...rest);
        const { output, tail } = scrubStream(
          Buffer.concat([tails[index] as Buffer, bytes]),
          false,
        );
        tails[index] = Buffer.from(tail);
        if (output.length > 0) return previous.call(stream, output, done);
        if (done) process.nextTick(done);
        return true;
      }) as typeof stream.write;
    });
    restoreLogs = () => {
      methods.forEach((method, index) => {
        console[method] = original[index] as (typeof console)[typeof method];
      });
      streams.forEach((stream, index) => {
        stream.write = writes[index] as typeof stream.write;
        const { output } = scrubStream(tails[index] as Buffer, true);
        tails[index] = Buffer.alloc(0);
        if (output.length > 0) stream.write(output);
      });
    };
  }
  return () => {
    // The last watch flushes the kept tails while its credential is still watched.
    if (logWatchers.size === 1 && logWatchers.has(secret)) {
      restoreLogs?.();
      restoreLogs = undefined;
    }
    logWatchers.delete(secret);
  };
}

// The launcher environment the kit plants while environment filtering runs.
// Reference-counted, so concurrent kit runs do not remove each other's.
const planted = new Map<string, { count: number; previous?: string }>();

function plant(variables: Record<string, string>): () => void {
  for (const [name, value] of Object.entries(variables)) {
    const entry = planted.get(name);
    if (entry) entry.count++;
    else
      planted.set(name, {
        count: 1,
        ...(process.env[name] !== undefined
          ? { previous: process.env[name] }
          : {}),
      });
    process.env[name] = value;
  }
  return () => {
    for (const name of Object.keys(variables)) {
      const entry = planted.get(name);
      if (!entry) continue;
      entry.count--;
      if (entry.count > 0) continue;
      planted.delete(name);
      if (entry.previous === undefined) delete process.env[name];
      else process.env[name] = entry.previous;
    }
  };
}

// ------------------------------------------------------------ declaration

/** Why a network probe is malformed, or undefined (PiShip's rule). */
function probeProblem(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return "it is not an object";
  const { host, port } = value as { host?: unknown; port?: unknown };
  if (
    typeof host !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$/.test(host)
  )
    return "the host must be a hostname or an IP address without brackets or a port";
  if (
    !Number.isInteger(port) ||
    (port as number) < 1 ||
    (port as number) > 65535
  )
    return "the port must be an integer from 1 to 65535";
  return undefined;
}

/** Why a workspace declaration is malformed, or undefined. */
function declarationProblem(raw: unknown): string | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    return "the workspace declaration is not an object";
  const { mode, propagationMs, sentinelDir } =
    raw as Partial<WorkspaceDeclaration>;
  if (!["snapshot", "synchronized", "shared"].includes(mode as string))
    return "the workspace mode is not snapshot, synchronized, or shared";
  if (propagationMs !== undefined) {
    if (mode !== "synchronized")
      return "propagationMs applies only to a synchronized workspace";
    if (
      !Number.isInteger(propagationMs) ||
      propagationMs < 1 ||
      propagationMs > 60_000
    )
      return "propagationMs must be an integer from 1 to 60000";
  }
  if (sentinelDir !== undefined) {
    if (mode === "snapshot")
      return "sentinelDir does not apply to a snapshot workspace";
    if (
      typeof sentinelDir !== "string" ||
      sentinelDir.length === 0 ||
      sentinelDir.length > 256
    )
      return "sentinelDir must be a non-empty string";
    if (sentinelDir.startsWith("/"))
      return "sentinelDir must be workspace-relative";
    // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what this rejects
    if (/[\\\u0000-\u001f]/.test(sentinelDir))
      return "sentinelDir must use / separators and no control characters";
    if (sentinelDir.split("/").includes(".."))
      return "sentinelDir must not contain ..";
  }
  return undefined;
}

/** The declared workspace: shared for a local backend, snapshot when omitted. */
function declaration(
  capabilities: SandboxCapabilities,
): WorkspaceDeclaration | undefined {
  if (capabilities.isolation === "local") return { mode: "shared" };
  if (capabilities.workspace === undefined) return { mode: "snapshot" };
  return declarationProblem(capabilities.workspace)
    ? undefined
    : capabilities.workspace;
}

/** Why the declared capabilities are malformed or insufficient, or undefined. */
function capabilityProblem(value: unknown): string | undefined {
  if (!value || typeof value !== "object")
    return "capabilities() returned no object";
  const caps = value as Partial<SandboxCapabilities>;
  if (caps.isolation !== "local" && caps.isolation !== "remote")
    return "isolation is neither local nor remote";
  if (!Array.isArray(caps.planes)) return "planes is not a list";
  for (const plane of caps.planes)
    if (!SANDBOX_GUARANTEES.includes(plane as SandboxGuarantee))
      return `planes names an unknown guarantee (${String(plane).slice(0, 60)})`;
  if (new Set(caps.planes).size !== caps.planes.length)
    return "planes names a guarantee twice";
  if (!Array.isArray(caps.network) || caps.network.length === 0)
    return "network lists no mode";
  for (const mode of caps.network)
    if (mode !== "deny" && mode !== "allow")
      return "network lists a mode that is neither deny nor allow";
  if (new Set(caps.network).size !== caps.network.length)
    return "network lists a mode twice";
  if (typeof caps.localProcesses !== "boolean")
    return "localProcesses is not a boolean";
  if (caps.localProcesses && caps.isolation !== "local")
    return "localProcesses is true for a remote backend, which cannot contain local processes";
  const planes = caps.planes as readonly string[];
  const claims = (plane: string) => planes.includes(plane);
  if (caps.network.includes("deny") && !claims("network-deny"))
    return "it lists network mode deny but does not claim network-deny";
  if (claims("network-deny") && !caps.network.includes("deny"))
    return "it claims network-deny but does not list network mode deny";
  if (!claims("environment-filter"))
    return "it does not claim environment-filter, which every required sandbox needs";
  if (caps.isolation === "local") {
    for (const plane of [HOST_FILESYSTEM_ISOLATION, "workspace-confinement"])
      if (claims(plane))
        return `a local backend runs commands on this host, so it cannot claim ${plane}`;
    for (const plane of ["filesystem-read-deny", "filesystem-write-allowlist"])
      if (!claims(plane))
        return `a local backend must claim ${plane} to enforce PiShip's path policy`;
    return undefined;
  }
  if (caps.workspace !== undefined) {
    const problem = declarationProblem(caps.workspace);
    if (problem) return `it declares a malformed workspace: ${problem}`;
  }
  if (caps.networkProbe !== undefined) {
    const problem = probeProblem(caps.networkProbe);
    if (problem) return `it declares a malformed network probe: ${problem}`;
  }
  const mode = caps.workspace?.mode ?? "snapshot";
  if (mode === "snapshot") {
    if (!claims(HOST_FILESYSTEM_ISOLATION))
      return `a remote backend with a snapshot workspace must claim ${HOST_FILESYSTEM_ISOLATION}`;
    return undefined;
  }
  if (claims(HOST_FILESYSTEM_ISOLATION))
    return `it claims ${HOST_FILESYSTEM_ISOLATION} although its workspace is ${mode}, which reaches this host's files`;
  for (const plane of ["workspace-confinement", "git-control-protection"])
    if (!claims(plane))
      return `a remote backend with a ${mode} workspace must claim ${plane}`;
  return undefined;
}

// ---------------------------------------------------------------- scripts

/** PiShip's two-way sentinel (POSIX sh; output is tokens only). */
function sentinelScript(
  dir: string,
  hostToken: string,
  sandboxToken: string,
  polls: number,
): string {
  const h2s = `"$d/h2s"`;
  const token = quote(hostToken);
  return [
    `d=${quote(dir)}; n=${polls}; i=0`,
    `while [ "$(cat ${h2s} 2>/dev/null)" != ${token} ] && [ "$i" -lt "$n" ]; do if sleep 0.2 2>/dev/null; then i=$((i+1)); else sleep 1; i=$((i+5)); fi; done`,
    `if [ "$(cat ${h2s} 2>/dev/null)" = ${token} ]; then echo "${WS} h2s $i"; else echo "${WS} h2s missing"; fi`,
    `if mkdir -p "$d" 2>/dev/null && printf '%s' ${quote(sandboxToken)} > "$d/s2h.tmp" 2>/dev/null && mv -f "$d/s2h.tmp" "$d/s2h" 2>/dev/null; then echo "${WS} s2h written"; else echo "${WS} s2h failed"; fi`,
    `echo ${WS} done`,
  ].join("\n");
}

/** PiShip's git control probe: changes nothing that exists. */
function gitProbeScript(nonce: string): string {
  const lines = PROTECTED_FILES.map(
    (file, index) =>
      `if [ -f ${quote(file)} ] && ( : >> ${quote(file)} ) 2>/dev/null; then echo "${WS} writable file ${index}"; fi`,
  );
  PROTECTED_DIRECTORIES.forEach((dir, index) => {
    lines.push(
      `if ( mkdir -p ${quote(dir)} && : > ${quote(`${dir}/.piship-probe-${nonce}`)} ) 2>/dev/null; then echo "${WS} writable dir ${index}"; fi`,
    );
  });
  lines.push(`echo ${WS} done`);
  return lines.join("\n");
}

/** A connection attempt from inside the sandbox; prints one token. */
function connectScript(host: string, port: number): string {
  return [
    `t=${quote(host)}; p=${port}`,
    `if command -v nc >/dev/null 2>&1; then if nc -z -w 2 "$t" "$p" >/dev/null 2>&1; then echo piship-net connected; else echo piship-net refused; fi`,
    `elif command -v bash >/dev/null 2>&1; then if command -v timeout >/dev/null 2>&1; then w='timeout 3'; else w=''; fi; if $w bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$t" "$p" >/dev/null 2>&1; then echo piship-net connected; else echo piship-net refused; fi`,
    "else echo piship-net unchecked; fi",
  ].join("\n");
}

// ---------------------------------------------------------------- harness

type Settled =
  | {
      readonly kind: "exit";
      readonly exitCode: number | null;
      readonly signal?: string | null;
    }
  | { readonly kind: "rejected"; readonly error: unknown };

interface Execution {
  readonly controller: AbortController;
  readonly stdout: () => string;
  readonly stderr: () => string;
  /** Settles with the exec outcome; never rejects. */
  readonly settled: Promise<Settled>;
  /** Resolves once stdout contains `text`. */
  readonly saw: (text: string) => Promise<void>;
  /** When the first stdout arrived, in `Date.now()` terms; undefined before. */
  readonly firstOutputAt: () => number | undefined;
}

interface Ran {
  readonly settled: Settled;
  readonly stdout: string;
  readonly stderr: string;
}

interface SentinelOutcome {
  readonly completed: boolean;
  readonly exitCode: number | null | undefined;
  readonly hostToSandbox: "immediate" | "delayed" | "missing";
  readonly sandboxToHost: "immediate" | "delayed" | "missing";
  readonly windowMs: number;
}

/**
 * Wait until a command is running: shortly after its first line arrives, or
 * after a fixed time for a backend that returns output only when the
 * command ends. False when the command already ended.
 */
async function whileRunning(execution: Execution): Promise<boolean> {
  let ended = false;
  void execution.settled.then(() => {
    ended = true;
  });
  await Promise.race([
    execution.saw("started").then(() => sleep(RUNNING_MS)),
    sleep(RUNNING_MS * 3),
  ]);
  return !ended;
}

/**
 * Wait until a command that did not stop would have written its marker. The
 * marker comes LATE_MS after the command started, and the kit knows the
 * command started when its first output arrives: a backend under load can
 * start it long after the kit asked, so the wait counts from the output and
 * grows if the output arrives while the kit waits. A command that has
 * printed nothing is counted from `from`, when the kit aborted or disposed,
 * plus `silentMs`: a command aborted before it started may be started by a
 * backend that ignored the abort later than the window, and a silent command
 * cannot say so. The extra wait is spent only while nothing has printed, so
 * it stays bounded, and output that arrives in it is counted as above.
 */
async function markerWindow(
  execution: Execution,
  from: number,
  silentMs = 0,
): Promise<void> {
  for (;;) {
    const remaining =
      (execution.firstOutputAt() ?? from + silentMs) +
      LATE_MS +
      MARGIN_MS -
      Date.now();
    if (remaining <= 0) return;
    await sleep(remaining);
  }
}

/** Why a sentinel outcome breaks the declaration, or undefined. */
function sentinelProblem(
  outcome: SentinelOutcome,
  mode: "shared" | "synchronized",
): string | undefined {
  if (!outcome.completed)
    return `the workspace check command did not complete (exit ${outcome.exitCode ?? "none"})`;
  if (
    outcome.hostToSandbox === "missing" &&
    outcome.sandboxToHost === "missing"
  )
    return `neither side saw the other's file within ${outcome.windowMs} ms: the sandbox sees a snapshot, not a ${mode} workspace`;
  if (outcome.hostToSandbox === "missing")
    return `the sandbox did not see a file the host wrote within ${outcome.windowMs} ms`;
  if (outcome.sandboxToHost === "missing")
    return `the host did not see a file the sandbox wrote within ${outcome.windowMs} ms`;
  if (
    mode === "shared" &&
    (outcome.hostToSandbox === "delayed" || outcome.sandboxToHost === "delayed")
  )
    return "it declares shared, but a direction was delayed, which is synchronized, not shared";
  return undefined;
}

class Harness {
  readonly run = randomBytes(8).toString("hex");
  readonly credential = `conformance-sandbox-credential-${this.run}`;
  readonly hostToken = `conformance-host-token-${this.run}`;
  readonly hostOnly = `conformance-host-only-${this.run}`;
  readonly hostApproved = `conformance-host-approved-${this.run}`;
  readonly fileSecret = `conformance-host-file-${this.run}`;
  readonly deniedSecret = `conformance-denied-file-${this.run}`;
  /** The kit's scratch directory, workspace-relative. */
  readonly scratch = `.piship-conformance-${this.run.slice(0, 8)}`;
  readonly settleMs: number;
  readonly boundMs: number;
  readonly sharedWindowMs: number;
  readonly root: string;
  readonly workspace: string;
  readonly hostDir: string;
  /** What the kit created in an author-supplied workspace. */
  readonly #created: string[] = [];
  /** Instances prepared in the current behavior, and those already disposed. */
  #live = new Set<SandboxInstance>();
  #disposed = new WeakSet<SandboxInstance>();
  /** The fetch mode for the next backend the kit builds. */
  #fetchMode: "normal" | "down" | "quoting" | "unauthorized" = "normal";
  /** Origins that received the credential although they are not the endpoint's. */
  readonly strayOrigins = new Set<string>();
  caps: SandboxCapabilities | undefined;

  constructor(
    readonly adapter: SandboxAdapterUnderTest,
    readonly options: SandboxKitOptions,
  ) {
    this.settleMs = options.settleMs ?? 5_000;
    this.boundMs = options.callTimeoutMs ?? 30_000;
    this.sharedWindowMs = options.sharedWindowMs ?? 10_000;
    const supplied = options.workspace
      ? realpathSync(options.workspace)
      : undefined;
    if (supplied && readdirSync(supplied).length > 0)
      throw new RangeError("the workspace option must be an empty directory");
    this.root = realpathSync(
      mkdtempSync(join(tmpdir(), "piship-conformance-")),
    );
    if (supplied) this.workspace = supplied;
    else {
      this.workspace = join(this.root, "workspace");
      mkdirSync(this.workspace);
    }
    this.hostDir = join(this.root, "host");
    for (const dir of ["host", "home", "tmp"])
      mkdirSync(join(this.root, dir), { mode: 0o700 });
    writeFileSync(join(this.hostDir, "secret"), this.fileSecret);
    this.#fixture();
  }

  /** The project a backend sees: a git directory and the kit's scratch. */
  #fixture(): void {
    const ws = this.workspace;
    const make = (relative: string, content?: string) => {
      const path = join(ws, relative);
      if (content === undefined) mkdirSync(path, { recursive: true });
      else writeFileSync(path, content);
    };
    this.#created.push(".git", this.scratch);
    make(".git/hooks");
    make(".git/info");
    make(".git/config", "[core]\n\trepositoryformatversion = 0\n");
    make(".git/HEAD", "ref: refs/heads/main\n");
    make(".git/hooks/pre-commit.sample", "#!/bin/sh\nexit 0\n");
    make(".git/info/exclude", "# conformance\n");
    make(`${this.scratch}/denied`);
    make(`${this.scratch}/denied/secret`, this.deniedSecret);
  }

  get secrets(): readonly string[] {
    return [
      this.credential,
      this.hostToken,
      this.hostOnly,
      this.hostApproved,
      this.fileSecret,
      this.deniedSecret,
    ];
  }

  /** A reason with every kit secret removed. */
  scrub(text: string): string {
    let output = text;
    for (const secret of this.secrets)
      output = output.split(secret).join("[redacted]");
    return output;
  }

  /** A failure named by its code or class and a short redacted message. */
  describe(error: unknown): string {
    const name = isPiShipError(error)
      ? error.code
      : error instanceof Error
        ? error.name
        : "a value that is not an error";
    const message =
      error instanceof Error ? redact(error.message).slice(0, 160) : "";
    return this.scrub(message ? `${name}: ${message}` : name);
  }

  leaks(value: unknown): boolean {
    const text = typeof value === "string" ? value : renderings(value);
    return text.includes(this.credential);
  }

  profile(network: "deny" | "allow"): SandboxProfile {
    const ws = this.workspace;
    return {
      workspace: ws,
      homeDir: join(this.root, "home"),
      tmpDir: join(this.root, "tmp"),
      readDeny: [join(ws, this.scratch, "denied")],
      writeAllow: [ws, join(this.root, "tmp")],
      readOnly: [],
      writeProtect: {
        files: PROTECTED_FILES.map((file) => join(ws, file)),
        directories: PROTECTED_DIRECTORIES.map((dir) => join(ws, dir)),
      },
      network,
      environmentAllow: ["PATH", ENV.value, ENV.approved, UNLISTED],
      warnings: [],
    };
  }

  // -------------------------------------------------------------- context

  #fetch(): ManagedFetch {
    const base: ManagedFetch =
      this.options.context?.fetch ??
      ((url, init) => globalThis.fetch(url, init));
    const endpoint = this.options.context?.endpoint;
    const mode = this.#fetchMode;
    return async (url, init) => {
      const headers = new Headers(init?.headers);
      const text = `${String(url)}\n${[...headers].map(([k, v]) => `${k}: ${v}`).join("\n")}\n${typeof init?.body === "string" ? init.body : ""}`;
      if (text.includes(this.credential) && endpoint) {
        let origin = "an unparseable URL";
        try {
          origin = new URL(String(url)).origin;
        } catch {
          // counted as stray below
        }
        let expected: string | undefined;
        try {
          expected = new URL(endpoint).origin;
        } catch {
          expected = undefined;
        }
        if (origin !== expected) this.strayOrigins.add(origin);
      }
      if (mode === "down")
        throw new TypeError("fetch failed", {
          cause: { code: "ECONNREFUSED" },
        });
      if (mode === "quoting")
        throw new TypeError(
          `Invalid value "Bearer ${this.credential}" for header "authorization"`,
        );
      if (mode === "unauthorized")
        return new Response(
          JSON.stringify({ error: "unauthorized", token: this.credential }),
          {
            status: 401,
            headers: {
              "content-type": "application/json",
              "www-authenticate": `Bearer error="invalid_token", token="${this.credential}"`,
            },
          },
        );
      return base(url, init);
    };
  }

  context(): CustomBackendContext {
    const endpoint = this.options.context?.endpoint;
    return {
      distributionId: this.options.context?.distributionId ?? "conformance",
      fetch: this.#fetch(),
      ...(endpoint !== undefined ? { endpoint } : {}),
      credential: async () => this.credential,
    };
  }

  /** A fresh backend, built with the fetch mode given. */
  async backend(
    mode: "normal" | "down" | "quoting" | "unauthorized" = "normal",
  ): Promise<SandboxBackend> {
    this.#fetchMode = mode;
    let value: unknown;
    try {
      value =
        typeof this.adapter === "function"
          ? await this.adapter(this.context())
          : this.adapter;
    } catch (error) {
      throw new Finding(`the adapter factory failed (${this.describe(error)})`);
    } finally {
      this.#fetchMode = "normal";
    }
    const backend = value as Partial<SandboxBackend> | null;
    check(
      backend &&
        typeof backend === "object" &&
        typeof backend.available === "function" &&
        typeof backend.capabilities === "function" &&
        typeof backend.prepare === "function",
      "the adapter factory returned no sandbox backend",
    );
    return backend as SandboxBackend;
  }

  /** The declared capabilities, read once; a behavior needing them fails without them. */
  async capabilities(): Promise<SandboxCapabilities> {
    if (this.caps) return this.caps;
    const backend = await this.backend();
    let caps: SandboxCapabilities;
    try {
      caps = backend.capabilities();
    } catch (error) {
      throw new Finding(
        `capabilities() threw (${this.describe(error)}), so this check could not run`,
      );
    }
    check(
      caps && typeof caps === "object",
      "capabilities() returned nothing, so this check could not run",
    );
    this.caps = caps;
    return caps;
  }

  get local(): boolean {
    return this.caps?.isolation === "local";
  }

  /** Whether the host sees the sandbox's workspace writes at once. */
  get observable(): boolean {
    if (!this.caps) return false;
    return this.local || this.caps.workspace?.mode === "shared";
  }

  /** The network mode the kit uses when a check does not need one. */
  get network(): "deny" | "allow" {
    return this.caps?.network?.includes("deny") ? "deny" : "allow";
  }

  /** An available backend's prepared instance, tracked for disposal. */
  async prepare(
    network: "deny" | "allow" = this.network,
    backend?: SandboxBackend,
  ): Promise<SandboxInstance> {
    const source = backend ?? (await this.backend());
    const availability = await settle(() => source.available(), this.boundMs);
    check(
      availability.kind === "resolved" &&
        availability.value?.available === true,
      "the backend is not available in the kit's context, so this check could not run",
    );
    const prepared = await settle(
      () => source.prepare({ profile: this.profile(network) }),
      this.boundMs,
    );
    check(
      prepared.kind !== "hung",
      `prepare() did not end within ${this.boundMs} ms`,
    );
    if (prepared.kind === "rejected")
      throw new Finding(`prepare() failed (${this.describe(prepared.error)})`);
    const instance = prepared.value;
    check(
      instance &&
        typeof instance.exec === "function" &&
        typeof instance.dispose === "function",
      "prepare() returned no instance with exec() and dispose()",
    );
    this.#live.add(instance);
    return instance;
  }

  /** Dispose an instance once; returns how dispose ended. */
  async dispose(instance: SandboxInstance): Promise<Outcome<void>> {
    this.#live.delete(instance);
    this.#disposed.add(instance);
    return settle(() => instance.dispose(), this.boundMs);
  }

  disposed(instance: SandboxInstance): boolean {
    return this.#disposed.has(instance);
  }

  /** Dispose what a behavior left behind, ignoring failures. */
  async release(): Promise<void> {
    const left = [...this.#live];
    this.#live.clear();
    await Promise.all(
      left.map(async (instance) => {
        this.#disposed.add(instance);
        await settle(() => instance.dispose(), this.boundMs);
      }),
    );
  }

  /** The base environment of a request: a local command needs a PATH. */
  env(extra: Record<string, string> = {}): Record<string, string> {
    return { ...(this.local ? { PATH: LOCAL_PATH } : {}), ...extra };
  }

  start(
    instance: SandboxInstance,
    command: string,
    options: { path?: string; env?: Record<string, string> } = {},
  ): Execution {
    const path = options.path ?? ".";
    const controller = new AbortController();
    let stdout = "";
    let stderr = "";
    let firstOutput: number | undefined;
    const waiters: { text: string; resolve: () => void }[] = [];
    const wake = () => {
      for (const waiter of [...waiters])
        if (stdout.includes(waiter.text)) {
          waiters.splice(waiters.indexOf(waiter), 1);
          waiter.resolve();
        }
    };
    // Called synchronously, so an abort right after start() arrives while
    // the backend is still setting the command up.
    let pending: Promise<SandboxExecResult>;
    try {
      pending = Promise.resolve(
        instance.exec(
          {
            command,
            cwd:
              path === "."
                ? this.workspace
                : join(this.workspace, ...path.split("/")),
            workspacePath: path,
            env: this.env(options.env),
          },
          {
            signal: controller.signal,
            onStdout: (chunk: Buffer) => {
              firstOutput ??= Date.now();
              if (stdout.length < 65_536) stdout += chunk.toString("utf8");
              wake();
            },
            onStderr: (chunk: Buffer) => {
              if (stderr.length < 65_536) stderr += chunk.toString("utf8");
            },
          },
        ),
      );
    } catch (error) {
      pending = Promise.reject(error);
    }
    const settled = pending.then(
      (result: SandboxExecResult): Settled => ({
        kind: "exit",
        exitCode: result?.exitCode ?? null,
        signal: result?.signal ?? null,
      }),
      (error: unknown): Settled => ({ kind: "rejected", error }),
    );
    return {
      controller,
      stdout: () => stdout,
      stderr: () => stderr,
      settled,
      saw: (text) =>
        new Promise<void>((resolve) => {
          waiters.push({ text, resolve });
          wake();
        }),
      firstOutputAt: () => firstOutput,
    };
  }

  /** Run a command to its end, within `boundMs` (plus `extraMs`). */
  async exec(
    instance: SandboxInstance,
    command: string,
    what: string,
    options: {
      path?: string;
      env?: Record<string, string>;
      extraMs?: number;
    } = {},
  ): Promise<Ran> {
    const execution = this.start(instance, command, options);
    const outcome = await settle(
      () => execution.settled,
      this.boundMs + (options.extraMs ?? 0),
    );
    if (outcome.kind !== "resolved") {
      execution.controller.abort();
      throw new Finding(
        `${what}: the command did not end within the kit's bound`,
      );
    }
    return {
      settled: outcome.value,
      stdout: execution.stdout(),
      stderr: execution.stderr(),
    };
  }

  /** Run a command that must succeed; returns its stdout. */
  async ok(
    instance: SandboxInstance,
    command: string,
    what: string,
    options: {
      path?: string;
      env?: Record<string, string>;
      extraMs?: number;
    } = {},
  ): Promise<string> {
    const ran = await this.exec(instance, command, what, options);
    if (ran.settled.kind === "rejected")
      throw new Finding(
        `${what}: exec() rejected (${this.describe(ran.settled.error)})`,
      );
    check(
      ran.settled.exitCode === 0,
      `${what}: the command exited ${ran.settled.exitCode ?? "without a code"}`,
    );
    return ran.stdout;
  }

  /** Whether a workspace-relative marker exists, asked inside the sandbox or read on the host. */
  async marker(
    instance: SandboxInstance | undefined,
    relative: string,
  ): Promise<boolean | undefined> {
    if (instance && !this.disposed(instance)) {
      const out = await this.ok(
        instance,
        `if [ -f ${quote(relative)} ]; then echo marker-present; else echo marker-absent; fi`,
        "checking for the marker",
      );
      if (out.includes("marker-present")) return true;
      if (out.includes("marker-absent")) return false;
      throw new Finding("the marker check printed neither answer");
    }
    if (this.observable) return existsSync(join(this.workspace, relative));
    return undefined;
  }

  // ------------------------------------------------------------ workspace

  /** Run PiShip's two-way sentinel once in `instance`. */
  async sentinel(
    instance: SandboxInstance,
    decl: WorkspaceDeclaration,
  ): Promise<SentinelOutcome> {
    const windowMs =
      decl.mode === "synchronized"
        ? (decl.propagationMs ?? DEFAULT_PROPAGATION_MS)
        : this.sharedWindowMs;
    const base = decl.sentinelDir
      ? [
          ...decl.sentinelDir
            .split("/")
            .filter((part) => part !== "" && part !== "."),
          "piship-workspace",
        ]
      : [".git", "piship-workspace"];
    const nonce = randomBytes(16).toString("hex");
    const hostToken = randomBytes(16).toString("hex");
    const sandboxToken = randomBytes(16).toString("hex");
    const dir = join(this.workspace, ...base, nonce);
    const firstMissing = base.findIndex(
      (_, index) =>
        !existsSync(join(this.workspace, ...base.slice(0, index + 1))),
    );
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(dir, "h2s"), hostToken, { mode: 0o600, flag: "wx" });
    try {
      const ran = await this.exec(
        instance,
        sentinelScript(
          [...base, nonce].join("/"),
          hostToken,
          sandboxToken,
          Math.ceil(windowMs / POLL_MS),
        ),
        "the workspace check",
        { extraMs: windowMs },
      );
      const lines = ran.stdout.split(/\r?\n/).map((line) => line.trim());
      const exitCode =
        ran.settled.kind === "exit" ? ran.settled.exitCode : undefined;
      const completed = exitCode === 0 && lines.includes(`${WS} done`);
      const h2sLine = lines.find((line) => line.startsWith(`${WS} h2s `));
      const h2sValue = h2sLine?.slice(`${WS} h2s `.length);
      const hostToSandbox =
        h2sValue === undefined || !/^\d+$/.test(h2sValue)
          ? "missing"
          : h2sValue === "0"
            ? "immediate"
            : "delayed";
      let sandboxToHost: SentinelOutcome["sandboxToHost"] = "missing";
      if (lines.includes(`${WS} s2h written`)) {
        const target = join(dir, "s2h");
        const read = () => {
          try {
            return readFileSync(target, "utf8") === sandboxToken;
          } catch {
            return false;
          }
        };
        if (read()) sandboxToHost = "immediate";
        else {
          const deadline = Date.now() + windowMs;
          while (Date.now() < deadline) {
            await sleep(Math.min(POLL_MS, deadline - Date.now()));
            if (read()) {
              sandboxToHost = "delayed";
              break;
            }
          }
        }
      }
      return { completed, exitCode, hostToSandbox, sandboxToHost, windowMs };
    } finally {
      rmSync(dir, { recursive: true, force: true });
      if (firstMissing >= 0)
        rmSync(join(this.workspace, ...base.slice(0, firstMissing + 1)), {
          recursive: true,
          force: true,
        });
    }
  }

  // --------------------------------------------------------------- finish

  async close(): Promise<void> {
    await this.release();
    if (this.options.workspace)
      for (const entry of this.#created)
        rmSync(join(this.workspace, entry), { recursive: true, force: true });
    rmSync(this.root, { recursive: true, force: true });
  }
}

/** The shared or synchronized declaration a workspace check needs, or a skip reason. */
async function workspaceUnderTest(
  h: Harness,
): Promise<WorkspaceDeclaration | string> {
  const caps = await h.capabilities();
  if (caps.isolation === "local")
    return "skipped: a local backend runs commands on this host's files, so its workspace is shared by construction and needs no check";
  const decl = declaration(caps);
  if (!decl)
    return "skipped: the workspace declaration is malformed (see capabilities)";
  if (decl.mode === "snapshot")
    return "skipped: declares snapshot: the sandbox sees a copy of the workspace at best, which is never a complete coding-agent workspace";
  return decl;
}

// ---------------------------------------------------------------- checks

type Check = (h: Harness) => Promise<string | undefined>;

const checks: Record<SandboxBehavior, Check> = {
  async availability(h) {
    const backend = await h.backend();
    const normal = await settle(() => backend.available(), h.boundMs);
    check(
      normal.kind !== "hung",
      "available() did not end within the kit's bound",
    );
    if (normal.kind === "rejected")
      throw new Finding(
        `available() threw (${h.describe(normal.error)}) instead of resolving {available: false, reason}`,
      );
    const result = normal.value;
    check(
      result && (result.available === true || result.available === false),
      "available() resolved something other than {available: true} or {available: false, reason}",
    );
    if (!result.available)
      throw new Finding(
        `the backend reported itself unavailable in the kit's context (${h.scrub(redact(String(result.reason)).slice(0, 160))})`,
      );
    const down = await h.backend("down");
    const outage = await settle(() => down.available(), h.boundMs);
    check(
      outage.kind !== "hung",
      "with its service unreachable, available() did not end within the kit's bound",
    );
    check(
      outage.kind === "resolved",
      "with its service unreachable, available() threw instead of resolving {available: false, reason}",
    );
    const value = outage.value;
    check(
      value && (value.available === true || value.available === false),
      "with its service unreachable, available() resolved something other than {available: true} or {available: false, reason}",
    );
    if (!value.available)
      check(
        typeof value.reason === "string" && value.reason.trim().length > 0,
        "with its service unreachable, available() resolved {available: false} without a reason",
      );
    return undefined;
  },

  async capabilities(h) {
    const backend = await h.backend();
    let first: unknown;
    let second: unknown;
    try {
      first = backend.capabilities();
      second = backend.capabilities();
    } catch (error) {
      throw new Finding(`capabilities() threw (${h.describe(error)})`);
    }
    const problem = capabilityProblem(first);
    check(!problem, `the declaration is refused: ${problem}`);
    check(
      JSON.stringify(first) === JSON.stringify(second),
      "capabilities() returned a different declaration on a second call",
    );
    return undefined;
  },

  async prepare(h) {
    const caps = await h.capabilities();
    const backend = await h.backend();
    const first = await h.prepare(h.network, backend);
    if (caps.localProcesses)
      check(
        typeof first.wrap === "function",
        "the backend declares localProcesses, but its instance has no wrap()",
      );
    check(
      first.epoch === undefined || typeof first.epoch === "function",
      "the instance's epoch is not a function",
    );
    const second = await h.prepare(h.network, backend);
    const a = await h.ok(
      first,
      "printf conformance-a",
      "a command in the first instance",
    );
    const b = await h.ok(
      second,
      "printf conformance-b",
      "a command in the second instance",
    );
    check(
      a === "conformance-a" && b === "conformance-b",
      "a command's output did not come back from its own instance",
    );
    const disposed = await h.dispose(first);
    check(
      disposed.kind === "resolved",
      "dispose() of the first instance did not resolve",
    );
    const after = await h.exec(
      second,
      "printf conformance-still",
      "a command in the second instance after the first was disposed",
    );
    check(
      after.settled.kind === "exit" &&
        after.settled.exitCode === 0 &&
        after.stdout === "conformance-still",
      "disposing one instance stopped another: every prepare() must create its own sandbox",
    );
    return undefined;
  },

  async execute(h) {
    await h.capabilities();
    const instance = await h.prepare();
    const value = `conformance value with 'single' "double" $dollar \\backslash and ü ${h.run}`;
    const ran = await h.exec(
      instance,
      `printf '%s' "$${ENV.value}"; printf 'conformance-stderr' >&2; exit 7`,
      "a command that prints and exits 7",
      { env: { [ENV.value]: value } },
    );
    if (ran.settled.kind === "rejected")
      throw new Finding(
        `exec() rejected a command that ran (${h.describe(ran.settled.error)})`,
      );
    check(
      ran.settled.exitCode === 7,
      `a command that exits 7 was reported with exit ${ran.settled.exitCode ?? "none"}`,
    );
    check(
      ran.stdout === value,
      "stdout did not arrive on onStdout exactly as printed, with the environment value given",
    );
    check(
      ran.stderr === "conformance-stderr",
      "stderr did not arrive on onStderr exactly as printed",
    );
    const zero = await h.exec(instance, "true", "a command that succeeds");
    check(
      zero.settled.kind === "exit" && zero.settled.exitCode === 0,
      "a command that succeeds was not reported with exit 0",
    );
    const dir = `${h.scratch}/cwd/sub`;
    await h.ok(instance, `mkdir -p ${quote(dir)}`, "creating a directory");
    await h.ok(
      instance,
      "printf conformance-here > here",
      "writing at a workspace path",
      {
        path: dir,
      },
    );
    const read = await h.ok(
      instance,
      `cat ${quote(`${dir}/here`)}`,
      "reading what a command wrote at a workspace path",
    );
    check(
      read === "conformance-here",
      "a command did not run at the workspace path it was given",
    );
    return undefined;
  },

  async "environment filtering"(h) {
    await h.capabilities();
    const approved = `conformance-approved-${h.run}`;
    const unplant = plant({
      [ENV.hostToken]: h.hostToken,
      [ENV.hostOnly]: h.hostOnly,
      [ENV.approved]: h.hostApproved,
    });
    try {
      const instance = await h.prepare();
      const out = await h.ok(
        instance,
        [
          `for n in ${ENV.hostToken} ${ENV.hostOnly}; do eval "s=\\\${$n+set}"; if [ "$s" = set ]; then echo "piship-env present $n"; fi; done`,
          `printf 'piship-env approved %s\\n' "\${${ENV.approved}-}"`,
          "env",
        ].join("\n"),
        "a command that lists its environment",
        { env: { [ENV.approved]: approved } },
      );
      const present = out
        .split(/\r?\n/)
        .filter((line) => line.startsWith("piship-env present "))
        .map((line) => line.slice("piship-env present ".length));
      check(
        present.length === 0,
        `a variable from the launcher's environment that PiShip did not approve reached the command (${present.join(", ")})`,
      );
      check(
        !out.includes(h.hostToken) && !out.includes(h.hostOnly),
        "a value from the launcher's environment reached the command",
      );
      check(
        !out.includes(h.hostApproved),
        "an allowlisted variable had the launcher's value instead of the approved one",
      );
      check(
        out.includes(`piship-env approved ${approved}`),
        "an allowlisted variable did not arrive with its approved value",
      );
    } finally {
      unplant();
    }
    return undefined;
  },

  async "secret leakage"(h) {
    await h.capabilities();
    const logged: string[] = [];
    const unwatch = watchLogs(h.credential, () => logged.push("x"));
    try {
      const backend = await h.backend();
      let availability: unknown;
      try {
        availability = await backend.available();
      } catch (error) {
        availability = error;
      }
      check(
        !h.leaks(availability),
        "the credential appeared in available()'s result",
      );
      check(
        !h.leaks(backend.capabilities()),
        "the credential appeared in capabilities()",
      );
      const instance = await h.prepare(h.network, backend);
      const ran = await h.exec(
        instance,
        `env; echo piship-leak-probe; piship-conformance-missing-${h.run.slice(0, 8)}`,
        "a command that prints its environment and fails",
      );
      check(
        !h.leaks(ran.stdout) && !h.leaks(ran.stderr),
        "the credential reached a sandboxed command's environment or output",
      );
      if (ran.settled.kind === "rejected")
        check(
          !h.leaks(ran.settled.error),
          "the credential appeared in an error from exec()",
        );
      check(!h.leaks(instance.epoch?.()), "the credential appeared in epoch()");
      const disposed = await h.dispose(instance);
      if (disposed.kind === "rejected")
        check(
          !h.leaks(disposed.error),
          "the credential appeared in an error from dispose()",
        );
      for (const [mode, what] of [
        ["quoting", "a transport error that quotes the credential"],
        ["unauthorized", "a 401 whose body and header echo the credential"],
      ] as const) {
        const failing = await h.backend(mode);
        const available = await settle(() => failing.available(), h.boundMs);
        if (available.kind !== "hung")
          check(
            !h.leaks(
              available.kind === "resolved" ? available.value : available.error,
            ),
            `after ${what}: the credential appeared in available()'s result or error`,
          );
        const prepared = await settle(
          () => failing.prepare({ profile: h.profile(h.network) }),
          h.boundMs,
        );
        if (prepared.kind === "rejected")
          check(
            !h.leaks(prepared.error),
            `after ${what}: the credential appeared in the error from prepare()`,
          );
        if (prepared.kind === "resolved" && prepared.value) {
          const extra = prepared.value;
          await h.dispose(extra);
        }
      }
      check(
        logged.length === 0,
        "the credential appeared in a line the backend logged",
      );
      check(
        h.strayOrigins.size === 0,
        "the backend sent the credential to an origin other than its endpoint's",
      );
    } finally {
      unwatch();
    }
    return undefined;
  },

  async "filesystem claims"(h) {
    const caps = await h.capabilities();
    const planes = caps.planes as readonly string[];
    const outside =
      planes.includes(HOST_FILESYSTEM_ISOLATION) ||
      planes.includes("workspace-confinement");
    const readDeny = planes.includes("filesystem-read-deny");
    const writeAllow = planes.includes("filesystem-write-allowlist");
    const git = h.local && planes.includes("git-control-protection");
    if (!outside && !readDeny && !writeAllow && !git)
      return "skipped: the backend claims no filesystem guarantee";
    const instance = await h.prepare();
    const nonce = randomBytes(8).toString("hex");
    const written = join(h.hostDir, `written-${nonce}`);
    const inside = `${h.scratch}/inside-${nonce}`;
    const configBefore = sha256(join(h.workspace, ".git/config"));
    const ran = await h.exec(
      instance,
      [
        `cat ${quote(join(h.hostDir, "secret"))} 2>/dev/null; echo`,
        `printf x > ${quote(written)} 2>/dev/null`,
        `cat ${quote(`${h.scratch}/denied/secret`)} 2>/dev/null; echo`,
        `mkdir -p ${quote(h.scratch)} 2>/dev/null; if printf x > ${quote(inside)} 2>/dev/null && [ -f ${quote(inside)} ]; then echo piship-fs inside-written; fi`,
        `if ( : >> .git/config ) 2>/dev/null; then echo piship-fs git-file-writable; fi`,
        `if ( : > .git/hooks/.piship-probe-${nonce} ) 2>/dev/null; then echo piship-fs git-dir-writable; fi`,
        "echo piship-fs done",
      ].join("\n"),
      "a command that tries the filesystem claims",
    );
    const wroteHost = existsSync(written);
    rmSync(written, { force: true });
    rmSync(join(h.workspace, `.git/hooks/.piship-probe-${nonce}`), {
      force: true,
    });
    check(
      ran.stdout.includes("piship-fs done"),
      "the filesystem check command did not run to its end in the sandbox",
    );
    if (outside) {
      check(
        !ran.stdout.includes(h.fileSecret),
        "a command in the sandbox read a file on this host outside the workspace",
      );
      check(
        !wroteHost,
        "a command in the sandbox wrote a file on this host outside the workspace",
      );
    }
    if (readDeny)
      check(
        !ran.stdout.includes(h.deniedSecret),
        "a command in the sandbox read a path in the profile's readDeny",
      );
    if (writeAllow) {
      check(
        !wroteHost,
        "a command in the sandbox wrote outside the profile's writeAllow",
      );
      check(
        ran.stdout.includes("piship-fs inside-written"),
        "a command in the sandbox could not write in the workspace, which writeAllow permits",
      );
    }
    if (git) {
      check(
        !ran.stdout.includes("piship-fs git-file-writable") &&
          sha256(join(h.workspace, ".git/config")) === configBefore,
        "a protected git control file (.git/config) was writable from the sandbox",
      );
      check(
        !ran.stdout.includes("piship-fs git-dir-writable"),
        "a file could be created in a protected git directory (.git/hooks) from the sandbox",
      );
    }
    return undefined;
  },

  async "network claims"(h) {
    const caps = await h.capabilities();
    if (
      !(caps.planes as readonly string[]).includes("network-deny") ||
      !caps.network.includes("deny")
    )
      return "skipped: the backend does not claim network-deny";
    let hits = 0;
    const server = createServer((socket) => {
      hits++;
      socket.destroy();
    });
    // A remote backend's declared probe is what PiShip checks it with.
    const declared =
      h.options.networkTarget === undefined && caps.isolation === "remote"
        ? caps.networkProbe
        : undefined;
    const own = h.options.networkTarget === undefined && !declared;
    const target =
      h.options.networkTarget ??
      declared ??
      (await new Promise<{ host: string; port: number }>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
          const address = server.address();
          resolve({
            host: "127.0.0.1",
            port: typeof address === "object" && address ? address.port : 0,
          });
        });
      }));
    const what = own
      ? "the kit's loopback listener"
      : declared
        ? "the declared network probe"
        : "the network target";
    try {
      const attempt = async (network: "deny" | "allow") => {
        const instance = await h.prepare(network);
        const before = hits;
        const ran = await h.exec(
          instance,
          connectScript(target.host, target.port),
          `a connection attempt with the network ${network === "deny" ? "denied" : "allowed"}`,
        );
        await h.dispose(instance);
        const connected =
          hits > before || ran.stdout.includes("piship-net connected");
        const unchecked =
          !connected && !ran.stdout.includes("piship-net refused");
        return { connected, unchecked };
      };
      const denied = await attempt("deny");
      check(
        !denied.connected,
        `a command in the sandbox connected to ${what} although the profile denies the network`,
      );
      if (denied.unchecked)
        return "skipped: the sandbox has neither nc nor bash, so the kit cannot try a connection from inside it";
      if (!caps.network.includes("allow"))
        return "skipped: the backend enforces only network deny, so the kit cannot show that its connection attempt would succeed with the network allowed; a refused connection alone proves nothing";
      const allowed = await attempt("allow");
      check(
        allowed.connected || !declared,
        "the declared network probe is not reachable from the sandbox with the network allowed, so PiShip reports network denial attested, not verified",
      );
      if (!allowed.connected)
        return own
          ? "skipped: the kit's loopback listener is not reachable from the sandbox even with the network allowed (a remote sandbox has its own loopback); pass networkTarget, a listener the sandbox can reach, to check network denial"
          : "skipped: the network target is not reachable from the sandbox even with the network allowed, so a refused connection proves nothing";
    } finally {
      server.close();
    }
    return undefined;
  },

  async timeout(h) {
    await h.capabilities();
    const instance = await h.prepare();
    const marker = `${h.scratch}/timeout-${randomBytes(4).toString("hex")}`;
    await h.ok(
      instance,
      `mkdir -p ${quote(h.scratch)}`,
      "creating a directory",
    );
    const execution = h.start(
      instance,
      `echo started; ( sleep 1; printf late > ${quote(marker)} ) & wait`,
    );
    check(
      await whileRunning(execution),
      "the command ended before its timeout, so the kit could not time it out while it ran",
    );
    execution.controller.abort();
    const aborted = Date.now();
    const settled = await settle(() => execution.settled, h.settleMs);
    check(
      settled.kind === "resolved",
      `exec() did not settle within ${h.settleMs} ms after io.signal aborted for a timeout, so PiShip would retire the instance and end the session`,
    );
    await markerWindow(execution, aborted);
    const present = await h.marker(instance, marker);
    check(
      present === false,
      "the timed-out command kept running and wrote its marker after the timeout",
    );
    const next = await h.exec(
      instance,
      "printf conformance-next",
      "a command after the timeout",
    );
    check(
      next.settled.kind === "exit" &&
        next.settled.exitCode === 0 &&
        next.stdout === "conformance-next",
      "the instance did not run a command after a timeout",
    );
    return undefined;
  },

  async cancellation(h) {
    await h.capabilities();
    const instance = await h.prepare();
    await h.ok(
      instance,
      `mkdir -p ${quote(h.scratch)}`,
      "creating a directory",
    );
    let retired = false;
    const cancel = async (
      command: string,
      marker: string,
      when: "before it started" | "while it ran",
    ): Promise<string | undefined> => {
      const execution = h.start(instance, command);
      // Before it started: while the backend is still setting it up. While
      // it ran: before it printed anything (a timeout usually hits a command
      // that is streaming output; the timeout check covers that).
      if (when === "while it ran") await sleep(RUNNING_MS);
      execution.controller.abort();
      const aborted = Date.now();
      const settled = await settle(() => execution.settled, h.settleMs);
      if (settled.kind !== "resolved") {
        // PiShip retires a backend that did not stop the command.
        retired = true;
        const disposed = await h.dispose(instance);
        check(
          disposed.kind === "resolved",
          `a command cancelled ${when} did not stop, and dispose() did not resolve either`,
        );
        const after = await settle(() => execution.settled, h.settleMs);
        check(
          after.kind === "resolved",
          `a command cancelled ${when} did not stop, and exec() did not settle even after dispose()`,
        );
      }
      // A command aborted before it started prints nothing if the backend
      // honored the abort; one that ignored it may start later than the
      // marker window, so a silent command is watched LATE_MS longer.
      await markerWindow(
        execution,
        aborted,
        when === "before it started" ? LATE_MS : 0,
      );
      const present = await h.marker(retired ? undefined : instance, marker);
      if (present === undefined)
        return `skipped: the backend did not stop a command cancelled ${when}, so the kit retired the instance, and it cannot see inside a disposed sandbox whether dispose() stopped it`;
      check(
        !present,
        `a command cancelled ${when} ran on and wrote its marker${retired ? ", also after dispose()" : ""}`,
      );
      return undefined;
    };
    const early = `${h.scratch}/cancel-early-${randomBytes(4).toString("hex")}`;
    // The first command prints a line as it starts, which tells the kit when
    // a backend that starts it late did; it is cancelled before that line.
    const skip = await cancel(
      `echo started; sleep 1; printf late > ${quote(early)}`,
      early,
      "before it started",
    );
    if (skip) return skip;
    if (retired) return undefined;
    const running = `${h.scratch}/cancel-running-${randomBytes(4).toString("hex")}`;
    const skipped = await cancel(
      `sleep 1; printf late > ${quote(running)}`,
      running,
      "while it ran",
    );
    if (skipped) return skipped;
    if (retired) return undefined;
    const next = await h.exec(
      instance,
      "printf conformance-next",
      "a command after a cancellation",
    );
    check(
      next.settled.kind === "exit" &&
        next.settled.exitCode === 0 &&
        next.stdout === "conformance-next",
      "the instance did not run a command after a cancellation",
    );
    return undefined;
  },

  async cleanup(h) {
    await h.capabilities();
    const count = h.options.sandboxes;
    if (!count)
      return "skipped: pass sandboxes(), a count of the sandboxes the backend's service holds, to let the kit see what prepare() created and dispose() removed";
    const measure = async (when: string) => {
      const value = await settle(() => count(), h.boundMs);
      check(
        value.kind === "resolved" && Number.isInteger(value.value),
        `sandboxes() did not return a count ${when}`,
      );
      return value.value;
    };
    const before = await measure("before prepare()");
    const instance = await h.prepare();
    await h.ok(instance, "true", "a command before dispose()");
    const disposed = await h.dispose(instance);
    check(disposed.kind === "resolved", "dispose() did not resolve");
    const after = await measure("after dispose()");
    check(
      after <= before,
      `after dispose() the backend still holds ${after - before} sandbox${after - before === 1 ? "" : "es"} more than before prepare()`,
    );
    return undefined;
  },

  async dispose(h) {
    await h.capabilities();
    const instance = await h.prepare();
    await h.ok(
      instance,
      `mkdir -p ${quote(h.scratch)}`,
      "creating a directory",
    );
    const marker = `${h.scratch}/dispose-${randomBytes(4).toString("hex")}`;
    const ranAfter = `${h.scratch}/after-dispose-${randomBytes(4).toString("hex")}`;
    const execution = h.start(
      instance,
      `echo started; sleep 1; printf late > ${quote(marker)}`,
    );
    check(
      await whileRunning(execution),
      "the command ended before dispose(), so the kit could not dispose while it ran",
    );
    const disposing = Date.now();
    const first = await h.dispose(instance);
    check(
      first.kind !== "hung",
      "dispose() did not end within the kit's bound",
    );
    check(
      first.kind === "resolved",
      `dispose() threw (${first.kind === "rejected" ? h.describe(first.error) : ""}); it must never throw`,
    );
    const settled = await settle(() => execution.settled, h.settleMs);
    check(
      settled.kind === "resolved",
      `a command still running did not end within ${h.settleMs} ms after dispose()`,
    );
    const second = await settle(() => instance.dispose(), h.boundMs);
    check(
      second.kind === "resolved",
      "a second dispose() did not resolve; dispose() must be safe to call again",
    );
    const after = h.start(instance, `printf ran > ${quote(ranAfter)}`);
    const late = await settle(() => after.settled, h.boundMs);
    check(
      !(
        late.kind === "resolved" &&
        late.value.kind === "exit" &&
        late.value.exitCode === 0
      ),
      "exec() after dispose() reported a command as run",
    );
    if (h.observable) {
      await markerWindow(execution, disposing);
      check(
        !existsSync(join(h.workspace, marker)),
        "a command that was running at dispose() kept running and wrote its marker",
      );
      check(
        !existsSync(join(h.workspace, ranAfter)),
        "exec() after dispose() still ran the command",
      );
    }
    return undefined;
  },

  async "fail-closed behavior"(h) {
    await h.capabilities();
    const instance = await h.prepare();
    const missing = await h.exec(
      instance,
      `piship-conformance-no-such-command-${h.run.slice(0, 8)}`,
      "a command that cannot run",
    );
    check(
      !(missing.settled.kind === "exit" && missing.settled.exitCode === 0),
      "a command that cannot run inside the sandbox was reported with exit 0",
    );
    const nonce = randomBytes(8).toString("hex");
    const ran = await h.exec(
      instance,
      `printf '%s %s\\n' ${READY} "\${${UNLISTED}:-unset}"`,
      "PiShip's sandbox check",
      { env: { [UNLISTED]: nonce } },
    );
    const line = ran.stdout
      .split(/\r?\n/)
      .find((item) => item.startsWith(`${READY} `));
    check(
      line === `${READY} ${nonce}`,
      line
        ? "the backend answered PiShip's sandbox check itself instead of running it, so a check could pass for guarantees nobody verified"
        : "PiShip's sandbox check did not report back",
    );
    return undefined;
  },

  async "workspace consistency"(h) {
    const decl = await workspaceUnderTest(h);
    if (typeof decl === "string") return decl;
    const instance = await h.prepare();
    const outcome = await h.sentinel(instance, decl);
    const problem = sentinelProblem(
      outcome,
      decl.mode as "shared" | "synchronized",
    );
    check(!problem, problem ?? "");
    return undefined;
  },

  async "git control protection"(h) {
    const decl = await workspaceUnderTest(h);
    if (typeof decl === "string") return decl;
    const instance = await h.prepare();
    const nonce = randomBytes(16).toString("hex");
    const config = join(h.workspace, ".git/config");
    const before = {
      config: sha256(config),
      hooks: listing(join(h.workspace, ".git/hooks")),
      info: listing(join(h.workspace, ".git/info")),
    };
    const ran = await h.exec(
      instance,
      gitProbeScript(nonce),
      "the git control check",
    );
    const probes = PROTECTED_DIRECTORIES.map((dir) =>
      join(h.workspace, dir, `.piship-probe-${nonce}`),
    );
    const left = probes.filter((path) => {
      try {
        return lstatSync(path) !== undefined;
      } catch {
        return false;
      }
    });
    for (const path of probes) rmSync(path, { force: true });
    const lines = ran.stdout.split(/\r?\n/).map((line) => line.trim());
    const exitCode =
      ran.settled.kind === "exit" ? ran.settled.exitCode : undefined;
    check(
      exitCode === 0 && lines.includes(`${WS} done`),
      `the git control check did not complete in the sandbox (exit ${exitCode ?? "none"}), which PiShip treats as unsafe and fails closed`,
    );
    const file = lines.find((line) => line.startsWith(`${WS} writable file `));
    check(
      !file,
      `a protected git control file (${PROTECTED_FILES[Number(file?.split(" ").at(-1))] ?? "?"}) was writable from the sandbox`,
    );
    const dir = lines.find((line) => line.startsWith(`${WS} writable dir `));
    check(
      !dir,
      `a file could be created in a protected git directory (${PROTECTED_DIRECTORIES[Number(dir?.split(" ").at(-1))] ?? "?"}) from the sandbox`,
    );
    check(
      left.length === 0,
      "a probe file appeared in a protected git directory on the host",
    );
    check(
      sha256(config) === before.config &&
        listing(join(h.workspace, ".git/hooks")) === before.hooks &&
        listing(join(h.workspace, ".git/info")) === before.info,
      "the git control check changed a protected path on the host",
    );
    return undefined;
  },

  async "workspace re-check"(h) {
    const decl = await workspaceUnderTest(h);
    if (typeof decl === "string") return decl;
    const mode = decl.mode as "shared" | "synchronized";
    const instance = await h.prepare();
    // PiShip's clock, advanced by the kit instead of waited for.
    let clock = 0;
    let checkedAt: number | undefined;
    let checkedEpoch: string | undefined;
    const readEpoch = (): string | undefined => {
      if (typeof instance.epoch !== "function") return undefined;
      let value: unknown;
      try {
        value = instance.epoch();
      } catch (error) {
        throw new Finding(`epoch() threw (${h.describe(error)})`);
      }
      check(
        value === undefined || (typeof value === "string" && value.length > 0),
        "epoch() returned something other than a non-empty string or undefined",
      );
      check(!h.leaks(value), "epoch() returned the credential");
      return value as string | undefined;
    };
    let checks = 0;
    const count = () => checks;
    const command = async (what: string) => {
      const due =
        checkedAt === undefined ||
        clock - checkedAt >= VALIDITY_MS ||
        readEpoch() !== checkedEpoch;
      if (due) {
        checks++;
        const outcome = await h.sentinel(instance, decl);
        const problem = sentinelProblem(outcome, mode);
        if (problem)
          return checks === 1
            ? "skipped: the first workspace check did not pass (see workspace consistency)"
            : `${what}: ${problem}`;
        checkedAt = clock;
        checkedEpoch = readEpoch();
      }
      await h.ok(instance, "true", what);
      return undefined;
    };
    const first = await command("the first command");
    if (first) return first;
    clock += 60_000;
    const epochBefore = readEpoch();
    check(
      !(await command("a command inside the validity window")),
      "the workspace was checked again inside the validity window",
    );
    check(
      count() === 1,
      "the workspace was checked again inside the validity window",
    );
    check(
      readEpoch() === epochBefore,
      "epoch() changed although the environment did not",
    );
    clock += VALIDITY_MS;
    const again = await command(
      "the workspace check repeated after the validity window",
    );
    check(!again, again ?? "");
    check(
      count() === 2,
      "the workspace was not checked again after the validity window",
    );
    const replace = h.options.replaceEnvironment;
    if (replace) {
      check(
        typeof instance.epoch === "function",
        "the environment can be replaced, but the instance has no epoch(), so PiShip would never check the new environment",
      );
      const old = readEpoch();
      const replaced = await settle(() => replace(instance), h.boundMs);
      check(
        replaced.kind === "resolved",
        "replaceEnvironment() did not complete, so the epoch check could not run",
      );
      check(
        readEpoch() !== old,
        "epoch() did not change after the environment was replaced, so PiShip would not check the new environment",
      );
      const renewed = await command(
        "the workspace check after epoch() changed",
      );
      check(!renewed, renewed ?? "");
      check(
        count() === 3,
        "the workspace was not checked again after epoch() changed",
      );
    }
    return undefined;
  },
};

/**
 * Run a sandbox backend through `SANDBOX_CONTRACT` and report each behavior
 * as passed, failed, or skipped, with a reason for anything but passed.
 * `adapter` is the adapter module's default export, as
 * `defineSandboxAdapter` returns it (the kit calls it for every check with a
 * context it controls), or a backend object. Commands run through the
 * backend with POSIX `sh` syntax and need `cat`, `mkdir`, `mv`, `printf`,
 * `sleep`, and `env` in the sandbox, plus `nc` or `bash` for the network
 * check.
 */
export async function testSandboxAdapter(
  adapter: SandboxAdapterUnderTest,
  options: SandboxKitOptions = {},
): Promise<ConformanceReport> {
  for (const behavior of options.only ?? [])
    if (!SANDBOX_BEHAVIORS.includes(behavior))
      throw new RangeError(`only names an unknown behavior: ${behavior}`);
  for (const [name, value] of [
    ["settleMs", options.settleMs],
    ["callTimeoutMs", options.callTimeoutMs],
    ["sharedWindowMs", options.sharedWindowMs],
  ] as const)
    if (value !== undefined && !(Number.isFinite(value) && value > 0))
      throw new RangeError(`${name} must be a positive number`);
  const harness = new Harness(adapter, options);
  const results: ConformanceResult[] = [];
  try {
    for (const behavior of SANDBOX_BEHAVIORS) {
      if (options.only && !options.only.includes(behavior)) {
        results.push({
          behavior,
          status: "skipped",
          reason: "not selected by the only option",
        });
        continue;
      }
      try {
        const outcome = await checks[behavior](harness);
        results.push(
          outcome?.startsWith("skipped: ")
            ? {
                behavior,
                status: "skipped",
                reason: harness.scrub(outcome.slice("skipped: ".length)),
              }
            : { behavior, status: "passed" },
        );
      } catch (error) {
        results.push({
          behavior,
          status: "failed",
          reason: harness.scrub(
            error instanceof Finding
              ? error.message
              : `the check ended unexpectedly (${harness.describe(error)})`,
          ),
        });
      } finally {
        await harness.release();
      }
    }
  } finally {
    await harness.close();
  }
  return { kind: "sandbox", results };
}
