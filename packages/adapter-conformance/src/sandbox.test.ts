import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import {
  type CustomBackendContext,
  defineSandboxAdapter,
  HOST_FILESYSTEM_ISOLATION,
  type ManagedFetch,
  type SandboxCapabilities,
  type SandboxExecIO,
  type SandboxExecRequest,
  type SandboxExecResult,
  type SandboxInstance,
  type SandboxProfile,
} from "@piship/adapter-sdk";
import { describe, expect, it } from "vitest";
import {
  describeIsolated,
  findBwrap,
} from "../../../tests/adapter-kits/isolator-gate.js";
import {
  type ConformanceReport,
  SANDBOX_BEHAVIORS,
  SANDBOX_CONTRACT,
  type SandboxBehavior,
  type SandboxKitOptions,
  testSandboxAdapter,
} from "./index.js";

// ------------------------------------------------------------ the isolator
//
// The reference backends run every command for real, in `/bin/sh`, inside an
// OS mechanism that makes each claim true: Seatbelt on macOS (deny by
// default, then the sandbox's own directories), bubblewrap on Linux (only
// the system directories and the sandbox's own directories mounted). Where
// neither works (Windows, a Linux host without unprivileged user
// namespaces) the kit's tests are skipped with a printed reason, or fail
// under PISHIP_REQUIRE_ISOLATOR=1 (tests/adapter-kits/isolator-gate.ts).

const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";

interface Isolation {
  /** Directories the sandbox reads and writes: its own root, or the mounted workspace. */
  readonly visible: readonly string[];
  readonly readDeny: readonly string[];
  readonly protect: {
    readonly files: string[];
    readonly directories: string[];
  };
  readonly network: "deny" | "allow";
  /** Seeded defect: this host's temporary directory is readable too. */
  readonly exposeHostTmp?: boolean;
}

const sbpl = (path: string) => `"${path.replace(/[\\"]/g, "\\$&")}"`;

function seatbelt(spec: Isolation): string {
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-exec process-fork signal sysctl-read mach-lookup ipc-posix-shm file-read-metadata)",
    // The sandbox's own system: the OS directories every machine has.
    '(allow file-read* (literal "/") (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/System") (subpath "/Library") (subpath "/private/var/db") (subpath "/dev"))',
    '(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/tty") (literal "/dev/stdout") (literal "/dev/stderr") (regex #"^/dev/fd/[0-9]+$"))',
    `(allow file-read* file-write* ${spec.visible.map((path) => `(subpath ${sbpl(path)})`).join(" ")})`,
  ];
  if (spec.exposeHostTmp)
    lines.push(`(allow file-read* (subpath ${sbpl(realpathSync(tmpdir()))}))`);
  const protect = [
    ...spec.protect.files.map((path) => `(literal ${sbpl(path)})`),
    ...spec.protect.directories.map((path) => `(subpath ${sbpl(path)})`),
  ];
  if (protect.length) lines.push(`(deny file-write* ${protect.join(" ")})`);
  if (spec.readDeny.length)
    lines.push(
      `(deny file-read* file-write* ${spec.readDeny.map((path) => `(subpath ${sbpl(path)})`).join(" ")})`,
    );
  if (spec.network === "allow") lines.push("(allow network*)");
  return `${lines.join("\n")}\n`;
}

function bubblewrap(spec: Isolation, cwd: string): string[] {
  const args = ["--die-with-parent", "--unshare-all"];
  if (spec.network === "allow") args.push("--share-net");
  args.push("--ro-bind", "/usr", "/usr");
  for (const dir of ["/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"]) {
    let stat: ReturnType<typeof lstatSync> | undefined;
    try {
      stat = lstatSync(dir);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) args.push("--symlink", readlinkSync(dir), dir);
    else args.push("--ro-bind", dir, dir);
  }
  args.push(
    "--ro-bind-try",
    "/etc/ld.so.cache",
    "/etc/ld.so.cache",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
  );
  if (spec.exposeHostTmp) {
    const host = realpathSync(tmpdir());
    args.push("--ro-bind", host, host);
  }
  for (const path of spec.visible) args.push("--bind", path, path);
  for (const path of [...spec.protect.files, ...spec.protect.directories])
    if (existsSync(path)) args.push("--ro-bind", path, path);
  for (const path of spec.readDeny)
    if (existsSync(path)) args.push("--tmpfs", path, "--remount-ro", path);
  args.push("--chdir", cwd);
  return args;
}

function command(
  spec: Isolation,
  cwd: string,
  line: string,
): { file: string; args: string[] } {
  if (isolator === "seatbelt")
    return {
      file: SANDBOX_EXEC,
      args: ["-p", seatbelt(spec), "/bin/sh", "-c", line],
    };
  return {
    file: bwrap as string,
    args: [...bubblewrap(spec, cwd), "/bin/sh", "-c", line],
  };
}

const bwrap = process.platform === "linux" ? findBwrap() : undefined;
const isolator: "seatbelt" | "bubblewrap" | undefined = (() => {
  if (process.platform === "darwin" && existsSync(SANDBOX_EXEC)) {
    const probe = spawnSync(
      SANDBOX_EXEC,
      [
        "-p",
        seatbelt({
          visible: [realpathSync(tmpdir())],
          readDeny: [],
          protect: { files: [], directories: [] },
          network: "deny",
        }),
        "/bin/sh",
        "-c",
        "exit 0",
      ],
      { timeout: 10_000 },
    );
    return probe.status === 0 ? "seatbelt" : undefined;
  }
  if (bwrap) {
    const dir = realpathSync(tmpdir());
    const probe = spawnSync(
      bwrap,
      [
        ...bubblewrap(
          {
            visible: [dir],
            readDeny: [],
            protect: { files: [], directories: [] },
            network: "deny",
          },
          dir,
        ),
        "/bin/sh",
        "-c",
        "exit 0",
      ],
      { timeout: 10_000 },
    );
    return probe.status === 0 ? "bubblewrap" : undefined;
  }
  return undefined;
})();

// --------------------------------------------------------- control service

/**
 * The reference backend's control plane, reached through the context's
 * managed fetch: a health check, and a session per sandbox. It counts the
 * sessions it holds, which the kit's `sandboxes` hook reads.
 */
class ControlService {
  readonly sessions = new Set<string>();
  #next = 0;

  readonly fetch: ManagedFetch = async (url, init) => {
    const target = new URL(String(url));
    const method = (init?.method ?? "GET").toUpperCase();
    const auth = new Headers(init?.headers).get("authorization") ?? "";
    if (init?.signal?.aborted) throw init.signal.reason;
    if (!auth.startsWith("Bearer ")) return new Response(null, { status: 401 });
    if (method === "GET" && target.pathname === "/health")
      return new Response(null, { status: 204 });
    if (method === "POST" && target.pathname === "/sessions") {
      const id = `session-${++this.#next}-${randomBytes(6).toString("hex")}`;
      this.sessions.add(id);
      return Response.json({ id }, { status: 201 });
    }
    const match = /^\/sessions\/([\w-]+)$/.exec(target.pathname);
    if (method === "DELETE" && match?.[1]) {
      this.sessions.delete(match[1]);
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 404 });
  };
}

const ENDPOINT = "https://sandbox.conformance.invalid";

// ------------------------------------------------------ reference backends

type Variant = "local" | "snapshot" | "shared" | "synchronized";

/** One seeded defect; the reference backend has none. */
type Fault =
  | "available() throws when its service is down"
  | "claims host-filesystem-isolation with a shared workspace"
  | "prepare() returns one shared instance"
  | "sends stderr to onStdout"
  | "passes the launcher's environment through"
  | "keeps the transport error that quotes the credential"
  | "logs the credential"
  | "claims host-filesystem-isolation but exposes a host path"
  | "claims network denial but connects"
  | "ignores a timeout once the command streams output"
  | "ignores cancellation"
  | "starts a timed-out command late and leaves it running"
  | "starts a cancelled command late and leaves it running"
  | "starts a cancelled command after the kit's window and leaves it running"
  | "starts a command late and ignores dispose()"
  | "dispose leaves the sandbox running"
  | "dispose throws the second time"
  | "answers PiShip's check command itself"
  | "the sandbox-to-host direction fails"
  | "claims shared but is a snapshot"
  | "declares shared but propagates with a delay"
  | "lets the workspace write .git/hooks"
  | "epoch() does not change when the environment is replaced"
  | "loses the workspace mount when the environment is replaced";

interface ReferenceOptions {
  readonly variant: Variant;
  readonly fault?: Fault;
  readonly networkModes?: readonly ("deny" | "allow")[];
  /** Deliver a command's output only when it ends, as a batch API does. */
  readonly buffered?: boolean;
  /**
   * Start each command that writes a marker only after `LATE_START_MS`, as a
   * service under load does. A sound backend gives up on the command when it
   * is aborted or its sandbox disposed, so the kit passes it.
   */
  readonly slowStart?: boolean;
}

/** How long a service under load takes to start a command, for `slowStart`. */
const LATE_START_MS = 1_700;

/**
 * The seeded slow starts. Each names the marker file its behavior's command
 * writes (the kit puts the name in the command's text) and how long the
 * defective service takes to start that command. The marker then appears
 * after a kit that counts from its own request has looked, and the command's
 * first line reaches the kit before a kit that counts from that line looks.
 * The kit's command that only looks for the marker is not slowed.
 */
const LATE_FAULTS: Partial<
  Record<Fault, { readonly marker: string; readonly delayMs: number }>
> = {
  "starts a timed-out command late and leaves it running": {
    marker: "timeout",
    delayMs: 1_700,
  },
  "starts a cancelled command late and leaves it running": {
    marker: "cancel-early",
    delayMs: 1_000,
  },
  // Its first line comes after the marker window that counts from the abort
  // (1.8 s) and before the one a silent command gets (2.8 s), so only a kit
  // that watches a silent command longer sees it. 2.3 s is the middle: half a
  // second of margin to either side for a loaded machine.
  "starts a cancelled command after the kit's window and leaves it running": {
    marker: "cancel-early",
    delayMs: 2_300,
  },
  "starts a command late and ignores dispose()": {
    marker: "dispose",
    delayMs: 1_700,
  },
};

/** Whether `command` writes a marker (as opposed to looking for one). */
const writesMarker = (command: string, prefix = "") =>
  new RegExp(`printf late > '[^']*/${prefix}`).test(command);

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

interface Session {
  readonly id: string;
  generation: number;
  /** Where commands run: the workspace itself, or the sandbox's own copy. */
  work: string;
  /** The sandbox's own root, removed at dispose. */
  root: string | undefined;
  readonly profile: SandboxProfile;
  readonly children: Set<ChildProcess>;
  stop: (() => void) | undefined;
  disposed: boolean;
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
    let stat: ReturnType<typeof lstatSync>;
    try {
      stat = lstatSync(join(root, rel));
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) output.push(...files(root, rel));
    else if (stat.isFile()) output.push(rel);
  }
  return output;
}

/** A one-way copier: new files appear on the other side after `delayMs`. */
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
        // gone mid-copy; the next tick decides again
      }
      seen.delete(rel);
    }
  };
}

/** Registry for the replaceEnvironment hook: epoch id to session. */
const sessionsById = new Map<string, Session>();

/**
 * A reference sandbox adapter written the way a company would: SDK only,
 * one control-service session per sandbox, every command run for real in an
 * isolator that makes each claim true. Each `fault` breaks one behavior.
 */
function referenceAdapter(options: ReferenceOptions) {
  const { variant, fault } = options;
  const behaves: Variant =
    fault === "claims shared but is a snapshot"
      ? "snapshot"
      : fault === "declares shared but propagates with a delay"
        ? "synchronized"
        : variant;
  const delayMs =
    fault === "declares shared but propagates with a delay" ? 300 : 100;
  const remote = variant !== "local";
  let singleton: Session | undefined;

  const capabilities = (): SandboxCapabilities => {
    const network = options.networkModes ?? ["deny", "allow"];
    const base = { network, localProcesses: false };
    const deny = network.includes("deny") ? (["network-deny"] as const) : [];
    if (variant === "local")
      return {
        ...base,
        isolation: "local",
        planes: [
          "filesystem-read-deny",
          "filesystem-write-allowlist",
          ...deny,
          "environment-filter",
          "git-control-protection",
        ],
      };
    if (variant === "snapshot")
      return {
        ...base,
        isolation: "remote",
        planes: [HOST_FILESYSTEM_ISOLATION, ...deny, "environment-filter"],
        workspace: { mode: "snapshot" },
      };
    return {
      ...base,
      isolation: "remote",
      planes: [
        "workspace-confinement",
        "git-control-protection",
        ...deny,
        "environment-filter",
        ...(fault === "claims host-filesystem-isolation with a shared workspace"
          ? ([HOST_FILESYSTEM_ISOLATION] as const)
          : []),
      ],
      workspace:
        variant === "shared"
          ? { mode: "shared" }
          : { mode: "synchronized", propagationMs: 1500 },
    };
  };

  /** The sandbox's own copy of the workspace (snapshot and synchronized). */
  const copy = (profile: SandboxProfile) => {
    const root = realpathSync(
      mkdtempSync(join(tmpdir(), "reference-sandbox-")),
    );
    const work = join(root, "work");
    cpSync(profile.workspace, work, { recursive: true });
    return { root, work };
  };

  const isolation = (session: Session): Isolation => {
    const map = (path: string) =>
      join(session.work, relative(session.profile.workspace, path));
    const protect = {
      files: session.profile.writeProtect.files.map(map),
      directories:
        fault === "lets the workspace write .git/hooks"
          ? []
          : session.profile.writeProtect.directories.map(map),
    };
    return {
      visible:
        variant === "local" ? session.profile.writeAllow : [session.work],
      readDeny: variant === "local" ? session.profile.readDeny : [],
      protect,
      network:
        fault === "claims network denial but connects"
          ? "allow"
          : session.profile.network,
      ...(fault === "claims host-filesystem-isolation but exposes a host path"
        ? { exposeHostTmp: true }
        : {}),
    };
  };

  return defineSandboxAdapter((context: CustomBackendContext) => {
    const call = async (method: string, path: string, signal?: AbortSignal) => {
      const token = await context.credential?.();
      return context.fetch(new URL(path, `${context.endpoint}/`), {
        method,
        headers: token ? { authorization: `Bearer ${token}` } : {},
        ...(signal ? { signal } : {}),
      });
    };

    /** Wait for a slow start, and give up when aborted or disposed. */
    const startLate = async (
      session: Session,
      io: SandboxExecIO,
      delayMs: number,
    ): Promise<void> => {
      const end = Date.now() + delayMs;
      while (Date.now() < end && !io.signal.aborted && !session.disposed)
        await sleep(25);
    };

    /**
     * A defective service: it starts the command `delayMs` after the request
     * whatever happens meanwhile, settles the call as soon as its signal
     * aborts or its sandbox is disposed, and never stops the command.
     */
    const leaveRunning = (
      session: Session,
      request: SandboxExecRequest,
      io: SandboxExecIO,
      delayMs: number,
    ): Promise<SandboxExecResult> => {
      let watch: ReturnType<typeof setInterval> | undefined;
      const stopped = new Promise<SandboxExecResult>((resolve) => {
        const stop = () => resolve({ exitCode: null });
        io.signal.addEventListener("abort", stop, { once: true });
        if (io.signal.aborted) stop();
        watch = setInterval(() => {
          if (session.disposed) stop();
        }, 25);
      });
      // The command runs on with a signal nothing aborts.
      const ran = sleep(delayMs).then(() =>
        spawnCommand(session, request, {
          ...io,
          signal: new AbortController().signal,
        }),
      );
      ran.catch(() => undefined);
      const finished = Promise.race([ran, stopped]);
      const release = () => clearInterval(watch);
      finished.then(release, release);
      return finished;
    };

    const exec = async (
      session: Session,
      request: SandboxExecRequest,
      io: SandboxExecIO,
    ): Promise<SandboxExecResult> => {
      if (session.disposed) throw new Error("the sandbox session is closed");
      // A round trip to the service before the command starts.
      await new Promise((resolve) => setImmediate(resolve));
      const late = fault ? LATE_FAULTS[fault] : undefined;
      if (late && writesMarker(request.command, `${late.marker}-`))
        return leaveRunning(session, request, io, late.delayMs);
      if (options.slowStart && writesMarker(request.command))
        await startLate(session, io, LATE_START_MS);
      if (fault !== "ignores cancellation" && io.signal.aborted)
        return { exitCode: null };
      if (session.disposed) throw new Error("the sandbox session is closed");
      return spawnCommand(session, request, io);
    };

    /** Run the command in the isolator; settle with how it ended. */
    const spawnCommand = async (
      session: Session,
      request: SandboxExecRequest,
      io: SandboxExecIO,
    ): Promise<SandboxExecResult> => {
      if (
        fault === "answers PiShip's check command itself" &&
        request.command.includes("piship-sandbox-ready")
      ) {
        io.onStdout(Buffer.from("piship-sandbox-ready unset\n"));
        return { exitCode: 0 };
      }
      const cwd =
        request.workspacePath && request.workspacePath !== "."
          ? join(session.work, ...request.workspacePath.split("/"))
          : session.work;
      const env =
        fault === "passes the launcher's environment through"
          ? { ...process.env, ...request.env, PATH: SYSTEM_PATH }
          : remote
            ? { ...request.env, PATH: SYSTEM_PATH }
            : { PATH: SYSTEM_PATH, ...request.env };
      const run = command(isolation(session), cwd, request.command);
      return new Promise((resolve, reject) => {
        const child = spawn(run.file, run.args, {
          cwd,
          env: env as NodeJS.ProcessEnv,
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
        });
        session.children.add(child);
        const kill = () => {
          try {
            if (child.pid) process.kill(-child.pid, "SIGKILL");
          } catch {
            // already gone
          }
        };
        let streaming = false;
        const onAbort = () => {
          // Seeded defect: the abort reaches only the start of the stream.
          if (
            fault === "ignores a timeout once the command streams output" &&
            streaming
          )
            return;
          kill();
        };
        io.signal.addEventListener("abort", onAbort, { once: true });
        const held: [(chunk: Buffer) => void, Buffer][] = [];
        const deliver =
          (to: (chunk: Buffer) => void) =>
          (chunk: Buffer): void => {
            if (options.buffered) held.push([to, chunk]);
            else to(chunk);
          };
        child.stdout?.on("data", (chunk: Buffer) => {
          streaming = true;
          deliver(io.onStdout)(chunk);
        });
        child.stderr?.on(
          "data",
          deliver(
            fault === "sends stderr to onStdout" ? io.onStdout : io.onStderr,
          ),
        );
        child.once("error", reject);
        child.once("close", (code, signal) => {
          for (const [to, chunk] of held) to(chunk);
          session.children.delete(child);
          io.signal.removeEventListener("abort", onAbort);
          resolve({ exitCode: code, signal });
        });
      });
    };

    const instance = (session: Session): SandboxInstance => ({
      exec: (request, io) => exec(session, request, io),
      ...(remote && variant !== "snapshot"
        ? {
            epoch: () =>
              fault ===
              "epoch() does not change when the environment is replaced"
                ? session.id
                : `${session.id}.${session.generation}`,
          }
        : {}),
      dispose: async () => {
        if (session.disposed) {
          if (fault === "dispose throws the second time")
            throw new Error("the sandbox session is already closed");
          return;
        }
        session.disposed = true;
        for (const child of session.children)
          try {
            if (child.pid) process.kill(-child.pid, "SIGKILL");
          } catch {
            // already gone
          }
        session.stop?.();
        if (fault === "dispose leaves the sandbox running") return;
        sessionsById.delete(session.id);
        if (session.root)
          rmSync(session.root, { recursive: true, force: true });
        await call("DELETE", `sessions/${session.id}`).catch(() => undefined);
      },
    });

    return {
      id: "acme-reference",
      async available() {
        if (!isolator)
          return { available: false, reason: "no isolator on this host" };
        try {
          const response = await call("GET", "health");
          return response.ok
            ? { available: true }
            : {
                available: false,
                reason: `the control service answered HTTP ${response.status}`,
              };
        } catch {
          if (fault === "available() throws when its service is down")
            throw new Error("the control service is down");
          return {
            available: false,
            reason: "the control service is unreachable",
          };
        }
      },
      capabilities,
      async prepare({ profile, signal }) {
        if (
          fault === "prepare() returns one shared instance" &&
          singleton &&
          !singleton.disposed
        )
          return instance(singleton);
        let response: Response;
        try {
          response = await call("POST", "sessions", signal);
        } catch (error) {
          if (fault === "logs the credential")
            console.warn("sandbox session failed:", error);
          throw fault === "keeps the transport error that quotes the credential"
            ? new Error("the control service is unreachable", { cause: error })
            : new Error("the control service is unreachable");
        }
        if (!response.ok)
          throw new Error(
            `the control service answered HTTP ${response.status}`,
          );
        const { id } = (await response.json()) as { id: string };
        const session: Session = {
          id,
          generation: 0,
          work: profile.workspace,
          root: undefined,
          profile,
          children: new Set(),
          stop: undefined,
          disposed: false,
        };
        if (behaves === "snapshot" || behaves === "synchronized") {
          const side = copy(profile);
          session.root = side.root;
          session.work = side.work;
        }
        if (behaves === "synchronized") {
          const toSandbox = copier(profile.workspace, session.work, delayMs);
          const toHost = copier(session.work, profile.workspace, delayMs);
          const timer = setInterval(() => {
            toSandbox();
            if (fault !== "the sandbox-to-host direction fails") toHost();
          }, 25);
          timer.unref();
          session.stop = () => clearInterval(timer);
        }
        sessionsById.set(id, session);
        singleton = session;
        return instance(session);
      },
    };
  });
}

/** The kit's replaceEnvironment hook for the reference: a new pod, same workspace. */
function replaceEnvironment(fault?: Fault) {
  return (instance: SandboxInstance) => {
    const id = instance.epoch?.()?.split(".")[0];
    const session = id ? sessionsById.get(id) : undefined;
    if (!session) throw new Error("no such session");
    session.generation++;
    if (
      fault === "loses the workspace mount when the environment is replaced"
    ) {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "reference-pod-")));
      cpSync(session.profile.workspace, join(root, "work"), {
        recursive: true,
      });
      session.root = root;
      session.work = join(root, "work");
    }
  };
}

// ---------------------------------------------------------------- helpers

const TIMINGS = {
  settleMs: 1_500,
  callTimeoutMs: 20_000,
  sharedWindowMs: 1_500,
} satisfies SandboxKitOptions;

async function run(
  options: ReferenceOptions,
  kit: SandboxKitOptions = {},
): Promise<ConformanceReport> {
  const service = new ControlService();
  return testSandboxAdapter(referenceAdapter(options), {
    ...TIMINGS,
    context: { endpoint: ENDPOINT, fetch: service.fetch },
    sandboxes: () => service.sessions.size,
    ...(options.variant === "shared" || options.variant === "synchronized"
      ? { replaceEnvironment: replaceEnvironment(options.fault) }
      : {}),
    ...kit,
  });
}

const statuses = (report: ConformanceReport) =>
  Object.fromEntries(
    report.results.map((result) => [result.behavior, result.status]),
  );

const passed = Object.fromEntries(
  SANDBOX_BEHAVIORS.map((behavior) => [behavior, "passed"]),
) as Record<SandboxBehavior, string>;

const WORKSPACE_BEHAVIORS: SandboxBehavior[] = [
  "workspace consistency",
  "git control protection",
  "workspace re-check",
];

/** What each good reference variant reports. */
const expected: Record<Variant, Record<string, string>> = {
  local: {
    ...passed,
    ...Object.fromEntries(WORKSPACE_BEHAVIORS.map((b) => [b, "skipped"])),
  },
  snapshot: {
    ...passed,
    ...Object.fromEntries(WORKSPACE_BEHAVIORS.map((b) => [b, "skipped"])),
  },
  shared: passed,
  synchronized: passed,
};

/** No reason may quote a credential, a planted value, or a planted file. */
function expectCleanReasons(report: ConformanceReport): void {
  for (const result of report.results)
    expect(result.reason ?? "").not.toMatch(
      /conformance-(sandbox-credential|host-token|host-only|host-approved|host-file|denied-file)-/,
    );
}

const reasons = (report: ConformanceReport) =>
  Object.fromEntries(
    report.results
      .filter((result) => result.reason)
      .map((result) => [result.behavior, result.reason]),
  );

// ------------------------------------------------------------------ tests

describe("sandbox conformance kit: contract", () => {
  it("names each behavior of §16.3 and the workspace checks once, each with a contract statement", () => {
    expect(SANDBOX_BEHAVIORS).toEqual([
      "availability",
      "capabilities",
      "prepare",
      "execute",
      "environment filtering",
      "secret leakage",
      "filesystem claims",
      "network claims",
      "timeout",
      "cancellation",
      "cleanup",
      "dispose",
      "fail-closed behavior",
      "workspace consistency",
      "git control protection",
      "workspace re-check",
    ]);
    for (const entry of SANDBOX_CONTRACT)
      expect(entry.statement.length).toBeGreaterThan(60);
  });

  it("refuses timing options that are not positive numbers", async () => {
    for (const value of [0, -1, Number.NaN, Number.POSITIVE_INFINITY])
      for (const name of ["settleMs", "callTimeoutMs", "sharedWindowMs"])
        await expect(
          testSandboxAdapter(referenceAdapter({ variant: "snapshot" }), {
            [name]: value,
          }),
        ).rejects.toThrow(RangeError);
  });

  it("fails every behavior, with a reason, when the factory builds no backend", async () => {
    const report = await testSandboxAdapter(
      defineSandboxAdapter(() => undefined as never),
      TIMINGS,
    );
    for (const result of report.results) {
      expect(result.status).toBe("failed");
      expect(result.reason).toMatch(/adapter factory failed/);
    }
  });
});

describeIsolated(isolator)(
  `sandbox conformance kit against reference backends (${isolator ?? "no isolator"})`,
  () => {
    it.concurrent.each([
      "local",
      "snapshot",
      "shared",
      "synchronized",
    ] as const)(
      "passes the %s reference backend",
      async (variant) => {
        const report = await run({ variant });
        expect(report.kind).toBe("sandbox");
        expect(report.results.map((result) => result.behavior)).toEqual(
          SANDBOX_BEHAVIORS,
        );
        expect({
          statuses: statuses(report),
          reasons: reasons(report),
        }).toEqual({
          statuses: expected[variant],
          reasons: expect.any(Object),
        });
        expectCleanReasons(report);
        // A snapshot or local backend's workspace checks are skipped, never
        // passed, and say why.
        if (variant === "snapshot" || variant === "local")
          for (const behavior of WORKSPACE_BEHAVIORS)
            expect(reasons(report)[behavior]).toMatch(
              variant === "snapshot"
                ? /^declares snapshot: .*never a complete coding-agent workspace$/
                : /^a local backend runs commands on this host's files/,
            );
      },
      120_000,
    );

    it.concurrent("passes a reference that returns a command's output only when it ends", async () => {
      const report = await run({ variant: "shared", buffered: true });
      expect(statuses(report)).toEqual(expected.shared);
    }, 120_000);

    it.concurrent("passes a reference that starts a command late, and gives up on it when it is aborted or disposed", async () => {
      const report = await run({ variant: "shared", slowStart: true });
      expect(statuses(report)).toEqual(expected.shared);
    }, 120_000);

    it("skips cleanup without the sandboxes hook, and the network check for a deny-only backend", async () => {
      const service = new ControlService();
      const report = await testSandboxAdapter(
        referenceAdapter({
          variant: "snapshot",
          networkModes: ["deny"],
        }),
        {
          ...TIMINGS,
          context: { endpoint: ENDPOINT, fetch: service.fetch },
          only: ["capabilities", "cleanup", "network claims"],
        },
      );
      expect(statuses(report)).toMatchObject({
        capabilities: "passed",
        cleanup: "skipped",
        "network claims": "skipped",
      });
      expect(reasons(report).cleanup).toMatch(/pass sandboxes\(\)/);
      expect(reasons(report)["network claims"]).toMatch(
        /enforces only network deny/,
      );
    }, 120_000);

    it("runs only the selected behaviors and reports the rest as not selected, never passed", async () => {
      const report = await run(
        { variant: "shared" },
        { only: ["execute", "workspace consistency"] },
      );
      expect(statuses(report)).toEqual({
        ...Object.fromEntries(SANDBOX_BEHAVIORS.map((b) => [b, "skipped"])),
        execute: "passed",
        "workspace consistency": "passed",
      });
      expect(reasons(report).dispose).toBe("not selected by the only option");
      await expect(
        run({ variant: "shared" }, { only: ["everything" as SandboxBehavior] }),
      ).rejects.toThrow(/only names an unknown behavior/);
    }, 120_000);

    it("reports every behavior failed when the backend is unavailable in the kit's context", async () => {
      const report = await testSandboxAdapter(
        referenceAdapter({ variant: "shared" }),
        {
          ...TIMINGS,
          context: {
            endpoint: ENDPOINT,
            fetch: async () => new Response(null, { status: 503 }),
          },
        },
      );
      expect(reasons(report).availability).toMatch(
        /reported itself unavailable in the kit's context \(the control service answered HTTP 503\)/,
      );
      for (const behavior of [
        "prepare",
        "execute",
        "timeout",
        "workspace consistency",
      ] as const)
        expect(
          report.results.find((result) => result.behavior === behavior),
        ).toMatchObject({
          status: "failed",
          reason: expect.stringMatching(/not available in the kit's context/),
        });
    }, 120_000);

    it.concurrent.each([
      [
        "an unknown guarantee",
        (caps: SandboxCapabilities) => ({
          ...caps,
          planes: [...caps.planes, "everything"],
        }),
        /unknown guarantee \(everything\)/,
      ],
      [
        "propagationMs on a shared workspace",
        (caps: SandboxCapabilities) => ({
          ...caps,
          workspace: { mode: "shared", propagationMs: 100 },
        }),
        /propagationMs applies only to a synchronized workspace/,
      ],
      [
        "an absolute sentinelDir",
        (caps: SandboxCapabilities) => ({
          ...caps,
          workspace: { mode: "shared", sentinelDir: "/etc" },
        }),
        /sentinelDir must be workspace-relative/,
      ],
      [
        "a sentinelDir with ..",
        (caps: SandboxCapabilities) => ({
          ...caps,
          workspace: { mode: "shared", sentinelDir: "a/../b" },
        }),
        /must not contain \.\./,
      ],
      [
        "a sentinelDir on a snapshot",
        (caps: SandboxCapabilities) => ({
          ...caps,
          workspace: { mode: "snapshot", sentinelDir: "sync" },
        }),
        /sentinelDir does not apply to a snapshot workspace/,
      ],
      [
        "an unknown workspace mode",
        (caps: SandboxCapabilities) => ({
          ...caps,
          workspace: { mode: "mounted" } as never,
        }),
        /not snapshot, synchronized, or shared/,
      ],
      [
        "localProcesses on a remote backend",
        (caps: SandboxCapabilities) => ({ ...caps, localProcesses: true }),
        /localProcesses is true for a remote backend/,
      ],
      [
        "network deny without network-deny",
        (caps: SandboxCapabilities) => ({
          ...caps,
          planes: caps.planes.filter((plane) => plane !== "network-deny"),
        }),
        /lists network mode deny but does not claim network-deny/,
      ],
      [
        "a shared workspace without git-control-protection",
        (caps: SandboxCapabilities) => ({
          ...caps,
          planes: caps.planes.filter(
            (plane) => plane !== "git-control-protection",
          ),
        }),
        /must claim git-control-protection/,
      ],
    ] as const)(
      "refuses a malformed declaration: %s",
      async (_name, change, reason) => {
        const service = new ControlService();
        const good = referenceAdapter({ variant: "shared" });
        const report = await testSandboxAdapter(
          defineSandboxAdapter(async (context) => {
            const backend = await good(context);
            return {
              id: "acme-reference",
              available: () => backend.available(),
              capabilities: () =>
                change(backend.capabilities()) as SandboxCapabilities,
              prepare: (request) => backend.prepare(request),
            };
          }),
          {
            ...TIMINGS,
            context: { endpoint: ENDPOINT, fetch: service.fetch },
            only: ["capabilities"],
          },
        );
        expect(
          report.results.find((result) => result.behavior === "capabilities"),
        ).toMatchObject({
          status: "failed",
          reason: expect.stringMatching(reason),
        });
      },
      120_000,
    );

    // Each seeded defect breaks exactly one behavior: the kit fails that one
    // with a reason and passes every other. A behavior that needs a verified
    // workspace first is skipped, never passed, when the first check failed.
    const seeds: [
      Fault,
      Variant,
      SandboxBehavior,
      RegExp,
      SandboxBehavior[]?,
    ][] = [
      [
        "available() throws when its service is down",
        "shared",
        "availability",
        /with its service unreachable, available\(\) threw/,
      ],
      [
        "claims host-filesystem-isolation with a shared workspace",
        "shared",
        "capabilities",
        /claims host-filesystem-isolation although its workspace is shared/,
      ],
      [
        "prepare() returns one shared instance",
        "shared",
        "prepare",
        /disposing one instance stopped another/,
      ],
      [
        "sends stderr to onStdout",
        "shared",
        "execute",
        /stdout did not arrive/,
      ],
      [
        "passes the launcher's environment through",
        "shared",
        "environment filtering",
        /launcher's environment that PiShip did not approve reached the command \(PISHIP_CONFORMANCE_HOST_TOKEN, PISHIP_CONFORMANCE_HOST_ONLY\)/,
      ],
      [
        "keeps the transport error that quotes the credential",
        "shared",
        "secret leakage",
        /after a transport error that quotes the credential: the credential appeared in the error from prepare\(\)/,
      ],
      [
        "logs the credential",
        "shared",
        "secret leakage",
        /in a line the backend logged/,
      ],
      [
        "claims host-filesystem-isolation but exposes a host path",
        "snapshot",
        "filesystem claims",
        /read a file on this host outside the workspace/,
      ],
      [
        "claims network denial but connects",
        "shared",
        "network claims",
        /connected to the kit's loopback listener although the profile denies the network/,
      ],
      [
        "ignores a timeout once the command streams output",
        "shared",
        "timeout",
        /did not settle within 1500 ms after io.signal aborted for a timeout|timed-out command kept running and wrote its marker/,
      ],
      [
        "ignores cancellation",
        "shared",
        "cancellation",
        /cancelled before it started ran on and wrote its marker/,
      ],
      [
        "starts a timed-out command late and leaves it running",
        "shared",
        "timeout",
        /the timed-out command kept running and wrote its marker/,
      ],
      [
        "starts a cancelled command late and leaves it running",
        "shared",
        "cancellation",
        /cancelled before it started ran on and wrote its marker/,
      ],
      [
        "starts a cancelled command after the kit's window and leaves it running",
        "shared",
        "cancellation",
        /cancelled before it started ran on and wrote its marker/,
      ],
      [
        "dispose leaves the sandbox running",
        "shared",
        "cleanup",
        /still holds 1 sandbox more than before prepare\(\)/,
      ],
      [
        "dispose throws the second time",
        "shared",
        "dispose",
        /second dispose\(\) did not resolve/,
      ],
      [
        "starts a command late and ignores dispose()",
        "shared",
        "dispose",
        /a command that was running at dispose\(\) kept running and wrote its marker/,
      ],
      [
        "answers PiShip's check command itself",
        "shared",
        "fail-closed behavior",
        /answered PiShip's sandbox check itself/,
      ],
      [
        "the sandbox-to-host direction fails",
        "synchronized",
        "workspace consistency",
        /the host did not see a file the sandbox wrote within 1500 ms/,
        ["workspace re-check"],
      ],
      [
        "claims shared but is a snapshot",
        "shared",
        "workspace consistency",
        /neither side saw the other's file within 1500 ms: the sandbox sees a snapshot, not a shared workspace/,
        ["workspace re-check"],
      ],
      [
        "declares shared but propagates with a delay",
        "shared",
        "workspace consistency",
        /declares shared, but a direction was delayed/,
        ["workspace re-check"],
      ],
      [
        "lets the workspace write .git/hooks",
        "shared",
        "git control protection",
        /created in a protected git directory \(\.git\/hooks\)/,
      ],
      [
        "epoch() does not change when the environment is replaced",
        "shared",
        "workspace re-check",
        /epoch\(\) did not change after the environment was replaced/,
      ],
      [
        "loses the workspace mount when the environment is replaced",
        "shared",
        "workspace re-check",
        /after epoch\(\) changed: neither side saw/,
      ],
    ];

    it.concurrent.each(seeds)(
      "fails only %j (%s reference), under %s",
      async (fault, variant, behavior, reason, dependents = []) => {
        const report = await run({ variant, fault });
        const result = report.results.find(
          (item) => item.behavior === behavior,
        );
        expect(result).toMatchObject({ status: "failed" });
        expect(result?.reason).toMatch(reason);
        expect(statuses(report)).toEqual({
          ...expected[variant],
          [behavior]: "failed",
          ...Object.fromEntries(dependents.map((b) => [b, "skipped"])),
        });
        for (const dependent of dependents)
          expect(reasons(report)[dependent]).toMatch(
            /first workspace check did not pass/,
          );
        expectCleanReasons(report);
      },
      120_000,
    );

    it("covers every behavior with at least one seeded defect", () => {
      expect(new Set(seeds.map(([, , behavior]) => behavior))).toEqual(
        new Set(SANDBOX_BEHAVIORS),
      );
    });

    it("restores the launcher environment and console it planted and watched", async () => {
      const before = { ...process.env };
      const log = console.log;
      const write = process.stderr.write;
      await run(
        { variant: "snapshot" },
        { only: ["environment filtering", "secret leakage"] },
      );
      expect(process.env).toEqual(before);
      expect(console.log).toBe(log);
      expect(process.stderr.write).toBe(write);
    }, 120_000);

    it.concurrent("removes its fixture from a workspace the author supplies, and refuses one that is not empty", async () => {
      const dir = realpathSync(
        mkdtempSync(join(tmpdir(), "author-workspace-")),
      );
      try {
        const report = await run({ variant: "shared" }, { workspace: dir });
        expect(statuses(report)).toEqual(expected.shared);
        expect(readdirSync(dir)).toEqual([]);
        writeFileSync(join(dir, "keep"), "x");
        await expect(
          run({ variant: "shared" }, { workspace: dir }),
        ).rejects.toThrow(/must be an empty directory/);
        expect(readdirSync(dir)).toEqual(["keep"]);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }, 120_000);
  },
);
