// The sandboxes: one container per session, created for the caller whose key
// asked for it, in which that caller's commands run against the workspace
// bind-mounted at /workspace. This module decides what may be mounted and
// runs the container lifecycle; it never sees a credential.
import { randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, posix, relative, sep } from "node:path";
import {
  cancelArguments,
  EXEC_ID_VARIABLE,
  execArguments,
  runArguments,
  WORKSPACE_MOUNT,
} from "./docker.mjs";

/** A refusal the caller may be told: a fixed status, code, and message. */
export class SandboxError extends Error {
  constructor(status, code, message, headers = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

const MAX_COMMAND_BYTES = 100_000;
const MAX_PATH = 4096;
const MAX_PROTECTED = 256;
const MAX_ENV = 256;
const MAX_ENV_VALUE = 32_768;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
// A mount option is a comma-separated list, and a path is written into it.
// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what this refuses
const UNSAFE_PATH = /[\u0000-\u001f\u007f,"]/;
const SESSION_ID = /^sbx_[0-9a-f]{24}$/;

const bad = (message) => new SandboxError(400, "bad_request", message);

const isObject = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function lstatOrUndefined(path) {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

const within = (root, path) =>
  path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);

/** The real path of `path`'s deepest existing ancestor, with the rest appended. */
function realpathNearest(path) {
  let current = path;
  const rest = [];
  for (;;) {
    try {
      return join(realpathSync(current), ...rest.reverse());
    } catch {
      const parent = dirname(current);
      if (parent === current) return path;
      rest.push(current.slice(parent.length + 1));
      current = parent;
    }
  }
}

function pathList(value, name) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_PROTECTED)
    throw bad(`writeProtect.${name} must be a short list of paths`);
  return value.map((entry) => {
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      entry.length > MAX_PATH ||
      !isAbsolute(entry)
    )
      throw bad(`writeProtect.${name} must list absolute paths`);
    return entry;
  });
}

/** The create request, checked. */
export function parseCreate(body) {
  if (!isObject(body)) throw bad("the request must be a JSON object");
  const { workspace, network, writeProtect } = body;
  if (
    typeof workspace !== "string" ||
    !isAbsolute(workspace) ||
    workspace.length > MAX_PATH ||
    UNSAFE_PATH.test(workspace)
  )
    throw bad("workspace must be an absolute path without commas or quotes");
  if (network !== "deny" && network !== "allow")
    throw bad("network must be deny or allow");
  if (writeProtect !== undefined && !isObject(writeProtect))
    throw bad("writeProtect must be an object");
  return {
    workspace,
    network,
    files: pathList(writeProtect?.files, "files"),
    directories: pathList(writeProtect?.directories, "directories"),
  };
}

/** The exec request, checked. */
export function parseExec(body) {
  if (!isObject(body)) throw bad("the request must be a JSON object");
  const { command, cwd = ".", env = {} } = body;
  if (
    typeof command !== "string" ||
    command.length === 0 ||
    Buffer.byteLength(command) > MAX_COMMAND_BYTES ||
    command.includes("\0")
  )
    throw bad("command must be a non-empty string of at most 100000 bytes");
  if (
    typeof cwd !== "string" ||
    cwd.length > MAX_PATH ||
    cwd.startsWith("/") ||
    cwd.includes("\0")
  )
    throw bad("cwd must be a path relative to the workspace");
  const directory = posix.normalize(cwd);
  if (directory === ".." || directory.startsWith("../"))
    throw bad("cwd must stay inside the workspace");
  if (!isObject(env) || Object.keys(env).length > MAX_ENV)
    throw bad("env must be an object of at most 256 variables");
  const variables = [];
  for (const [name, value] of Object.entries(env)) {
    // The value goes on one line of an env file, so it cannot hold a line
    // break; the ID variable is this service's.
    if (
      !ENV_NAME.test(name) ||
      name === EXEC_ID_VARIABLE ||
      typeof value !== "string" ||
      value.length > MAX_ENV_VALUE ||
      /[\0\r\n]/.test(value)
    )
      throw bad("env must map valid names to single-line strings");
    variables.push([name, value]);
  }
  return {
    command,
    workdir:
      directory === "."
        ? WORKSPACE_MOUNT
        : posix.join(WORKSPACE_MOUNT, directory),
    env: variables,
  };
}

export class Sandboxes {
  #config;
  #docker;
  #log;
  #now;
  #sessions = new Map();
  #reserved = 0;
  #closed = false;
  #directory;
  #timer;
  #runtime = { ok: false, at: 0 };

  constructor({ config, docker, log, now = Date.now }) {
    this.#config = config;
    this.#docker = docker;
    this.#log = log;
    this.#now = now;
    // Owner-only (mkdtemp makes it 0700): the env files of running commands
    // are written here.
    this.#directory = mkdtempSync(join(tmpdir(), "piship-sandbox-service-"));
  }

  /** Remove what an earlier run of this instance left behind, then start the sweep. */
  async start() {
    const listed = await this.#docker.run([
      "ps",
      "--all",
      "--quiet",
      "--filter",
      `label=piship.sandbox.instance=${this.#config.instance}`,
    ]);
    const stale = listed.stdout.split("\n").filter(Boolean);
    if (stale.length > 0)
      await this.#docker.run(["rm", "--force", ...stale], {
        timeoutMs: 60_000,
      });
    this.#log("service.started", { removed: stale.length });
    this.#timer = setInterval(() => this.sweep(), this.#config.sweepMs);
    this.#timer.unref();
  }

  /** Remove every sandbox and the env directory. */
  async close() {
    this.#closed = true;
    clearInterval(this.#timer);
    await Promise.all(
      [...this.#sessions.values()].map((session) =>
        this.#destroy(session, "shutdown").catch(() => undefined),
      ),
    );
    rmSync(this.#directory, { recursive: true, force: true });
  }

  count(owner) {
    let total = 0;
    for (const session of this.#sessions.values())
      if (session.owner === owner && !session.closing) total++;
    return total;
  }

  /** Whether the container runtime answers; asked at most every five seconds. */
  async #runtimeAnswers() {
    if (this.#now() - this.#runtime.at < 5000) return this.#runtime.ok;
    const answer = await this.#docker.run(
      ["version", "--format", "{{.Server.Version}}"],
      { timeoutMs: 10_000 },
    );
    this.#runtime = { ok: answer.code === 0, at: this.#now() };
    return this.#runtime.ok;
  }

  async status(owner) {
    return {
      runtime: (await this.#runtimeAnswers()) ? "ok" : "unavailable",
      sandboxes: this.count(owner),
      limit: this.#config.maxPerKey,
    };
  }

  #find(owner, id) {
    const session = SESSION_ID.test(id) ? this.#sessions.get(id) : undefined;
    // Another user's sandbox is answered like one that does not exist.
    if (!session || session.owner !== owner || session.closing)
      throw new SandboxError(404, "not_found", "There is no such sandbox");
    return session;
  }

  #touch(session) {
    session.lastActivity = this.#now();
  }

  /**
   * What the workspace mounts look like, or a refusal. The workspace must be
   * inside a root the operator configured; it must be a git repository with
   * a real `.git` directory, since that is how the git control files are
   * kept unchangeable; and it must not belong to root, since commands run as
   * its owner.
   */
  #plan(request) {
    const refused = new SandboxError(
      422,
      "workspace_not_allowed",
      "The workspace is not a directory this service may mount",
    );
    let real;
    try {
      real = realpathSync(request.workspace);
      if (!statSync(real).isDirectory()) throw refused;
    } catch {
      throw refused;
    }
    if (!this.#config.workspaceRoots.some((root) => within(root, real)))
      throw refused;
    if (UNSAFE_PATH.test(real)) throw refused;
    const unsupported = (message) =>
      new SandboxError(409, "workspace_unsupported", message);
    const dotGit = join(real, ".git");
    const dotGitStat = lstatOrUndefined(dotGit);
    if (!dotGitStat || dotGitStat.isSymbolicLink() || !dotGitStat.isDirectory())
      throw unsupported(
        "The workspace must be a git repository with a .git directory",
      );
    const { uid, gid } = statSync(real);
    if (uid === 0)
      throw unsupported(
        "The workspace belongs to root; commands do not run as root",
      );
    // The one place under the read-only .git that stays writable: where
    // PiShip's workspace check puts its files.
    const location = join(dotGit, "piship-workspace");
    const locationStat = lstatOrUndefined(location);
    if (!locationStat) {
      try {
        mkdirSync(location, { mode: 0o700 });
      } catch (error) {
        if (error?.code !== "EEXIST")
          throw unsupported(
            "The workspace's .git directory cannot be prepared",
          );
      }
    }
    const made = lstatOrUndefined(location);
    if (!made || made.isSymbolicLink() || !made.isDirectory())
      throw unsupported("The workspace's .git directory cannot be prepared");
    const mounts = [
      { source: dotGit, target: `${WORKSPACE_MOUNT}/.git`, readonly: true },
      {
        source: location,
        target: `${WORKSPACE_MOUNT}/.git/piship-workspace`,
        readonly: false,
      },
    ];
    // PiShip names the git control paths it needs kept read-only. Those under
    // .git are covered by the mount above; the rest (a core.hooksPath in the
    // working tree, a config file the git config includes) are mounted
    // read-only if they exist. One that does not exist cannot be guarded, and
    // PiShip's workspace check would find it creatable, so refuse now.
    const candidates = [];
    for (const path of [...request.directories, ...request.files]) {
      const resolved = realpathNearest(path);
      const rel = relative(real, resolved);
      if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`)) continue;
      if (isAbsolute(rel) || rel === ".git" || rel.startsWith(`.git${sep}`))
        continue;
      if (UNSAFE_PATH.test(rel))
        throw unsupported("A protected path cannot be mounted");
      candidates.push({
        resolved,
        depth: rel.split(sep).length,
        target: posix.join(WORKSPACE_MOUNT, ...rel.split(sep)),
      });
    }
    // A parent before what lies under it: a path inside a directory that is
    // mounted read-only is covered by that mount, missing or not.
    candidates.sort((a, b) => a.depth - b.depth);
    const directories = [];
    for (const { resolved, target } of candidates) {
      if (directories.some((dir) => target.startsWith(`${dir}/`))) continue;
      const stat = lstatOrUndefined(resolved);
      if (!stat)
        throw new SandboxError(
          409,
          "protected_path_missing",
          "A git control path that must be read-only does not exist, so it cannot be protected",
        );
      if (stat.isSymbolicLink())
        throw unsupported("A protected path is a symbolic link");
      if (stat.isDirectory()) directories.push(target);
      mounts.push({ source: resolved, target, readonly: true });
    }
    // A parent is mounted before what lies under it.
    mounts.sort((a, b) => a.target.length - b.target.length);
    return { real, uid, gid, mounts };
  }

  #assertOpen() {
    if (this.#closed)
      throw new SandboxError(
        503,
        "shutting_down",
        "The service is shutting down",
      );
  }

  async create(owner, request) {
    this.#assertOpen();
    if (this.#sessions.size + this.#reserved >= this.#config.maxTotal)
      throw new SandboxError(429, "limit_reached", "The service is full", {
        "retry-after": "5",
      });
    if (this.count(owner) >= this.#config.maxPerKey)
      throw new SandboxError(
        429,
        "limit_reached",
        "This key already holds its maximum number of sandboxes",
        { "retry-after": "5" },
      );
    if (!(await this.#runtimeAnswers()))
      throw new SandboxError(
        503,
        "runtime_unavailable",
        "The container runtime is not available",
      );
    const plan = this.#plan(request);
    const id = `sbx_${randomBytes(12).toString("hex")}`;
    const name = `piship-sbx-${this.#config.instance}-${id.slice(4, 16)}`;
    this.#reserved++;
    let started;
    try {
      started = await this.#docker.run(
        runArguments(this.#config, {
          name,
          session: id,
          workspace: plan.real,
          mounts: plan.mounts,
          uid: plan.uid,
          gid: plan.gid,
          network: request.network,
        }),
        { timeoutMs: 180_000 },
      );
    } finally {
      this.#reserved--;
    }
    if (started.code !== 0) {
      // A container that was created and did not start is gone with --rm;
      // make sure of it. The runtime's message goes to the operator's log (its
      // last line, which may name the image or a path) and never to the caller.
      this.#log("sandbox.create.failed", {
        owner,
        reason:
          started.stderr.trim().split("\n").at(-1) ||
          (started.error ? "the docker CLI did not start" : "no message"),
      });
      await this.#docker.run(["rm", "--force", name]);
      throw new SandboxError(
        started.error ? 503 : 502,
        started.error ? "runtime_unavailable" : "runtime_error",
        "The container runtime could not start the sandbox",
      );
    }
    const now = this.#now();
    const session = {
      id,
      owner,
      name,
      createdAt: now,
      lastActivity: now,
      execs: new Map(),
      closing: undefined,
    };
    this.#sessions.set(id, session);
    this.#log("sandbox.create", { owner, session: id });
    return { id };
  }

  /**
   * Start a command. Returns at once with the `docker exec` child, so the
   * caller can attach to its output before any arrives, and a `done` promise
   * that settles with the exit. Nothing here rejects after this returns.
   */
  startExec(owner, id, request) {
    this.#assertOpen();
    const session = this.#find(owner, id);
    if (session.execs.size >= this.#config.maxExecsPerSandbox)
      throw new SandboxError(
        429,
        "limit_reached",
        "This sandbox is already running its maximum number of commands",
        { "retry-after": "1" },
      );
    const execId = randomBytes(16).toString("hex");
    const envFile = join(this.#directory, `${execId}.env`);
    writeFileSync(
      envFile,
      `${[[EXEC_ID_VARIABLE, execId], ...request.env].map(([name, value]) => `${name}=${value}`).join("\n")}\n`,
      { mode: 0o600, flag: "wx" },
    );
    let child;
    try {
      child = this.#docker.start(
        execArguments(this.#config, {
          envFile,
          workdir: request.workdir,
          container: session.name,
          command: request.command,
        }),
      );
    } catch (error) {
      rmSync(envFile, { force: true });
      throw error;
    }
    const started = this.#now();
    const exec = {
      id: execId,
      session,
      child,
      cancelled: false,
      cancelling: undefined,
      finished: false,
      spawned: new Promise((resolve, reject) => {
        child.once("spawn", resolve);
        child.once("error", reject);
      }),
    };
    exec.spawned.catch(() => undefined);
    exec.done = new Promise((resolve) => {
      const finish = (code, signal) => {
        if (exec.finished) return;
        exec.finished = true;
        clearTimeout(timer);
        rmSync(envFile, { force: true });
        session.execs.delete(execId);
        this.#touch(session);
        this.#log("sandbox.exec", {
          session: session.id,
          duration_ms: this.#now() - started,
          ...(exec.cancelled ? { reason: exec.reason ?? "cancelled" } : {}),
          ...(typeof code === "number" ? { exit: code } : {}),
        });
        resolve(
          exec.cancelled
            ? { exit: null, signal: "SIGKILL", reason: exec.reason }
            : { exit: code, signal: signal ?? null },
        );
      };
      const timer = setTimeout(
        () => void this.cancelExec(exec, "timeout"),
        this.#config.maxExecSeconds * 1000,
      );
      child.once("close", finish);
      child.once("error", () => finish(null, null));
    });
    session.execs.set(execId, exec);
    this.#touch(session);
    return exec;
  }

  /**
   * Stop a command and every process it started. The docker CLI is killed
   * (it would otherwise leave the command running in the container), then the
   * cancel script runs in the sandbox; see `CANCEL_SCRIPT`.
   */
  cancelExec(exec, reason) {
    if (exec.cancelling) return exec.cancelling;
    if (exec.finished) return Promise.resolve();
    exec.cancelled = true;
    exec.reason = reason;
    exec.cancelling = (async () => {
      exec.child.kill("SIGKILL");
      if (!exec.session.closing)
        await this.#docker.run(
          cancelArguments(this.#config, exec.session.name, exec.id),
          { timeoutMs: 15_000 },
        );
    })();
    return exec.cancelling;
  }

  async remove(owner, id) {
    await this.#destroy(this.#find(owner, id), "deleted");
  }

  /** End a sandbox: stop its commands, then remove the container. */
  #destroy(session, reason) {
    if (session.closing) return session.closing;
    session.closing = (async () => {
      for (const exec of session.execs.values()) {
        exec.cancelled = true;
        exec.reason = reason;
        exec.child.kill("SIGKILL");
      }
      const removed = await this.#docker.run(["rm", "--force", session.name], {
        timeoutMs: 30_000,
      });
      // The container may already be gone (--rm, the lifetime limit, a
      // restarted runtime). Anything else leaves the sandbox tracked, so the
      // next attempt (a retry, the sweep, the shutdown) tries again.
      if (removed.code !== 0 && !/No such container/i.test(removed.stderr))
        throw new SandboxError(
          502,
          "runtime_error",
          "The container runtime could not remove the sandbox",
        );
      this.#sessions.delete(session.id);
      this.#log("sandbox.remove", { session: session.id, reason });
    })();
    session.closing.catch(() => {
      session.closing = undefined;
    });
    return session.closing;
  }

  sweep() {
    const now = this.#now();
    const { idleSeconds, maxLifetimeSeconds } = this.#config;
    for (const session of [...this.#sessions.values()]) {
      if (session.closing) continue;
      const expired =
        now - session.createdAt >= maxLifetimeSeconds * 1000 ||
        (session.execs.size === 0 &&
          now - session.lastActivity >= idleSeconds * 1000);
      if (expired) this.#destroy(session, "expired").catch(() => undefined);
    }
  }
}
