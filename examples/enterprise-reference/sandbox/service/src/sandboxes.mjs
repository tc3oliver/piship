// The sandboxes: one container per session, created for the caller whose key
// asked for it, in which that caller's commands run against the workspace
// bind-mounted at /workspace. This module decides what may be mounted and
// runs the container lifecycle; it never sees a credential.
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, posix, relative, sep } from "node:path";
import {
  cancelArguments,
  EXEC_ID_VARIABLE,
  environmentInput,
  execArguments,
  mainProcessArguments,
  mountIdentityArguments,
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

// Linux's O_PATH, which Node does not export: a descriptor that names a file
// without opening it, so it needs no read permission and opens nothing (a
// FIFO, a device) by being taken.
const O_PATH = process.platform === "linux" ? 0o10000000 : 0;

/**
 * The file at `path`, held by a descriptor while it is read: its stat, and
 * its identity (`device:inode`), which the container's mount is compared
 * with. Undefined unless `path` is, at that moment, the file's own path with
 * no symbolic link anywhere in it: on Linux, the kernel's name for the held
 * descriptor (/proc/self/fd) must be `path` itself. So every check made on
 * the stat (directory, owner, inside the roots) is about one file, the one
 * at that canonical path, whatever is renamed around it afterwards. Without
 * /proc the name is read with `realpath`, which a link swapped in and back
 * out around it could fool; such hosts (macOS) run Docker in a virtual
 * machine, where the identity cannot be compared anyway
 * (SANDBOX_MOUNT_IDENTITY=unverified).
 */
function identify(path) {
  let fd;
  try {
    fd = openSync(
      path,
      O_PATH
        ? O_PATH | constants.O_NOFOLLOW
        : constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
  } catch {
    return undefined;
  }
  try {
    const stat = fstatSync(fd);
    if (stat.isSymbolicLink()) return undefined;
    const where = O_PATH
      ? readlinkSync(`/proc/self/fd/${fd}`)
      : realpathSync(path);
    if (where !== path) return undefined;
    return { stat, identity: `${stat.dev}:${stat.ino}` };
  } catch {
    return undefined;
  } finally {
    closeSync(fd);
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
    // The value goes on one line of the environment the reader in the
    // container takes, so it cannot hold a line break; the ID variable is
    // this service's.
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
  #owner;
  #reserved = 0;
  #closed = false;
  #timer;
  #runtime = { ok: false, at: 0 };

  /**
   * `owner` reads a workspace's owner and group (a test seam: the tests
   * cannot make a directory of another user's or of root's).
   */
  constructor({
    config,
    docker,
    log,
    now = Date.now,
    owner = (_path, stat) => stat,
  }) {
    this.#config = config;
    this.#docker = docker;
    this.#log = log;
    this.#now = now;
    this.#owner = owner;
  }

  /**
   * Remove what an earlier run of this service left behind, then start the
   * sweep. "This service" is the containers that carry both its instance name
   * and its user's ID, so another service's containers, or anyone else's,
   * are never touched.
   */
  async start() {
    const listed = await this.#docker.run([
      "ps",
      "--all",
      "--quiet",
      "--filter",
      `label=piship.sandbox.instance=${this.#config.instance}`,
      "--filter",
      `label=piship.sandbox.owner=${this.#config.uid}`,
    ]);
    const stale = listed.stdout.split("\n").filter(Boolean);
    if (stale.length > 0)
      await this.#docker.run(["rm", "--force", ...stale], {
        timeoutMs: 60_000,
      });
    this.#log("service.started", { removed: stale.length });
    if (this.#config.mountIdentity !== "verify")
      this.#log("service.mount_identity_unverified");
    this.#timer = setInterval(() => this.sweep(), this.#config.sweepMs);
    this.#timer.unref();
  }

  /** Remove every sandbox. */
  async close() {
    this.#closed = true;
    clearInterval(this.#timer);
    await Promise.all(
      [...this.#sessions.values()].map((session) =>
        this.#destroy(session, "shutdown").catch(() => undefined),
      ),
    );
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
   * inside a root the operator configured (and one of the key's own roots, if
   * its registry entry names any); it must belong to the host user the key is
   * bound to, and never to root or to group 0, since commands run as its
   * owner and group, and a key must not run commands as someone else's user;
   * and it must be a git repository with a real `.git` directory, since that
   * is how the git control files are kept unchangeable. What the caller may
   * not mount is one answer, whether it is outside the roots, someone else's,
   * or root's, so a caller learns nothing about directories it may not use.
   */
  #plan(user, request) {
    const refused = new SandboxError(
      422,
      "workspace_not_allowed",
      "The workspace is not a directory this service may mount",
    );
    // Every check below is made on the stat of the one directory held at its
    // canonical path, and the mount is later compared with its identity.
    let real;
    let ownership;
    let held;
    try {
      real = realpathSync(request.workspace);
      held = identify(real);
      if (!held?.stat.isDirectory()) throw refused;
      ownership = this.#owner(real, held.stat);
    } catch {
      throw refused;
    }
    if (!this.#config.workspaceRoots.some((root) => within(root, real)))
      throw refused;
    if (user.roots && !user.roots.some((root) => within(root, real)))
      throw refused;
    if (UNSAFE_PATH.test(real)) throw refused;
    if (ownership.uid === 0 || ownership.gid === 0) throw refused;
    if (!user.unbound && ownership.uid !== user.uid) throw refused;
    const unsupported = (message) =>
      new SandboxError(409, "workspace_unsupported", message);
    const dotGit = join(real, ".git");
    const dotGitHeld = identify(dotGit);
    if (!dotGitHeld?.stat.isDirectory())
      throw unsupported(
        "The workspace must be a git repository with a .git directory",
      );
    const { uid, gid } = ownership;
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
    const made = identify(location);
    if (!made?.stat.isDirectory())
      throw unsupported("The workspace's .git directory cannot be prepared");
    const mounts = [
      {
        source: dotGit,
        target: `${WORKSPACE_MOUNT}/.git`,
        readonly: true,
        identity: dotGitHeld.identity,
      },
      {
        source: location,
        target: `${WORKSPACE_MOUNT}/.git/piship-workspace`,
        readonly: false,
        identity: made.identity,
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
    const protectedMounts = [];
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
      const guarded = identify(resolved);
      if (!guarded || !(guarded.stat.isDirectory() || guarded.stat.isFile()))
        throw unsupported("A protected path cannot be mounted");
      if (guarded.stat.isDirectory()) directories.push(target);
      protectedMounts.push({
        source: resolved,
        target,
        readonly: true,
        identity: guarded.identity,
      });
    }
    // A read-only mount only keeps its own mount point from being renamed.
    // A protected path deeper than the workspace's top level could otherwise
    // be moved aside with its parent (`mv x x-old`), and a writable `x/hooks`
    // made in its place on the host. Each directory between the workspace
    // and a protected path is therefore bound onto itself, writable: a mount
    // point, which cannot be renamed or removed.
    const pins = new Map();
    for (const { target } of protectedMounts) {
      const parts = posix.relative(WORKSPACE_MOUNT, target).split("/");
      for (let depth = 1; depth < parts.length; depth++) {
        const pin = posix.join(WORKSPACE_MOUNT, ...parts.slice(0, depth));
        if (pins.has(pin) || directories.includes(pin)) continue;
        const source = join(real, ...parts.slice(0, depth));
        const pinned = identify(source);
        if (!pinned?.stat.isDirectory())
          throw unsupported("A protected path cannot be mounted");
        pins.set(pin, {
          source,
          target: pin,
          readonly: false,
          identity: pinned.identity,
        });
      }
    }
    mounts.push(...protectedMounts, ...pins.values());
    // A parent is mounted before what lies under it.
    mounts.sort((a, b) => a.target.length - b.target.length);
    return { real, identity: held.identity, uid, gid, mounts };
  }

  #assertOpen() {
    if (this.#closed)
      throw new SandboxError(
        503,
        "shutting_down",
        "The service is shutting down",
      );
  }

  /** `user` is the registry entry the request's key belongs to. */
  async create(user, request) {
    const owner = user.id;
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
    const plan = this.#plan(user, request);
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
    // The Docker daemon resolved every mount source again, by its path, when
    // it mounted it: a path swapped for a link between the check and the
    // mount would give the container another directory than the one checked.
    // So before anything runs in it, the container's view of each mount must
    // be the very file the check held, by device and inode; otherwise the
    // container goes.
    if (this.#config.mountIdentity === "verify") {
      const targets = [WORKSPACE_MOUNT, ...plan.mounts.map((m) => m.target)];
      const expected = [plan.identity, ...plan.mounts.map((m) => m.identity)];
      const seen = await this.#docker.run(
        mountIdentityArguments(name, targets),
        { timeoutMs: 15_000 },
      );
      const lines = seen.stdout.trim().split("\n");
      const same =
        seen.code === 0 &&
        lines.length === expected.length &&
        lines.every((line, index) => line === expected[index]);
      if (!same) {
        this.#log("sandbox.create.failed", {
          owner,
          reason:
            seen.code === 0
              ? "a mount is not the file that was checked"
              : "the mounts could not be compared",
        });
        await this.#docker.run(["rm", "--force", name]);
        throw seen.code === 0
          ? new SandboxError(
              409,
              "workspace_changed",
              "The workspace changed while the sandbox was being created",
            )
          : new SandboxError(
              502,
              "runtime_error",
              "The container runtime could not start the sandbox",
            );
      }
    }
    // The sandbox's main process, found now, before any command has run: a
    // cancel that sweeps the sandbox must leave it alone. If it cannot be
    // found (a runtime without /proc/<pid>/stat), a cancel stays with the
    // processes that carry the command's ID.
    const found = await this.#docker.run(
      mainProcessArguments(this.#config, name),
      { timeoutMs: 15_000 },
    );
    const main =
      found.code === 0 && /^[1-9]\d{0,9}$/.test(found.stdout.trim())
        ? Number(found.stdout.trim())
        : undefined;
    const now = this.#now();
    const session = {
      id,
      owner,
      name,
      main,
      createdAt: now,
      lastActivity: now,
      execs: new Map(),
      closing: undefined,
      // Set while a cancel is sweeping the sandbox: no command starts in it
      // until the sweep is over, or the sweep would kill it.
      sweeping: undefined,
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
  async startExec(owner, id, request) {
    this.#assertOpen();
    let session = this.#find(owner, id);
    // A sweep of the sandbox by a cancel would kill a command that started
    // during it. Everything from here to the registration below is
    // synchronous, so no sweep can begin in between.
    while (session.sweeping) {
      await session.sweeping;
      this.#assertOpen();
      session = this.#find(owner, id);
    }
    if (session.execs.size >= this.#config.maxExecsPerSandbox)
      throw new SandboxError(
        429,
        "limit_reached",
        "This sandbox is already running its maximum number of commands",
        { "retry-after": "1" },
      );
    const execId = randomBytes(16).toString("hex");
    const child = this.#docker.start(
      execArguments(this.#config, {
        workdir: request.workdir,
        container: session.name,
        command: request.command,
      }),
      { input: environmentInput(execId, request.env) },
    );
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
   * Stop a command and everything it started. The docker CLI is killed (it
   * would otherwise leave the command running in the container), then the
   * cancel script runs in the sandbox; see `CANCEL_SCRIPT`. When this is the
   * only command running in the sandbox, the script sweeps every process of
   * the sandbox but its init and main process, so a process that dropped the
   * command's ID (`env -u PISHIP_EXEC_ID sleep 1e9 &`) does not outlive the
   * command's timeout or cancellation; no command starts in the sandbox until
   * the sweep is done. With another command running, the script can only
   * end the processes that carry this command's ID: one that dropped it
   * lives until the sandbox ends, which the docs name as the limit.
   */
  cancelExec(exec, reason) {
    if (exec.cancelling) return exec.cancelling;
    if (exec.finished) return Promise.resolve();
    const { session } = exec;
    const alone = [...session.execs.values()].every((other) => other === exec);
    const sweep = alone && session.main !== undefined;
    exec.cancelled = true;
    exec.reason = reason;
    exec.cancelling = (async () => {
      exec.child.kill("SIGKILL");
      if (session.closing) return;
      await this.#docker.run(
        cancelArguments(
          this.#config,
          session.name,
          exec.id,
          sweep ? "sweep" : "marked",
          session.main,
        ),
        { timeoutMs: 15_000 },
      );
    })();
    if (sweep) {
      const sweeping = exec.cancelling.finally(() => {
        if (session.sweeping === sweeping) session.sweeping = undefined;
      });
      session.sweeping = sweeping;
    }
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
