// Everything the service asks of Docker, as argument lists built in one place:
// what a sandbox container is allowed to be is read here, and nowhere else.
import { spawn } from "node:child_process";

/** Where the workspace appears inside a sandbox. */
export const WORKSPACE_MOUNT = "/workspace";
/** Where a cancelled command leaves its token, on the sandbox's tmpfs. */
const CANCEL_DIRECTORY = "/tmp";
/** Set in every command's environment; names it for the cancel script. */
export const EXEC_ID_VARIABLE = "PISHIP_EXEC_ID";

// The environment the docker CLI needs to find its daemon and context, and
// nothing else: the service holds no secret, but the CLI has no use for the
// rest.
const CLI_VARIABLES = new Set([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "TMPDIR",
  "LANG",
  "XDG_CONFIG_HOME",
  "XDG_RUNTIME_DIR",
]);

export function cliEnvironment(env) {
  return Object.fromEntries(
    Object.entries(env).filter(
      ([name, value]) =>
        typeof value === "string" &&
        (CLI_VARIABLES.has(name) || name.startsWith("DOCKER_")),
    ),
  );
}

/**
 * Arguments of `docker run` for one sandbox. The container is started with
 * no privilege and nothing shared with the host but what is listed:
 *
 * - the workspace, read-write, at /workspace; the project's `.git` read-only
 *   on top of it (so no hook, config, or worktree metadata can be changed or
 *   created, and none renamed away), with only `.git/piship-workspace`
 *   writable again, the directory PiShip's workspace check uses; and each
 *   further protected path the caller names, read-only;
 * - a small tmpfs at /tmp, the only other writable place;
 * - no capability, no new privilege, the runtime's default seccomp and
 *   AppArmor profiles, a read-only root filesystem, and limits on processes,
 *   memory, and CPU;
 * - no network at all when the profile denies it.
 *
 * There is no `--privileged`, no published port, no docker socket, no host
 * PID, IPC, or network namespace, and no device.
 */
export function runArguments(config, spec) {
  const mounts = [
    { source: spec.workspace, target: WORKSPACE_MOUNT, readonly: false },
    ...spec.mounts,
  ];
  return [
    "run",
    "--detach",
    "--rm",
    "--init",
    "--name",
    spec.name,
    "--label",
    `piship.sandbox.instance=${config.instance}`,
    "--label",
    `piship.sandbox.owner=${config.uid}`,
    "--label",
    `piship.sandbox.session=${spec.session}`,
    "--user",
    `${spec.uid}:${spec.gid}`,
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--read-only",
    "--tmpfs",
    `${CANCEL_DIRECTORY}:rw,nosuid,nodev,size=${config.tmpSize}`,
    "--pids-limit",
    String(config.pids),
    "--memory",
    config.memory,
    "--memory-swap",
    config.memory,
    "--cpus",
    config.cpus,
    "--network",
    spec.network === "deny" ? "none" : config.allowNetwork,
    "--restart",
    "no",
    "--env",
    `HOME=${CANCEL_DIRECTORY}`,
    ...mounts.flatMap((mount) => [
      "--mount",
      `type=bind,src=${mount.source},dst=${mount.target}${mount.readonly ? ",readonly" : ""}`,
    ]),
    "--workdir",
    WORKSPACE_MOUNT,
    config.image,
    // The sandbox ends by itself at the maximum lifetime, even if this
    // service died and could not remove it.
    "sleep",
    String(config.maxLifetimeSeconds + 60),
  ];
}

/**
 * Arguments of `docker exec` for one command. The environment is written to
 * the CLI's standard input, which `--interactive` forwards to the reader in
 * the container: no value is on this process's command line, none is in the
 * exec's configuration at the daemon, and no file holds one, so nothing
 * survives a crash of this service. (`--env-file /dev/stdin` cannot be used:
 * on Linux the CLI's standard input is a socket, which cannot be opened by
 * path.) The command itself is on the command line: an organization that
 * cannot accept that runs the container runtime through its API instead of
 * this CLI.
 *
 * The reader exports each `NAME=value` line and, at the empty line that ends
 * them, replaces itself with the wrapper, whose environment then carries the
 * command's ID from its start, with the standard input closed. An environment
 * cut short (the CLI killed while it forwarded it) runs nothing. The wrapper
 * gives up at once if the command was cancelled before it began: `docker
 * exec` returns before the process exists in the container, so a cancel can
 * arrive first.
 */
export function execArguments(config, exec) {
  const reader = `while IFS= read -r variable; do [ -z "$variable" ] && exec ${config.shell} -c "$2" piship-exec "$1" < /dev/null; export "$variable" || exit 125; done; exit 125`;
  const wrapper = `[ -e "${CANCEL_DIRECTORY}/.piship-cancel-$${EXEC_ID_VARIABLE}" ] && exit 143; exec ${config.shell} -c "$1"`;
  return [
    "exec",
    "--interactive",
    "--workdir",
    exec.workdir,
    exec.container,
    config.shell,
    "-c",
    reader,
    "piship-exec",
    exec.command,
    wrapper,
  ];
}

/** The environment of one command as the reader takes it: a `NAME=value` line each, then an empty line. */
export function environmentInput(id, variables) {
  const lines = [[EXEC_ID_VARIABLE, id], ...variables].map(
    ([name, value]) => `${name}=${value}`,
  );
  return `${lines.join("\n")}\n\n`;
}

/**
 * Stops a command. Run inside the sandbox by a second `docker exec`, with the
 * command's ID, a mode, and the process ID of the sandbox's own main process.
 * It leaves the cancel token first (a command that has not begun will not),
 * then stops the processes it is to end (SIGSTOP, so nothing forks any more)
 * and kills them.
 *
 * - `marked`: every process whose environment carries the command's ID. A
 *   command's children inherit it, so this reaches a background process and a
 *   process that started its own session, which a process group would not.
 *   It cannot reach one that dropped the variable (`env -u`), so it is used
 *   only while another command runs in the sandbox, whose processes a sweep
 *   would kill too.
 * - `sweep`: every process of the sandbox except its init and its main
 *   process, which the service found at creation. Nothing else runs in the
 *   sandbox but the cancelled command and what it left, so a process that
 *   dropped the ID, or every variable, goes as well.
 *
 * The ID is random and never leaves this service.
 */
export const CANCEL_SCRIPT = `
ID=$1; MODE=$2; MAIN=$3
: > "${CANCEL_DIRECTORY}/.piship-cancel-$ID"
marked() { tr '\\0' '\\n' < "/proc/$1/environ" 2>/dev/null | grep -qx "${EXEC_ID_VARIABLE}=$ID"; }
signal() {
  for d in /proc/[0-9]*; do
    p=\${d##*/}
    [ "$p" = "$$" ] && continue
    if [ "$MODE" = sweep ]; then
      [ "$p" = 1 ] && continue
      [ "$p" = "$MAIN" ] && continue
      kill -"$1" "$p" 2>/dev/null
    else
      marked "$p" && kill -"$1" "$p" 2>/dev/null
    fi
  done
}
signal STOP; signal STOP; signal STOP
signal KILL; signal KILL
exit 0
`;

/** `mode` is "sweep" or "marked"; `main` is the sandbox's main process, for a sweep. */
export function cancelArguments(config, container, id, mode, main) {
  return [
    "exec",
    container,
    config.shell,
    "-c",
    CANCEL_SCRIPT,
    "piship-cancel",
    id,
    mode,
    String(main ?? ""),
  ];
}

/**
 * Prints the process ID of the sandbox's main process: right after creation,
 * the only process whose parent is the init (process 1), since nothing else
 * runs yet. The service asks once, before any command.
 */
export const MAIN_PROCESS_SCRIPT = `
for d in /proc/[0-9]*; do
  p=\${d##*/}
  [ "$p" = "$$" ] && continue
  set -- $(sed 's/^.*) //' "$d/stat" 2>/dev/null)
  [ "$2" = 1 ] && { echo "$p"; exit 0; }
done
exit 1
`;

export function mainProcessArguments(config, container) {
  return [
    "exec",
    container,
    config.shell,
    "-c",
    MAIN_PROCESS_SCRIPT,
    "piship-main",
  ];
}

/**
 * Prints `device:inode` of each path, one line each, as the container sees
 * it: for a mount point, the file the runtime mounted there. `stat` is run
 * directly, with no shell, before any command of the caller's.
 */
export function mountIdentityArguments(container, targets) {
  return ["exec", container, "stat", "-c", "%d:%i", "--", ...targets];
}

/**
 * The docker CLI as the service uses it. `run` collects a short command's
 * output; `start` hands back the child of a long one (a command's `exec`).
 * Neither rejects: a CLI that cannot start is `{code: null, error: true}`.
 */
export function createDocker({ command = "docker", env = process.env } = {}) {
  const environment = cliEnvironment(env);
  return {
    run(args, { timeoutMs = 60_000 } = {}) {
      return new Promise((resolve) => {
        let stdout = "";
        let stderr = "";
        let timedOut = false;
        let child;
        try {
          child = spawn(command, args, {
            env: environment,
            stdio: ["ignore", "pipe", "pipe"],
          });
        } catch {
          resolve({ code: null, stdout, stderr, error: true, timedOut });
          return;
        }
        const timer = setTimeout(() => {
          timedOut = true;
          child.kill("SIGKILL");
        }, timeoutMs);
        child.stdout.on("data", (chunk) => {
          if (stdout.length < 1_000_000) stdout += chunk;
        });
        child.stderr.on("data", (chunk) => {
          if (stderr.length < 1_000_000) stderr += chunk;
        });
        child.once("error", () => {
          clearTimeout(timer);
          resolve({ code: null, stdout, stderr, error: true, timedOut });
        });
        child.once("close", (code) => {
          clearTimeout(timer);
          resolve({ code, stdout, stderr, error: false, timedOut });
        });
      });
    },
    /**
     * A long command's child. `input` is written to its standard input, which
     * is then closed.
     */
    start(args, { input = "" } = {}) {
      const child = spawn(command, args, {
        env: environment,
        stdio: ["pipe", "pipe", "pipe"],
      });
      // The CLI may end before it reads all of it; its exit says so.
      child.stdin.on("error", () => undefined);
      child.stdin.end(input);
      return child;
    },
  };
}
