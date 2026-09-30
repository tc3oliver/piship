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
 * Arguments of `docker exec` for one command. The environment is read from a
 * file the caller made (mode 0600), so no value is on this process's command
 * line. The command itself is: an organization that cannot accept that runs
 * the container runtime through its API instead of this CLI.
 *
 * The wrapper gives up at once if the command was cancelled before it began:
 * `docker exec` returns before the process exists in the container, so a
 * cancel can arrive first.
 */
export function execArguments(config, exec) {
  const wrapper = `[ -e "${CANCEL_DIRECTORY}/.piship-cancel-$${EXEC_ID_VARIABLE}" ] && exit 143; exec ${config.shell} -c "$1"`;
  return [
    "exec",
    "--env-file",
    exec.envFile,
    "--workdir",
    exec.workdir,
    exec.container,
    config.shell,
    "-c",
    wrapper,
    "piship-exec",
    exec.command,
  ];
}

/**
 * Stops every process of one command, run inside the sandbox by a second
 * `docker exec`: it leaves the cancel token first (a command that has not
 * begun will not), then stops (SIGSTOP, so nothing forks any more) and kills
 * every process whose environment carries the command's ID. A command's
 * children inherit its environment, so this reaches a background process
 * and a process that started its own session, which a process group would
 * not. The ID is random and never leaves this service.
 */
export const CANCEL_SCRIPT = `
: > "${CANCEL_DIRECTORY}/.piship-cancel-$1"
marked() { tr '\\0' '\\n' < "/proc/$1/environ" 2>/dev/null | grep -qx "${EXEC_ID_VARIABLE}=$2"; }
signal() {
  for d in /proc/[0-9]*; do
    p=\${d##*/}
    [ "$p" = "$$" ] && continue
    marked "$p" "$1" && kill -"$2" "$p" 2>/dev/null
  done
}
signal "$1" STOP; signal "$1" STOP; signal "$1" STOP
signal "$1" KILL; signal "$1" KILL
exit 0
`;

export function cancelArguments(config, container, id) {
  return [
    "exec",
    container,
    config.shell,
    "-c",
    CANCEL_SCRIPT,
    "piship-cancel",
    id,
  ];
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
    start(args) {
      return spawn(command, args, {
        env: environment,
        stdio: ["ignore", "pipe", "pipe"],
      });
    },
  };
}
