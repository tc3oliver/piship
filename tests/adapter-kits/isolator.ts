// Runs a shell command for a fake remote execution service, inside an OS
// mechanism that makes the service's isolation claims true: Seatbelt on
// macOS (deny by default, then the sandbox's own directory), bubblewrap on
// Linux (only the system directories and the sandbox's own directory). Where
// neither works, `isolator` is undefined and the sandbox tests are skipped.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync, lstatSync, readlinkSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
/** The PATH a command inside the fake sandbox receives when it has none. */
export const SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";

export interface Isolation {
  /** The one directory the command may read and write. */
  readonly root: string;
  readonly network: "deny" | "allow";
}

const sbpl = (path: string) => `"${path.replace(/[\\"]/g, "\\$&")}"`;

function seatbelt(spec: Isolation): string {
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-exec process-fork signal sysctl-read mach-lookup ipc-posix-shm file-read-metadata)",
    '(allow file-read* (literal "/") (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/System") (subpath "/Library") (subpath "/private/var/db") (subpath "/dev"))',
    '(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/tty") (literal "/dev/stdout") (literal "/dev/stderr") (regex #"^/dev/fd/[0-9]+$"))',
    `(allow file-read* file-write* (subpath ${sbpl(spec.root)}))`,
  ];
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
    "--bind",
    spec.root,
    spec.root,
    "--chdir",
    cwd,
  );
  return args;
}

function findBwrap(): string | undefined {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    const candidate = join(dir, "bwrap");
    if (dir && existsSync(candidate)) return candidate;
  }
  return undefined;
}

const bwrap = process.platform === "linux" ? findBwrap() : undefined;

function commandLine(
  spec: Isolation,
  cwd: string,
  line: string,
  kind: "seatbelt" | "bubblewrap",
): { file: string; args: string[] } {
  if (kind === "seatbelt")
    return {
      file: SANDBOX_EXEC,
      args: ["-p", seatbelt(spec), "/bin/sh", "-c", line],
    };
  return {
    file: bwrap as string,
    args: [...bubblewrap(spec, cwd), "/bin/sh", "-c", line],
  };
}

export const isolator: "seatbelt" | "bubblewrap" | undefined = (() => {
  const dir = realpathSync(tmpdir());
  const probe = (kind: "seatbelt" | "bubblewrap") => {
    const { file, args } = commandLine(
      { root: dir, network: "deny" },
      dir,
      "exit 0",
      kind,
    );
    return spawnSync(file, args, { timeout: 10_000 }).status === 0;
  };
  if (process.platform === "darwin" && existsSync(SANDBOX_EXEC))
    return probe("seatbelt") ? "seatbelt" : undefined;
  if (bwrap) return probe("bubblewrap") ? "bubblewrap" : undefined;
  return undefined;
})();

export interface Isolated {
  readonly child: ChildProcess;
  /** Resolves when the command ended: its exit code, or null when signalled. */
  readonly exited: Promise<{ code: number | null; signal: string | null }>;
  /** SIGKILL the command's whole process group, background jobs included. */
  killGroup(): void;
  /** SIGKILL the started process only; what it started in the background lives on. */
  killProcess(): void;
}

/** Start `line` in `/bin/sh` inside the isolator, in its own process group. */
export function runIsolated(
  spec: Isolation,
  cwd: string,
  line: string,
  env: Record<string, string>,
  onStdout: (chunk: Buffer) => void,
  onStderr: (chunk: Buffer) => void,
): Isolated {
  if (!isolator) throw new Error("no isolator on this host");
  const run = commandLine(spec, cwd, line, isolator);
  const child = spawn(run.file, run.args, {
    cwd,
    env: { PATH: SYSTEM_PATH, ...env },
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", onStdout);
  child.stderr?.on("data", onStderr);
  const exited = new Promise<{ code: number | null; signal: string | null }>(
    (resolve) => {
      child.once("error", () => resolve({ code: 127, signal: null }));
      child.once("close", (code, signal) => resolve({ code, signal }));
    },
  );
  const kill = (pid: number) => {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // already gone
    }
  };
  return {
    child,
    exited,
    killGroup: () => {
      if (child.pid) kill(-child.pid);
    },
    killProcess: () => {
      if (child.pid) kill(child.pid);
    },
  };
}
