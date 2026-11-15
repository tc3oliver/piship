import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { win32 } from "node:path";

export interface PosixShell {
  /** Absolute path of the shell that runs a "remote sandbox" command. */
  shell: string;
  /** PATH for that shell: on Windows it starts with Git for Windows' unix tools (tar, ls, sed). */
  path: string;
}

/** `git --exec-path` is `<Git>/mingw64/libexec/git-core` on Git for Windows. */
export function gitRootFromExecPath(execPath: string): string {
  let root = win32.normalize(execPath.trim());
  for (let i = 0; i < 3; i++) root = win32.dirname(root);
  return root;
}

/**
 * The shell and PATH a test sandbox runs commands with. Windows has no
 * `/bin/sh`; Git for Windows ships `sh.exe` (not the WSL `bash.exe` in
 * System32, which runs a different filesystem). Undefined when none is found.
 */
export function resolvePosixShell(
  options: {
    platform?: NodeJS.Platform;
    pathEnv?: string;
    gitExecPath?: () => string | undefined;
    exists?: (path: string) => boolean;
  } = {},
): PosixShell | undefined {
  const platform = options.platform ?? process.platform;
  const pathEnv = options.pathEnv ?? process.env.PATH ?? process.env.Path ?? "";
  if (platform !== "win32") return { shell: "/bin/sh", path: pathEnv };
  const exists = options.exists ?? existsSync;
  const execPath = (
    options.gitExecPath ??
    (() => {
      const done = spawnSync("git", ["--exec-path"], { encoding: "utf8" });
      return done.status === 0 ? done.stdout : undefined;
    })
  )();
  if (!execPath?.trim()) return undefined;
  const root = gitRootFromExecPath(execPath);
  const usr = win32.join(root, "usr", "bin");
  const shell = [
    win32.join(usr, "sh.exe"),
    win32.join(root, "bin", "sh.exe"),
  ].find(exists);
  if (!shell) return undefined;
  return {
    shell,
    path: [usr, win32.join(root, "mingw64", "bin"), pathEnv].join(";"),
  };
}
