// Linux adapter: bubblewrap (bwrap) with unprivileged user namespaces.
//
// Mount plan, applied in order (later mounts shadow earlier ones):
//   1. the host root read-only, a fresh /dev and /proc;
//   2. a private tmpfs on /tmp unless host /tmp is itself configured;
//   3. write-allowed paths bound read-write and extra read-only paths bound
//      read-only, outermost first so a nested entry wins over its parent;
//   4. protected paths inside writable ones (git control files and hooks)
//      bound read-only, the directories above those that exist pinned as
//      mount points;
//   5. read-denied directories replaced by an empty, mode 0000, read-only
//      tmpfs and read-denied files by /dev/null, last, so a deny always wins
//      over an allow, including a deny nested inside a writable workspace.
import { dirname, posix } from "node:path";
import { PiShipError } from "@piship/contracts";
import {
  type AdapterAvailability,
  findExecutable,
  runCheck,
  type SandboxAdapter,
  type SandboxCommand,
  type WrappedCommand,
} from "./adapter.js";
import {
  isDirectory,
  isWithin,
  pathDepth,
  pathExists,
  protectedAncestors,
  realpathNearest,
  type SandboxProfile,
  writableProtected,
} from "./profile.js";

export interface BubblewrapFeatures {
  /** `--unshare-user --disable-userns` (bubblewrap >= 0.8). */
  readonly disableUserns: boolean;
  /** `--perms` before `--tmpfs` (bubblewrap >= 0.8). */
  readonly tmpfsPerms: boolean;
}

export const MODERN_BUBBLEWRAP: BubblewrapFeatures = {
  disableUserns: true,
  tmpfsPerms: true,
};

/**
 * Host IPC endpoints that would let a contained process act outside the
 * sandbox (the session bus can ask systemd to start unconfined processes; a
 * container daemon socket is root-equivalent). They are filesystem sockets,
 * so a network namespace does not block them; they are hidden in every mode.
 */
export function hostEscapePaths(
  uid: number | undefined = process.getuid?.(),
): string[] {
  const paths = ["/run/docker.sock", "/var/run/docker.sock", "/run/podman"];
  if (uid !== undefined) paths.push(`/run/user/${uid}`);
  return paths;
}

interface PlanOptions {
  readonly features?: BubblewrapFeatures;
  /** Test seam: path existence check. */
  readonly exists?: (path: string) => boolean;
  /** Test seam: directory check. */
  readonly isDir?: (path: string) => boolean;
  /** Test seam: extra hidden host paths (defaults to hostEscapePaths()). */
  readonly escapePaths?: readonly string[];
}

function byDepth(paths: readonly string[]): string[] {
  return [...paths].sort((a, b) => pathDepth(a) - pathDepth(b));
}

/** Build the bwrap argument vector (without the bwrap executable itself). */
export function bubblewrapArgs(
  profile: SandboxProfile,
  command: SandboxCommand,
  options: PlanOptions = {},
): string[] {
  const features = options.features ?? MODERN_BUBBLEWRAP;
  const exists = options.exists ?? pathExists;
  const isDir = options.isDir ?? isDirectory;
  const tmpRoot = realpathNearest("/tmp");
  const privateTmp = ![...profile.writeAllow, ...profile.readOnly].some(
    (path) => isWithin(tmpRoot, path),
  );
  const protect = writableProtected(profile, posix);
  // A directory bound onto itself is a mount point, which cannot be renamed
  // or removed, so a protected path below it cannot be moved aside.
  const pins = protectedAncestors(profile, protect, posix, exists).filter(
    (path) => exists(path) && isDir(path),
  );
  const binds = byDepth([
    ...new Set([...profile.writeAllow, ...profile.readOnly, ...pins]),
  ]).filter(exists);
  const visible = (path: string) =>
    !privateTmp ||
    !isWithin(path, tmpRoot) ||
    binds.some((bind) => isWithin(path, bind));

  const args = ["--die-with-parent", "--new-session", "--unshare-all"];
  if (features.disableUserns) args.push("--unshare-user", "--disable-userns");
  if (profile.network === "allow") args.push("--share-net");
  args.push("--cap-drop", "ALL");
  args.push("--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc");
  if (privateTmp) args.push("--tmpfs", tmpRoot);
  for (const path of binds)
    args.push(
      profile.writeAllow.includes(path) || pins.includes(path)
        ? "--bind"
        : "--ro-bind",
      path,
      path,
    );
  for (const { path, directory } of protect) {
    if (!visible(path)) continue;
    if (exists(path)) args.push("--ro-bind", path, path);
    // A missing protected directory becomes an empty read-only one, so it
    // cannot be created with content. A missing file cannot be guarded this
    // way: its mount point would be an empty file left on the host.
    else if (directory && isDir(dirname(path)))
      args.push("--tmpfs", path, "--remount-ro", path);
  }

  const escapes = (options.escapePaths ?? hostEscapePaths())
    .map(realpathNearest)
    .filter(
      (path) =>
        !profile.writeAllow.some((w) => isWithin(w, path) || isWithin(path, w)),
    );
  const hidden: string[] = [];
  for (const path of byDepth([...new Set([...profile.readDeny, ...escapes])])) {
    if (!exists(path) || !visible(path)) continue;
    if (hidden.some((dir) => isWithin(path, dir))) continue;
    if (isDir(path)) {
      hidden.push(path);
      if (features.tmpfsPerms) args.push("--perms", "0000");
      args.push("--tmpfs", path, "--remount-ro", path);
    } else {
      args.push("--ro-bind", "/dev/null", path);
    }
  }

  args.push("--clearenv");
  for (const name of Object.keys(command.env).sort())
    args.push("--setenv", name, command.env[name] ?? "");
  args.push("--chdir", command.cwd, "--", command.file, ...command.args);
  return args;
}

const CHECK_BASE = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];

export class BubblewrapAdapter implements SandboxAdapter {
  readonly id = "linux-bubblewrap" as const;
  // A protected path is guarded by mounting over it; a file that does not
  // exist has no mount point that would not leave an empty file on the host.
  readonly guardsMissingFiles = false;
  #executable: string | undefined;
  #features: BubblewrapFeatures = MODERN_BUBBLEWRAP;
  #availability: Promise<AdapterAvailability> | undefined;

  constructor(executable?: string) {
    this.#executable = executable;
  }

  available(): Promise<AdapterAvailability> {
    this.#availability ??= this.#detect();
    return this.#availability;
  }

  async #detect(): Promise<AdapterAvailability> {
    const bwrap = this.#executable ?? findExecutable("bwrap");
    if (!bwrap)
      return {
        available: false,
        reason:
          "bubblewrap (bwrap) was not found on PATH; install the bubblewrap package",
      };
    this.#executable = bwrap;
    const modern = await runCheck(bwrap, [
      "--unshare-all",
      "--unshare-user",
      "--disable-userns",
      "--cap-drop",
      "ALL",
      ...CHECK_BASE,
      "--perms",
      "0000",
      "--tmpfs",
      "/tmp",
      "--",
      "/bin/sh",
      "-c",
      "exit 0",
    ]);
    if (modern.ok) return { available: true };
    const basic = await runCheck(bwrap, [
      "--unshare-all",
      "--cap-drop",
      "ALL",
      ...CHECK_BASE,
      "--",
      "/bin/sh",
      "-c",
      "exit 0",
    ]);
    if (!basic.ok)
      return {
        available: false,
        reason: `bubblewrap cannot create a sandbox (unprivileged user namespaces may be disabled): ${basic.detail}`,
      };
    this.#features = { disableUserns: false, tmpfsPerms: false };
    return { available: true };
  }

  wrap(profile: SandboxProfile, command: SandboxCommand): WrappedCommand {
    if (!this.#executable)
      throw new PiShipError(
        "SANDBOX_UNAVAILABLE",
        "The bubblewrap adapter was used before its availability check",
        { component: "sandbox" },
      );
    return {
      file: this.#executable,
      args: bubblewrapArgs(profile, command, { features: this.#features }),
      cwd: command.cwd,
      env: command.env,
    };
  }
}
