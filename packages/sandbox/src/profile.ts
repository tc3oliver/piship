// Desired sandbox policy (manifest `sandbox:`) resolved into concrete,
// symlink-resolved host paths. Enforcement is the adapter's job.
import { existsSync, realpathSync, statSync } from "node:fs";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  posix,
  resolve,
  sep,
} from "node:path";
import { PiShipError } from "@piship/contracts";

/** Structurally identical to `SandboxConfig` in @piship/schema. */
export interface SandboxPolicy {
  readonly required: boolean;
  readonly filesystem: {
    readonly read: { readonly deny: readonly string[] };
    readonly write: { readonly allow: readonly string[] };
  };
  readonly network: { readonly mode: "deny" | "allow" };
  readonly environment: { readonly allow: readonly string[] };
}

export interface ProfileContext {
  /** Project root; the `workspace` token. */
  readonly workspace: string;
  /** Home directory; the `~` token. */
  readonly homeDir: string;
  /** Private per-session temp directory; the `tmp` token. */
  readonly tmpDir: string;
  /** Additional writable paths (absolute), e.g. a Pi session directory. */
  readonly extraWritable?: readonly string[];
  /** Paths that must stay readable even when an adapter hides a parent (e.g. host /tmp). */
  readonly extraReadOnly?: readonly string[];
  /** Paths tools may never change, even inside a writable path. */
  readonly protectedPaths?: ProtectedPaths;
}

/**
 * Paths kept read-only inside writable ones, such as the git files that
 * classify a project and the git hooks that run outside the sandbox.
 * `directories` are protected as whole trees, also while they are missing.
 */
export interface ProtectedPaths {
  readonly files: readonly string[];
  readonly directories: readonly string[];
}

export interface SandboxProfile {
  readonly workspace: string;
  readonly homeDir: string;
  readonly tmpDir: string;
  /** Absolute, realpath'd paths whose contents must not be readable (or writable). */
  readonly readDeny: readonly string[];
  /** Absolute, realpath'd paths that may be written. Everything else is read-only. */
  readonly writeAllow: readonly string[];
  /** Absolute, realpath'd paths kept readable when a parent is hidden. */
  readonly readOnly: readonly string[];
  /** Absolute, realpath'd paths that stay read-only inside a writable path. */
  readonly writeProtect: ProtectedPaths;
  readonly network: "deny" | "allow";
  /** Environment variable names passed into sandboxed processes. */
  readonly environmentAllow: readonly string[];
  /** Configuration conflicts worth surfacing (deny always wins). */
  readonly warnings: readonly string[];
}

/** Resolve a path through its nearest existing ancestor so symlinks cannot redirect a rule. */
export function realpathNearest(path: string): string {
  const absolute = resolve(path);
  const rest: string[] = [];
  let current = absolute;
  for (;;) {
    try {
      const real = realpathSync.native(current);
      return rest.length ? join(real, ...rest.reverse()) : real;
    } catch {
      const parent = dirname(current);
      if (parent === current) return absolute;
      rest.push(basename(current));
      current = parent;
    }
  }
}

/** True when `path` equals `root` or lies below it. Both must be normalized. */
export function isWithin(path: string, root: string): boolean {
  if (path === root) return true;
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
  return path.startsWith(prefix);
}

function underToken(token: string, value: string): string | undefined {
  if (value === token) return "";
  if (value.startsWith(`${token}/`)) return value.slice(token.length + 1);
  return undefined;
}

/** Expand `workspace`, `tmp`, `~`, `~/x`, or an absolute path to an absolute path. */
export function expandPathToken(
  value: string,
  ctx: Pick<ProfileContext, "workspace" | "homeDir" | "tmpDir">,
): string {
  const bases: readonly [string, string][] = [
    ["workspace", ctx.workspace],
    ["tmp", ctx.tmpDir],
    ["~", ctx.homeDir],
  ];
  for (const [token, base] of bases) {
    const rest = underToken(token, value);
    if (rest !== undefined) return rest ? join(base, rest) : base;
  }
  if (isAbsolute(value)) return value;
  throw new PiShipError(
    "CONFIG_INVALID",
    `Sandbox path "${value}" must be absolute or start with workspace, tmp, or ~`,
    { component: "sandbox" },
  );
}

function resolveAll(
  values: readonly string[],
  ctx: ProfileContext,
): readonly string[] {
  const output: string[] = [];
  for (const value of values) {
    const path = realpathNearest(expandPathToken(value, ctx));
    if (!output.includes(path)) output.push(path);
  }
  return output;
}

function conflicts(
  deny: readonly string[],
  writable: readonly string[],
  workspace: string,
): string[] {
  const warnings: string[] = [];
  for (const denied of deny)
    for (const path of [workspace, ...writable])
      if (isWithin(path, denied))
        warnings.push(
          `${path} is inside the read-denied path ${denied}; deny wins and it is hidden in the sandbox`,
        );
  return [...new Set(warnings)];
}

export function resolveProfile(
  config: SandboxPolicy,
  ctx: ProfileContext,
): SandboxProfile {
  const base = {
    workspace: realpathNearest(ctx.workspace),
    homeDir: realpathNearest(ctx.homeDir),
    tmpDir: realpathNearest(ctx.tmpDir),
  };
  const full = { ...ctx, ...base };
  const readDeny = resolveAll(config.filesystem.read.deny, full);
  const writeAllow = resolveAll(
    [...config.filesystem.write.allow, ...(ctx.extraWritable ?? [])],
    full,
  );
  const readOnly = resolveAll(ctx.extraReadOnly ?? [], full).filter(
    (path) => !writeAllow.includes(path),
  );
  const protect = ctx.protectedPaths;
  return {
    ...base,
    readDeny,
    writeAllow,
    readOnly,
    writeProtect: {
      files: resolveAll(protect?.files ?? [], full),
      directories: resolveAll(protect?.directories ?? [], full),
    },
    network: config.network.mode,
    environmentAllow: [...new Set(config.environment.allow)],
    warnings: conflicts(readDeny, writeAllow, base.workspace),
  };
}

/** Whether a resolved path is an existing directory (false for files and missing paths). */
export function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

export function pathExists(path: string): boolean {
  return existsSync(path);
}

/** Number of path segments, used to order mounts from outermost to innermost. */
export function pathDepth(path: string): number {
  return path.split(sep).filter(Boolean).length;
}

/**
 * Containment for adapter profiles, whose paths are always POSIX (bubblewrap
 * and Seatbelt run only on Linux and macOS), whatever the host running the
 * profile builder.
 */
function withinPosix(path: string, root: string): boolean {
  if (path === root) return true;
  return path.startsWith(root.endsWith("/") ? root : `${root}/`);
}

const posixDepth = (path: string) => path.split("/").filter(Boolean).length;

export interface ProtectedEntry {
  readonly path: string;
  readonly directory: boolean;
}

/**
 * Protected paths inside a writable path, outermost first; a path under
 * another protected directory is covered by it and left out. Protected
 * paths outside every writable path are read-only already.
 */
export function writableProtected(profile: SandboxProfile): ProtectedEntry[] {
  const entries = [
    ...profile.writeProtect.files.map((path) => ({ path, directory: false })),
    ...profile.writeProtect.directories.map((path) => ({
      path,
      directory: true,
    })),
  ]
    .filter(({ path }) =>
      profile.writeAllow.some((allowed) => withinPosix(path, allowed)),
    )
    .sort((a, b) => posixDepth(a.path) - posixDepth(b.path));
  const kept: ProtectedEntry[] = [];
  for (const entry of entries)
    if (
      !kept.some(
        (outer) =>
          outer.path === entry.path ||
          (outer.directory && withinPosix(entry.path, outer.path)),
      )
    )
      kept.push(entry);
  return kept;
}

/**
 * Directories between a writable root and a protected path, outermost
 * first. Their contents stay writable, but renaming or removing one would
 * move the protected path aside and let a replacement take its place.
 */
export function protectedAncestors(
  profile: SandboxProfile,
  entries: readonly ProtectedEntry[],
): string[] {
  const ancestors = new Set<string>();
  for (const { path } of entries) {
    const roots = profile.writeAllow.filter((allowed) =>
      withinPosix(path, allowed),
    );
    for (
      let current = posix.dirname(path);
      !roots.includes(current) &&
      roots.some((root) => withinPosix(current, root));
      current = posix.dirname(current)
    )
      ancestors.add(current);
  }
  return [...ancestors].sort((a, b) => posixDepth(a) - posixDepth(b));
}
