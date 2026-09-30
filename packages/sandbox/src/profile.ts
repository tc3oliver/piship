// Desired sandbox policy (manifest `sandbox:`) resolved into concrete,
// symlink-resolved host paths. Enforcement is the adapter's job.
import { existsSync, realpathSync, statSync } from "node:fs";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  type PlatformPath,
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
  /**
   * The symbolic links on the way to a protected path, as the links
   * themselves (absolute, not resolved). Protection covers what a link points
   * to and nothing can hold the link in place, so a link in a directory the
   * sandbox may write is a path it can retarget: `resolveProfile` turns such
   * a link into `unverified`. Only used as input.
   */
  readonly links?: readonly string[];
  /**
   * Why this list is known to be incomplete (the git config named more
   * paths than are listed, or a protected path is reached through a link the
   * sandbox may replace), when it is. Git control is then reported not
   * verified, for every backend, and the reason is a warning.
   */
  readonly unverified?: string;
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

/** How many links the reason names; the rest are counted. */
const LINKS_NAMED = 3;

/**
 * Why git control cannot be verified for the links among `links` that lie in
 * a path the sandbox may write, or undefined when none does. A link in a
 * directory the sandbox cannot write cannot be retargeted from inside.
 */
function retargetableLinks(
  links: readonly string[],
  writeAllow: readonly string[],
): string | undefined {
  const writable = links.filter((link) => {
    const holder = realpathNearest(dirname(link));
    return writeAllow.some((allowed) => isWithin(holder, allowed));
  });
  if (writable.length === 0) return undefined;
  const named = writable.slice(0, LINKS_NAMED).join(", ");
  const more =
    writable.length > LINKS_NAMED
      ? ` and ${writable.length - LINKS_NAMED} more`
      : "";
  return `a protected git path is reached through a symbolic link in a directory the sandbox may write (${named}${more}); protection covers what a link points to and nothing can hold the link itself in place, so a command could point it at a file of its own`;
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
  const unverified = [
    protect?.unverified,
    retargetableLinks(protect?.links ?? [], writeAllow),
  ]
    .filter((reason) => reason)
    .join("; ");
  return {
    ...base,
    readDeny,
    writeAllow,
    readOnly,
    writeProtect: {
      files: resolveAll(protect?.files ?? [], full),
      directories: resolveAll(protect?.directories ?? [], full),
      ...(unverified ? { unverified } : {}),
    },
    network: config.network.mode,
    environmentAllow: [...new Set(config.environment.allow)],
    warnings: [
      ...conflicts(readDeny, writeAllow, base.workspace),
      ...(unverified ? [`git control is not verified: ${unverified}`] : []),
    ],
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
 * The path semantics protected-path matching uses. A resolved profile holds
 * host-native paths; an adapter that emits a POSIX profile (bubblewrap,
 * Seatbelt) passes `posix`.
 */
export type ProfilePaths = Pick<PlatformPath, "sep" | "dirname">;
const NATIVE_PATHS: ProfilePaths = { sep, dirname };

function within(paths: ProfilePaths, path: string, root: string): boolean {
  if (path === root) return true;
  return path.startsWith(
    root.endsWith(paths.sep) ? root : `${root}${paths.sep}`,
  );
}

const depth = (paths: ProfilePaths, path: string) =>
  path.split(paths.sep).filter(Boolean).length;

export interface ProtectedEntry {
  readonly path: string;
  readonly directory: boolean;
}

/**
 * Protected paths inside a writable path, outermost first; a path under
 * another protected directory is covered by it and left out. Protected
 * paths outside every writable path are read-only already.
 */
export function writableProtected(
  profile: SandboxProfile,
  paths: ProfilePaths = NATIVE_PATHS,
): ProtectedEntry[] {
  const entries = [
    ...profile.writeProtect.files.map((path) => ({ path, directory: false })),
    ...profile.writeProtect.directories.map((path) => ({
      path,
      directory: true,
    })),
  ]
    .filter(({ path }) =>
      profile.writeAllow.some((allowed) => within(paths, path, allowed)),
    )
    .sort((a, b) => depth(paths, a.path) - depth(paths, b.path));
  const kept: ProtectedEntry[] = [];
  for (const entry of entries)
    if (
      !kept.some(
        (outer) =>
          outer.path === entry.path ||
          (outer.directory && within(paths, entry.path, outer.path)),
      )
    )
      kept.push(entry);
  return kept;
}

/**
 * Directories between a writable root and a protected path, outermost
 * first. Their contents stay writable, but renaming or removing one would
 * move the protected path aside and let a replacement take its place. A
 * protected path that does not exist has none: there is nothing to move
 * aside, git control is reported not verified for such a path anyway, and
 * pinning its directories would only stop commands from moving or removing
 * a directory that may hold it later.
 */
export function protectedAncestors(
  profile: SandboxProfile,
  entries: readonly ProtectedEntry[],
  paths: ProfilePaths = NATIVE_PATHS,
  exists: (path: string) => boolean = pathExists,
): string[] {
  const ancestors = new Set<string>();
  for (const { path } of entries) {
    if (!exists(path)) continue;
    const roots = profile.writeAllow.filter((allowed) =>
      within(paths, path, allowed),
    );
    for (
      let current = paths.dirname(path);
      !roots.includes(current) &&
      roots.some((root) => within(paths, current, root));
      current = paths.dirname(current)
    )
      ancestors.add(current);
  }
  return [...ancestors].sort((a, b) => depth(paths, a) - depth(paths, b));
}
