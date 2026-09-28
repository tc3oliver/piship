// Glob matching for policy rules and filesystem resource normalization.
//
// Patterns are anchored and case-sensitive. `*` matches any run of characters
// except `/`, `:`, and line breaks; `**` matches anything, including
// separators. Globs alone do not stop shell chaining (`git *` matches
// `git status; rm -rf ~`); the policy engine refuses to let an allow or ask
// shell rule match a command with shell metacharacters. A trailing
// `/**` also matches the directory itself, and `/**/` also matches a single
// `/`, so `~/.ssh/**` covers `~/.ssh` and `a/**/b` covers `a/b`.
import { lstatSync, readlinkSync, realpathSync, type Stats } from "node:fs";
import { dirname, isAbsolute, join, parse, sep } from "node:path";

const compiled = new Map<string, RegExp>();

function escapeRegExp(text: string): string {
  return text.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}

/** Compile a glob into an anchored regular expression (memoized). */
export function globToRegExp(pattern: string): RegExp {
  const cached = compiled.get(pattern);
  if (cached) return cached;
  let source = "";
  let index = 0;
  while (index < pattern.length) {
    if (pattern.startsWith("/**/", index)) {
      source += "(?:/|/.*/)";
      index += 4;
    } else if (
      pattern.startsWith("/**", index) &&
      index + 3 === pattern.length
    ) {
      source += "(?:/.*)?";
      index += 3;
    } else if (pattern.startsWith("**", index)) {
      source += ".*";
      index += 2;
    } else if (pattern[index] === "*") {
      source += "[^/:\\r\\n]*";
      index += 1;
    } else {
      source += escapeRegExp(pattern[index] ?? "");
      index += 1;
    }
  }
  const regexp = new RegExp(`^${source}$`, "s");
  compiled.set(pattern, regexp);
  return regexp;
}

export function matchGlob(pattern: string, value: string): boolean {
  return globToRegExp(pattern).test(value);
}

/** Match a rule action (`exact`, `prefix.*`, or `*`) against a request action. */
export function matchAction(ruleAction: string, action: string): boolean {
  if (ruleAction === "*" || ruleAction === action) return true;
  if (!ruleAction.endsWith(".*")) return false;
  return action.startsWith(ruleAction.slice(0, -1));
}

export interface PathTokenContext {
  readonly workspaceRoot: string;
  readonly homeDir: string;
  readonly tmpDir: string;
}

function joinToken(base: string, rest: string): string {
  if (rest === "") return base;
  return base.endsWith("/") ? `${base}${rest}` : `${base}/${rest}`;
}

/**
 * Expand the leading `workspace`, `tmp`, and `~` tokens of a rule pattern
 * (bare or followed by `/`). The context paths should already be normalized.
 * Other patterns are returned unchanged.
 */
export function expandPathTokens(
  pattern: string,
  context: PathTokenContext,
): string {
  const tokens: readonly (readonly [string, string])[] = [
    ["workspace", context.workspaceRoot],
    ["tmp", context.tmpDir],
    ["~", context.homeDir],
  ];
  for (const [token, base] of tokens) {
    if (pattern === token) return base;
    if (pattern.startsWith(`${token}/`))
      return joinToken(base, pattern.slice(token.length + 1));
  }
  return pattern;
}

/** Convert a native path to POSIX separators (Windows keeps its drive letter). */
export function toPosixPath(path: string, separator: string = sep): string {
  return separator === "\\" ? path.replace(/\\/g, "/") : path;
}

const MAX_SYMLINK_DEPTH = 40;

function lstatOrUndefined(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

/**
 * Resolve `path` segment by segment with kernel semantics: every existing
 * prefix is realpath'd (so `..` after a symlink walks from its target), a
 * dangling symlink is followed through its link text, and segments after the
 * first missing one are appended lexically.
 */
function resolveSegments(path: string, depth: number): string {
  if (depth > MAX_SYMLINK_DEPTH) return path;
  const { root } = parse(path);
  const segments = path.slice(root.length).split(/[\\/]+/);
  let current = safeRealpath(root) ?? root;
  let existing = true;
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index] ?? "";
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      current = dirname(current);
      continue;
    }
    const next = join(current, segment);
    if (!existing) {
      current = next;
      continue;
    }
    const real = safeRealpath(next);
    if (real !== undefined) {
      current = real;
      continue;
    }
    const stats = lstatOrUndefined(next);
    if (stats?.isSymbolicLink()) {
      const target = readlinkSync(next);
      const absolute = isAbsolute(target) ? target : join(current, target);
      const rest = segments.slice(index + 1).join(sep);
      return resolveSegments(
        rest === "" ? absolute : `${absolute}${sep}${rest}`,
        depth + 1,
      );
    }
    existing = false;
    current = next;
  }
  return current;
}

function safeRealpath(path: string): string | undefined {
  try {
    return realpathSync.native(path);
  } catch {
    return undefined;
  }
}

/**
 * Normalize a filesystem resource: absolute (relative paths resolve against
 * the workspace root), symlink-resolved through the nearest existing ancestor,
 * with POSIX separators.
 */
export function normalizePathResource(
  path: string,
  context: Pick<PathTokenContext, "workspaceRoot">,
): string {
  const absolute = isAbsolute(path)
    ? path
    : `${context.workspaceRoot}${sep}${path}`;
  return toPosixPath(resolveSegments(absolute, 0));
}

/** Normalize the context directories themselves (realpath, POSIX separators). */
export function normalizeTokenContext(
  context: PathTokenContext,
): PathTokenContext {
  const workspaceRoot = normalizePathResource(context.workspaceRoot, {
    workspaceRoot: process.cwd(),
  });
  return {
    workspaceRoot,
    homeDir: normalizePathResource(context.homeDir, { workspaceRoot }),
    tmpDir: normalizePathResource(context.tmpDir, { workspaceRoot }),
  };
}

/** True when `path` equals `root` or lies below it (both normalized POSIX). */
export function isWithin(root: string, path: string): boolean {
  if (path === root) return true;
  const prefix = root.endsWith("/") ? root : `${root}/`;
  return path.startsWith(prefix);
}
