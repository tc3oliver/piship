// Expansion of a Pi package into an explicit resource inventory (spec §8.2
// step 4). It follows Pi 1.0.2's package discovery (`package-manager.js`):
// the `pi` manifest in package.json or the conventional directories, then the
// declaration's object-form filters. At runtime the files enter the governed
// loader lists one by one; Pi never sees the package as a package.
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { packageError } from "./refs.js";
import {
  PACKAGE_RESOURCE_KINDS,
  type PackageFilters,
  type LockedPackageResource,
  type PackageResourceKind,
} from "./types.js";

const FILE_PATTERNS: Record<PackageResourceKind, RegExp> = {
  extensions: /\.(ts|js)$/,
  skills: /\.md$/,
  prompts: /\.md$/,
  themes: /\.json$/,
};
const IGNORE_FILES = [".gitignore", ".ignore", ".fdignore"];

const posix = (path: string) => path.split(sep).join("/");

function escapeRegExp(text: string): string {
  return text.replace(/[.+^$()|\\/]/g, "\\$&");
}

/**
 * A minimatch-compatible subset: `**` spans path segments, `*` and `?` stay
 * within one, `{a,b}` alternates, `[...]` is a class; wildcards never match a
 * leading dot.
 */
export function globToRegExp(pattern: string): RegExp {
  let output = "";
  for (let index = 0; index < pattern.length; index++) {
    const char = pattern[index] as string;
    if (char === "*" && pattern[index + 1] === "*") {
      const slash = pattern[index + 2] === "/";
      output += slash ? "(?:(?!\\.)[^/]*/)*" : "(?:(?!\\.)[^/]*(?:/|$))*";
      index += slash ? 2 : 1;
    } else if (char === "*") output += "(?!\\.)[^/]*";
    else if (char === "?") output += "[^/]";
    else if (char === "{") {
      const end = pattern.indexOf("}", index);
      if (end === -1) output += "\\{";
      else {
        output += `(?:${pattern
          .slice(index + 1, end)
          .split(",")
          .map((part) => globToRegExp(part).source.slice(1, -1))
          .join("|")})`;
        index = end;
      }
    } else if (char === "[") {
      const end = pattern.indexOf("]", index + 1);
      if (end === -1) output += "\\[";
      else {
        output += `[${pattern.slice(index + 1, end).replace(/^!/, "^")}]`;
        index = end;
      }
    } else output += escapeRegExp(char);
  }
  return new RegExp(`^${output}$`);
}

function matches(path: string, pattern: string): boolean {
  return globToRegExp(pattern.replace(/^\.\//, "")).test(path);
}

class Expander {
  constructor(
    private readonly id: string,
    private readonly root: string,
  ) {}

  private rel(path: string): string {
    return posix(relative(this.root, path));
  }

  private entries(dir: string) {
    for (const name of IGNORE_FILES)
      if (existsSync(join(dir, name)))
        throw packageError(
          "CONFIG_INVALID",
          this.id,
          `${this.rel(join(dir, name)) || name} narrows Pi resource discovery, which PiShip does not reproduce; list the resources in the package.json pi manifest instead`,
        );
    return readdirSync(dir, { withFileTypes: true })
      .filter((entry) => !entry.name.startsWith("."))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }

  private files(dir: string, pattern: RegExp): string[] {
    const output: string[] = [];
    for (const entry of this.entries(dir)) {
      if (entry.name === "node_modules") continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) output.push(...this.files(path, pattern));
      else if (entry.isFile() && pattern.test(entry.name)) output.push(path);
    }
    return output;
  }

  /** Pi's `collectSkillEntries(dir, "pi")`. */
  private skills(dir: string, top: string): string[] {
    const entries = this.entries(dir);
    const skill = entries.find(
      (entry) => entry.name === "SKILL.md" && entry.isFile(),
    );
    if (skill) return [join(dir, skill.name)];
    const output: string[] = [];
    for (const entry of entries) {
      if (entry.name === "node_modules") continue;
      const path = join(dir, entry.name);
      if (entry.isFile() && entry.name.endsWith(".md") && dir === top)
        output.push(path);
      else if (entry.isDirectory()) output.push(...this.skills(path, top));
    }
    return output;
  }

  private manifestExtensions(dir: string): string[] | null {
    const manifest = readPiManifest(join(dir, "package.json"));
    const listed = (manifest?.extensions ?? [])
      .map((entry) => resolve(dir, entry))
      .filter((path) => existsSync(path));
    if (listed.length) return listed;
    for (const index of ["index.ts", "index.js"])
      if (existsSync(join(dir, index))) return [join(dir, index)];
    return null;
  }

  /** Pi's `collectAutoExtensionEntries`. */
  private extensions(dir: string): string[] {
    const own = this.manifestExtensions(dir);
    if (own) return own;
    const output: string[] = [];
    for (const entry of this.entries(dir)) {
      if (entry.name === "node_modules") continue;
      const path = join(dir, entry.name);
      if (entry.isFile() && /\.(ts|js)$/.test(entry.name)) output.push(path);
      else if (entry.isDirectory())
        output.push(...(this.manifestExtensions(path) ?? []));
    }
    return output;
  }

  collect(dir: string, kind: PackageResourceKind): string[] {
    if (!existsSync(dir)) return [];
    if (kind === "skills") return this.skills(dir, dir);
    if (kind === "extensions") return this.extensions(dir);
    return this.files(dir, FILE_PATTERNS[kind]);
  }

  private fromPaths(paths: string[], kind: PackageResourceKind): string[] {
    return paths.flatMap((path) => {
      if (!existsSync(path)) return [];
      const stat = statSync(path);
      if (stat.isFile()) return [path];
      return stat.isDirectory() ? this.collect(path, kind) : [];
    });
  }

  /** Every file and directory under the root without a dot segment. */
  private tree(dir = this.root, output: string[] = []): string[] {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith(".")) continue;
      const path = join(dir, entry.name);
      output.push(path);
      if (entry.isDirectory()) this.tree(path, output);
    }
    return output;
  }

  /** Pi's `collectFilesFromManifestEntries`: plain paths and glob expansions. */
  fromManifestEntries(
    entries: readonly string[],
    kind: PackageResourceKind,
  ): string[] {
    const sources = entries.filter((entry) => !isOverride(entry));
    let tree: string[] | undefined;
    const resolved = sources.flatMap((entry) => {
      if (!/[*?]/.test(entry)) return [resolve(this.root, entry)];
      tree ??= this.tree();
      return tree.filter((path) => matches(this.rel(path), entry)).sort();
    });
    return this.fromPaths(resolved, kind);
  }

  matchesAny(path: string, patterns: readonly string[]): boolean {
    const rel = this.rel(path);
    const name = basename(path);
    const skill = name === "SKILL.md";
    return patterns.some(
      (pattern) =>
        matches(rel, pattern) ||
        matches(name, pattern) ||
        (skill &&
          (matches(this.rel(dirname(path)), pattern) ||
            matches(basename(dirname(path)), pattern))),
    );
  }

  matchesExact(path: string, patterns: readonly string[]): boolean {
    const rel = this.rel(path);
    const parent =
      basename(path) === "SKILL.md" ? this.rel(dirname(path)) : undefined;
    return patterns.some((pattern) => {
      const exact = posix(pattern.replace(/^\.[\\/]/, ""));
      return exact === rel || exact === parent;
    });
  }

  /** Pi's `applyPatterns`: includes, then `!` excludes, `+` force-includes, `-` force-excludes. */
  apply(paths: string[], patterns: readonly string[]): Set<string> {
    const pick = (prefix: string) =>
      patterns
        .filter((pattern) => pattern.startsWith(prefix))
        .map((pattern) => pattern.slice(1));
    const includes = patterns.filter((pattern) => !isOverride(pattern));
    const excludes = pick("!");
    const forceIncludes = pick("+");
    const forceExcludes = pick("-");
    let result = includes.length
      ? paths.filter((path) => this.matchesAny(path, includes))
      : [...paths];
    if (excludes.length)
      result = result.filter((path) => !this.matchesAny(path, excludes));
    for (const path of paths)
      if (!result.includes(path) && this.matchesExact(path, forceIncludes))
        result.push(path);
    if (forceExcludes.length)
      result = result.filter((path) => !this.matchesExact(path, forceExcludes));
    return new Set(result);
  }
}

function isOverride(entry: string): boolean {
  return (
    entry.startsWith("!") || entry.startsWith("+") || entry.startsWith("-")
  );
}

type PiManifest = Partial<Record<PackageResourceKind, string[]>>;

/** Pi's `readPiManifest`: string arrays under `pi` in package.json, or null. */
function readPiManifest(file: string): PiManifest | null {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(file, "utf8").replace(/^﻿/, ""));
  } catch {
    return null;
  }
  const pi = (value as { pi?: unknown } | null)?.pi;
  if (!pi || typeof pi !== "object" || Array.isArray(pi)) return null;
  const manifest: PiManifest = {};
  for (const kind of PACKAGE_RESOURCE_KINDS) {
    const entries = (pi as Record<string, unknown>)[kind];
    if (
      Array.isArray(entries) &&
      entries.every((entry) => typeof entry === "string")
    )
      manifest[kind] = entries as string[];
  }
  return manifest;
}

function hasFilters(filters: PackageFilters): boolean {
  return PACKAGE_RESOURCE_KINDS.some((kind) => filters[kind] !== undefined);
}

/**
 * The files Pi would enable for this package and these filters, relative to
 * the package root, each with its sha256. A resource that resolves outside
 * the package root or through a symlink is refused.
 */
export function expandPackageResources(
  id: string,
  packageRoot: string,
  filters: PackageFilters,
): LockedPackageResource[] {
  const root = resolve(packageRoot);
  const expander = new Expander(id, root);
  const manifest = readPiManifest(join(root, "package.json"));
  const enabled = new Map<string, PackageResourceKind>();
  const add = (kind: PackageResourceKind, paths: Iterable<string>) => {
    for (const path of paths) if (!enabled.has(path)) enabled.set(path, kind);
  };
  const manifestEntries = (kind: PackageResourceKind, entries: string[]) => {
    const all = expander.fromManifestEntries(entries, kind);
    add(kind, expander.apply(all, entries.filter(isOverride)));
  };
  for (const kind of PACKAGE_RESOURCE_KINDS) {
    const entries = manifest?.[kind];
    if (!hasFilters(filters)) {
      // Pi without a filter: the manifest alone when there is one, else the
      // conventional directories.
      if (manifest) {
        if (entries) manifestEntries(kind, entries);
      } else add(kind, expander.collect(join(root, kind), kind));
      continue;
    }
    const patterns = filters[kind];
    if (patterns === undefined) {
      if (entries) manifestEntries(kind, entries);
      else add(kind, expander.collect(join(root, kind), kind));
      continue;
    }
    if (patterns.length === 0) continue;
    // Pi's `collectManifestFiles`: what the package allows, then the filter.
    const allowed = entries?.length
      ? [
          ...expander.apply(
            expander.fromManifestEntries(entries, kind),
            entries.filter(isOverride),
          ),
        ]
      : expander.collect(join(root, kind), kind);
    add(kind, expander.apply(allowed, patterns));
  }
  const resources: LockedPackageResource[] = [];
  for (const [path, kind] of enabled) {
    const rel = posix(relative(root, path));
    if (!rel || rel.startsWith("../") || rel === "..")
      throw packageError(
        "POLICY_DENIED",
        id,
        `${kind} entry resolves outside the package root`,
      );
    for (let current = path; current !== root; current = dirname(current))
      if (lstatSync(current).isSymbolicLink())
        throw packageError(
          "POLICY_DENIED",
          id,
          `${kind} ${rel} is reached through a symlink`,
        );
    resources.push({
      kind,
      path: rel,
      sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
    });
  }
  return resources.sort(
    (a, b) =>
      PACKAGE_RESOURCE_KINDS.indexOf(a.kind) -
        PACKAGE_RESOURCE_KINDS.indexOf(b.kind) ||
      (a.path < b.path ? -1 : a.path > b.path ? 1 : 0),
  );
}
