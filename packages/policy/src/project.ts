// Project identity, origin classification, and project resource discovery.
// No git binary is executed: the origin remote is read from the git config.
import { type Dirent, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { PiShipError, redact } from "@piship/contracts";
import type {
  PolicyConfig,
  ProjectDimensionEffect,
  ProjectMatcher,
  ProjectTrustDimension,
  ProjectTrustPolicy,
} from "@piship/schema";
import { parseRuleList, type ParsedRuleList } from "./engine.js";
import {
  expandPathTokens,
  isWithin,
  matchGlob,
  normalizePathResource,
} from "./glob.js";
import { projectEffectReason, type ProjectOrigin } from "./trust.js";

export interface ProjectIdentity {
  /** Realpath'd project root (POSIX separators). */
  readonly root: string;
  /** Normalized origin remote `host/path`, when one is configured. */
  readonly remote?: string;
  readonly origin: ProjectOrigin;
  /** The matcher that classified the project. */
  readonly matchedBy?: ProjectMatcher;
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function readText(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

function real(path: string): string {
  return normalizePathResource(path, { workspaceRoot: process.cwd() });
}

/** Locate the git directory of `dir`, following a `.git` file's `gitdir:`. */
function gitDirectory(dir: string): string | undefined {
  const dotGit = join(dir, ".git");
  if (isDirectory(dotGit)) return real(dotGit);
  if (!isFile(dotGit)) return undefined;
  const match = /^gitdir:\s*(.+?)\s*$/m.exec(readText(dotGit) ?? "");
  if (!match?.[1]) return undefined;
  const target = isAbsolute(match[1]) ? match[1] : resolve(dir, match[1]);
  return real(target);
}

function findProjectRoot(
  start: string,
): { root: string; gitDir?: string } | undefined {
  let current = start;
  for (;;) {
    if (isDirectory(join(current, ".git")) || isFile(join(current, ".git"))) {
      const gitDir = gitDirectory(current);
      return gitDir ? { root: current, gitDir } : { root: current };
    }
    const parent = dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

function unquote(value: string): string {
  const trimmed = value.trim();
  const quoted = /^"((?:[^"\\]|\\.)*)"/.exec(trimmed);
  if (quoted) return (quoted[1] ?? "").replace(/\\(["\\])/g, "$1");
  // Drop a trailing comment: whitespace followed by `#` or `;`.
  for (let index = 1; index < trimmed.length; index += 1) {
    const char = trimmed[index];
    if ((char === "#" || char === ";") && /\s/.test(trimmed[index - 1] ?? ""))
      return trimmed.slice(0, index).trim();
  }
  return trimmed;
}

/** Read `[remote "origin"] url` from git config text. */
export function parseOriginUrl(config: string): string | undefined {
  let inOrigin = false;
  for (const raw of config.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const section =
      /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]/.exec(line);
    if (section) {
      inOrigin =
        section[1]?.toLowerCase() === "remote" && section[2] === "origin";
      continue;
    }
    if (!inOrigin) continue;
    const equals = line.indexOf("=");
    if (equals < 0) continue;
    const key = line.slice(0, equals).trim();
    if (/^[A-Za-z][A-Za-z0-9-]*$/.test(key) && key.toLowerCase() === "url")
      return unquote(line.slice(equals + 1));
  }
  return undefined;
}

/**
 * Normalize a remote URL to `host/path`: strip the scheme, user info, port,
 * and trailing `.git`; convert scp-like `user@host:path`; lowercase the host.
 * Local paths and `file:` URLs have no host and return undefined.
 */
export function normalizeRemote(url: string): string | undefined {
  const value = url.trim();
  let host: string;
  let path: string;
  const separator = value.indexOf("://");
  const schemeName = separator > 0 ? value.slice(0, separator) : "";
  if (/^[A-Za-z][A-Za-z0-9+.-]*$/.test(schemeName)) {
    if (schemeName.toLowerCase() === "file") return undefined;
    const rest = value.slice(separator + 3);
    const slash = rest.indexOf("/");
    const authority = slash < 0 ? rest : rest.slice(0, slash);
    const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
    host = hostPort.startsWith("[")
      ? hostPort.slice(0, hostPort.indexOf("]") + 1)
      : (hostPort.split(":")[0] ?? "");
    path = slash < 0 ? "" : rest.slice(slash);
  } else {
    // scp-like `[user@]host:path`, parsed without a backtracking pattern.
    const colon = value.indexOf(":");
    const head = colon > 0 ? value.slice(0, colon) : "";
    const tail = value.slice(colon + 1);
    if (!head || head.includes("/") || tail.startsWith("//")) return undefined;
    const at = head.indexOf("@");
    host = at > 0 ? head.slice(at + 1) : head;
    // A single letter is a Windows drive, not a host.
    if (!host || /^[A-Za-z]$/.test(host)) return undefined;
    path = tail;
  }
  host = host.toLowerCase();
  if (host === "") return undefined;
  path = trimSlashes(path);
  if (path.endsWith(".git")) path = trimSlashes(path.slice(0, -4));
  return path === "" ? host : `${host}/${path}`;
}

/** Remove leading and trailing `/` without a backtracking regular expression. */
function trimSlashes(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && value[start] === "/") start += 1;
  while (end > start && value[end - 1] === "/") end -= 1;
  return value.slice(start, end);
}

/** The shared git directory a worktree's `commondir` names, or `gitDir` itself. */
function commonDirectory(gitDir: string): string {
  const commondir = readText(join(gitDir, "commondir"))?.trim();
  if (!commondir) return gitDir;
  return isAbsolute(commondir) ? commondir : resolve(gitDir, commondir);
}

function gitConfigPath(gitDir: string): string {
  return join(commonDirectory(gitDir), "config");
}

/**
 * The git files that decide how `root` is classified or what git runs: the
 * `.git` entry itself (a `gitdir:` pointer when it is a file), the git
 * directory's `config`, `config.worktree`, and `commondir`, the shared
 * `config` a worktree points to, and the files those configs include
 * (`include.path`, `includeIf.*.path`), whether or not they exist yet. Also
 * the user's global config files, and what they include, when they lie
 * inside the project. Rewriting any of them could change the origin remote a
 * later launch reads or the commands git runs. Paths are normalized
 * (symlink-resolved, POSIX separators).
 */
export function projectGitControlFiles(root: string): string[] {
  const dotGit = join(root, ".git");
  const files = [real(dotGit), real(join(dotGit, "config"))];
  const gitDir = gitDirectory(root);
  if (gitDir) {
    files.push(
      real(join(gitDir, "config")),
      real(join(gitDir, "config.worktree")),
      real(join(gitDir, "commondir")),
      real(gitConfigPath(gitDir)),
    );
  }
  files.push(...scanGitConfigs(repositoryConfigs(root, gitDir)).included);
  // The global config is the user's, not the project's: only a file inside
  // the project (the home directory holding a repository, an include into
  // the working tree) is one the sandbox could write.
  const project = real(root);
  const globals = globalConfigs();
  files.push(
    ...[...globals.map(real), ...scanGitConfigs(globals).included].filter(
      (path) => isWithin(project, path),
    ),
  );
  return [...new Set(files)];
}

/** A git config file larger than this is not read; real ones are a few lines. */
const MAX_CONFIG_BYTES = 1024 * 1024;
/** How deep git follows includes: it refuses a deeper chain itself. */
const MAX_INCLUDE_DEPTH = 10;

interface ConfigEntry {
  readonly section: string;
  readonly subsection: string | undefined;
  readonly key: string;
  readonly value: string;
}

/** The `key = value` entries of git config text, with their section names lowercased. */
function configEntries(config: string): ConfigEntry[] {
  const entries: ConfigEntry[] = [];
  let section: string | undefined;
  let subsection: string | undefined;
  for (const raw of config.split(/\r?\n/)) {
    let line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const header =
      /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]/.exec(line);
    if (header) {
      section = header[1]?.toLowerCase();
      subsection = header[2];
      // `[core] hooksPath = x` on one line.
      line = line.slice(header[0].length).trim();
      if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    }
    if (section === undefined) continue;
    const equals = line.indexOf("=");
    if (equals < 0) continue;
    const key = line.slice(0, equals).trim().toLowerCase();
    if (!/^[a-z][a-z0-9-]*$/.test(key)) continue;
    entries.push({
      section,
      subsection,
      key,
      value: unquote(line.slice(equals + 1)),
    });
  }
  return entries;
}

/**
 * The values of `core.hooksPath` in git config text. Git uses the last one;
 * every value is returned, so a later override cannot take a directory out of
 * the protected set.
 */
export function parseHooksPaths(config: string): string[] {
  return configEntries(config)
    .filter(
      (entry) =>
        entry.section === "core" &&
        entry.subsection === undefined &&
        entry.key === "hookspath" &&
        entry.value !== "",
    )
    .map((entry) => entry.value);
}

/**
 * The paths of `[include] path` and `[includeIf "<condition>"] path` entries
 * in git config text, every one whatever its condition, so that a condition
 * that is false today cannot hide a file.
 */
export function parseConfigIncludes(config: string): string[] {
  return configEntries(config)
    .filter(
      (entry) =>
        entry.key === "path" &&
        entry.value !== "" &&
        ((entry.section === "include" && entry.subsection === undefined) ||
          (entry.section === "includeif" && entry.subsection !== undefined)),
    )
    .map((entry) => entry.value);
}

/** The repository's own config files: `.git/config`, the git directory's, and the shared one's. */
function repositoryConfigs(root: string, gitDir: string | undefined): string[] {
  const configs = [join(root, ".git", "config")];
  if (gitDir) {
    const common = commonDirectory(gitDir);
    configs.push(
      join(gitDir, "config"),
      join(gitDir, "config.worktree"),
      join(common, "config"),
      join(common, "config.worktree"),
    );
  }
  return [...new Set(configs)];
}

/**
 * The user's global git config files, the only two places outside the
 * repository git reads for a user: `~/.gitconfig` and
 * `$XDG_CONFIG_HOME/git/config` (`~/.config/git/config` by default).
 */
function globalConfigs(): string[] {
  const home = homedir();
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg && isAbsolute(xdg) ? xdg : join(home, ".config");
  return [join(home, ".gitconfig"), join(base, "git", "config")];
}

function readConfig(path: string): string | undefined {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > MAX_CONFIG_BYTES) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * Read git config files and follow their includes: a path is taken from the
 * including file's directory, `~/` is the home directory. Only the files
 * named by the given configs and, transitively, by their includes are read,
 * each once (a cycle ends there) and no deeper than git itself follows.
 * Returns every `core.hooksPath` value seen, raw, and the include targets
 * as normalized paths, whether or not they exist.
 */
function scanGitConfigs(configs: readonly string[]): {
  readonly hooksPaths: string[];
  readonly included: string[];
} {
  const seen = new Set<string>();
  const hooksPaths: string[] = [];
  const included: string[] = [];
  const visit = (file: string, depth: number): void => {
    const key = real(file);
    if (seen.has(key)) return;
    seen.add(key);
    const text = readConfig(file);
    if (text === undefined) return;
    hooksPaths.push(...parseHooksPaths(text));
    if (depth >= MAX_INCLUDE_DEPTH) return;
    for (const value of parseConfigIncludes(text)) {
      const target = value.startsWith("~/")
        ? join(homedir(), value.slice(2))
        : resolve(dirname(file), value);
      included.push(real(target));
      visit(target, depth + 1);
    }
  };
  for (const config of configs) visit(config, 0);
  return { hooksPaths, included };
}

/**
 * The directories `core.hooksPath` names in the repository's git config, the
 * user's global config, and what they include. A relative path is taken from
 * the project root, where git runs hooks, whichever file sets it (a global
 * `.githooks` lands in every working tree); `~/` is the home directory. A
 * path that holds the project root itself cannot be a read-only tree without
 * making the whole project read-only, so it is left out.
 */
function hooksPathDirectories(
  root: string,
  gitDir: string | undefined,
): string[] {
  const project = real(root);
  const directories: string[] = [];
  const values = [
    ...scanGitConfigs(repositoryConfigs(root, gitDir)).hooksPaths,
    ...scanGitConfigs(globalConfigs()).hooksPaths,
  ];
  for (const value of values) {
    const path = value.startsWith("~/")
      ? join(homedir(), value.slice(2))
      : isAbsolute(value)
        ? value
        : resolve(root, value);
    const directory = real(path);
    if (!isWithin(directory, project)) directories.push(directory);
  }
  return directories;
}

/**
 * The git directories whose contents git runs or trusts on the user's
 * behalf, protected as whole trees whether or not they exist yet:
 * - `hooks` (run by the user's next git command, outside any sandbox) and
 *   `info` (attributes and excludes);
 * - `modules` (the git directories of submodules, which `git status` enters:
 *   each has its own `config`, `hooks`, and `info`) and `worktrees` (the
 *   administrative directories of linked worktrees, each with its own
 *   `commondir`, `gitdir`, and `config.worktree`);
 * of the `.git` directory, of the git directory a `.git` file points to, and
 * of the shared directory a worktree names. Also the directory
 * `core.hooksPath` names in those configs, which may lie in the working tree
 * (husky's `.husky/_`).
 * Paths are normalized (symlink-resolved, POSIX separators).
 */
export function projectGitControlDirectories(root: string): string[] {
  const bases = [join(root, ".git")];
  const gitDir = gitDirectory(root);
  if (gitDir) bases.push(gitDir, commonDirectory(gitDir));
  const directories = [
    ...bases.flatMap((base) =>
      ["hooks", "info", "modules", "worktrees"].map((name) =>
        real(join(base, name)),
      ),
    ),
    ...hooksPathDirectories(root, gitDir),
  ];
  return [...new Set(directories)];
}

function matcherMatches(
  matcher: ProjectMatcher,
  root: string,
  remote: string | undefined,
  homeDir: string | undefined,
): boolean {
  if (matcher.remote === undefined && matcher.path === undefined) return false;
  if (
    matcher.remote !== undefined &&
    (remote === undefined || !matchGlob(matcher.remote, remote))
  )
    return false;
  if (matcher.path !== undefined) {
    const pattern =
      homeDir === undefined
        ? matcher.path
        : expandPathTokens(matcher.path, {
            workspaceRoot: root,
            homeDir: real(homeDir),
            tmpDir: root,
          });
    if (!matchGlob(pattern, root)) return false;
  }
  return true;
}

/**
 * Classify a project root. A matcher with both `remote` and `path` needs
 * both to match. Company matchers are checked before external ones.
 */
export function classifyProject(
  root: string,
  remote: string | undefined,
  projectTrust: ProjectTrustPolicy,
  options: { readonly homeDir?: string } = {},
): { origin: ProjectOrigin; matchedBy?: ProjectMatcher } {
  for (const origin of ["company", "external"] as const) {
    const matchedBy = projectTrust[origin].match.find((matcher) =>
      matcherMatches(matcher, root, remote, options.homeDir),
    );
    if (matchedBy) return { origin, matchedBy };
  }
  return { origin: "unknown" };
}

/** Identify the project containing `cwd` and classify its origin. */
export function identifyProject(
  cwd: string,
  projectTrust: ProjectTrustPolicy,
  options: { readonly homeDir?: string } = {},
): ProjectIdentity {
  const start = real(cwd);
  const found = findProjectRoot(start);
  const root = found?.root ?? start;
  let remote: string | undefined;
  if (found?.gitDir) {
    const url = parseOriginUrl(readText(gitConfigPath(found.gitDir)) ?? "");
    remote = url === undefined ? undefined : normalizeRemote(url);
  }
  const { origin, matchedBy } = classifyProject(
    root,
    remote,
    projectTrust,
    options,
  );
  return {
    root,
    ...(remote === undefined ? {} : { remote }),
    origin,
    ...(matchedBy ? { matchedBy } : {}),
  };
}

const RESOURCE_DIMENSIONS: ReadonlySet<ProjectTrustDimension> = new Set([
  "passiveContext",
  "instructions",
  "skills",
  "extensions",
]);

/** Dimensions whose project items are executable code or start processes. */
export const EXECUTABLE_DIMENSIONS: ReadonlySet<ProjectTrustDimension> =
  new Set(["skills", "agents", "hooks", "extensions", "mcp", "providers"]);

/**
 * The effect of a project trust dimension for an identified project.
 * `resourceTrust.project: deny` denies every dimension; `allow` allows the
 * Pi resource dimensions (passive context, instructions, skills, extensions)
 * while agents, hooks, MCP, and providers still follow `projectTrust`.
 */
export function projectDimensionEffect(
  policy: Pick<PolicyConfig, "resourceTrust" | "projectTrust">,
  identity: Pick<ProjectIdentity, "origin">,
  dimension: ProjectTrustDimension,
): ProjectDimensionEffect {
  const setting = policy.resourceTrust.project;
  if (setting === "deny") return "deny";
  if (setting === "allow" && RESOURCE_DIMENSIONS.has(dimension)) return "allow";
  return policy.projectTrust[identity.origin].dimensions[dimension];
}

// --------------------------------------------------------------- discovery

export type ProjectResourceKind =
  | "instructions"
  | "instruction-import"
  | "system-prompt"
  | "prompts"
  | "skills"
  | "extensions"
  | "settings"
  | "themes"
  | "agents"
  | "mcp"
  | "providers"
  | "restrictions";

export interface ProjectResourceCandidate {
  /** `restrictions` is the narrowing-only project policy file. */
  readonly dimension: ProjectTrustDimension | "restrictions";
  readonly kind: ProjectResourceKind;
  /** Path inside the project root (POSIX, not symlink-resolved). */
  readonly path: string;
  /** Realpath of the candidate. */
  readonly resolvedPath: string;
  /** The origin the candidate was evaluated as (`unknown` when it escapes the root). */
  readonly origin: ProjectOrigin;
  readonly effect: ProjectDimensionEffect;
  readonly reason: string;
  /** For `company-approved` MCP: only distribution-allowlisted server ids may start. */
  readonly allowlistOnly?: boolean;
  /** For imports: the instruction file that imported this path. */
  readonly importedFrom?: string;
}

interface CandidateSpec {
  readonly relative: string;
  readonly dimension: ProjectTrustDimension | "restrictions";
  readonly kind: ProjectResourceKind;
}

const INSTRUCTION_FILES = ["AGENTS.md", "AGENTS.override.md", "CLAUDE.md"];

const CANDIDATES: readonly CandidateSpec[] = [
  ...INSTRUCTION_FILES.map(
    (relative): CandidateSpec => ({
      relative,
      dimension: "instructions",
      kind: "instructions",
    }),
  ),
  {
    relative: ".pi/SYSTEM.md",
    dimension: "instructions",
    kind: "system-prompt",
  },
  {
    relative: ".pi/APPEND_SYSTEM.md",
    dimension: "instructions",
    kind: "system-prompt",
  },
  { relative: ".pi/prompts", dimension: "instructions", kind: "prompts" },
  { relative: ".pi/skills", dimension: "skills", kind: "skills" },
  { relative: ".agents/skills", dimension: "skills", kind: "skills" },
  { relative: ".pi/extensions", dimension: "extensions", kind: "extensions" },
  { relative: ".pi/settings.json", dimension: "hooks", kind: "settings" },
  { relative: ".pi/themes", dimension: "passiveContext", kind: "themes" },
  { relative: ".pi/agents", dimension: "agents", kind: "agents" },
  { relative: ".mcp.json", dimension: "mcp", kind: "mcp" },
  { relative: ".piship/providers", dimension: "providers", kind: "providers" },
  {
    relative: ".piship/policy.json",
    dimension: "restrictions",
    kind: "restrictions",
  },
];

const COMPANY_APPROVED_REASON =
  "company-approved admits only distribution-approved items";

function exists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

function joinPosix(root: string, relative: string): string {
  return root.endsWith("/") ? `${root}${relative}` : `${root}/${relative}`;
}

interface Evaluation {
  readonly origin: ProjectOrigin;
  readonly effect: ProjectDimensionEffect;
  readonly reason: string;
  readonly allowlistOnly?: boolean;
}

function evaluateCandidate(
  policy: Pick<PolicyConfig, "resourceTrust" | "projectTrust">,
  identity: ProjectIdentity,
  dimension: ProjectTrustDimension | "restrictions",
  inside: boolean,
): Evaluation {
  if (dimension === "restrictions")
    return inside
      ? {
          origin: identity.origin,
          effect: "allow",
          reason: "Project restriction rules are read as narrowing only",
        }
      : {
          origin: "unknown",
          effect: "deny",
          reason:
            "The project restriction file resolves outside the project root",
        };
  if (!inside) {
    if (EXECUTABLE_DIMENSIONS.has(dimension))
      return {
        origin: "unknown",
        effect: "deny",
        reason: `Resolves outside the project root; executable ${dimension} from unknown origins are denied`,
      };
    const effect = projectDimensionEffect(
      policy,
      { origin: "unknown" },
      dimension,
    );
    return {
      origin: "unknown",
      effect: effect === "company-approved" ? "deny" : effect,
      reason: `Resolves outside the project root; evaluated as unknown origin: ${projectEffectReason("unknown", dimension, effect)}`,
    };
  }
  const effect = projectDimensionEffect(policy, identity, dimension);
  if (effect !== "company-approved")
    return {
      origin: identity.origin,
      effect,
      reason: projectEffectReason(identity.origin, dimension, effect),
    };
  if (dimension === "mcp")
    return {
      origin: identity.origin,
      effect,
      allowlistOnly: true,
      reason: `${COMPANY_APPROVED_REASON}; only allowlisted server ids may start`,
    };
  return {
    origin: identity.origin,
    effect: "deny",
    reason: COMPANY_APPROVED_REASON,
  };
}

function toCandidate(
  spec: Omit<CandidateSpec, "relative">,
  path: string,
  resolvedPath: string,
  evaluation: Evaluation,
  importedFrom?: string,
): ProjectResourceCandidate {
  return {
    dimension: spec.dimension,
    kind: spec.kind,
    path,
    resolvedPath,
    origin: evaluation.origin,
    effect: evaluation.effect,
    reason: redact(evaluation.reason),
    ...(evaluation.allowlistOnly ? { allowlistOnly: true } : {}),
    ...(importedFrom === undefined ? {} : { importedFrom }),
  };
}

const IMPORT_LINE = /^\s*@(\S+)\s*$/;
const MAX_IMPORT_DEPTH = 5;

/** `@path` import lines of an instruction file, in order. */
export function parseInstructionImports(text: string): string[] {
  const imports: string[] = [];
  let fenced = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    const match = IMPORT_LINE.exec(line);
    if (match?.[1]) imports.push(match[1]);
  }
  return imports;
}

function discoverImports(
  source: ProjectResourceCandidate,
  identity: ProjectIdentity,
  policy: Pick<PolicyConfig, "resourceTrust" | "projectTrust">,
  homeDir: string,
  seen: Set<string>,
  depth: number,
  out: ProjectResourceCandidate[],
): void {
  if (depth > MAX_IMPORT_DEPTH || source.effect === "deny") return;
  // Content is read only from files whose realpath stays inside the root.
  if (!isWithin(identity.root, source.resolvedPath)) return;
  const text = readText(source.resolvedPath);
  if (text === undefined) return;
  for (const reference of parseInstructionImports(text)) {
    const expanded = reference.startsWith("~/")
      ? joinPosix(homeDir, reference.slice(2))
      : reference;
    const lexical = isAbsolute(expanded)
      ? expanded
      : resolve(dirname(source.resolvedPath), expanded);
    const resolvedPath = real(lexical);
    const spec = {
      dimension: "instructions" as const,
      kind: "instruction-import" as const,
    };
    let evaluation: Evaluation;
    if (!isWithin(identity.root, resolvedPath))
      evaluation = {
        origin: "unknown",
        effect: "deny",
        reason: `Instruction import ${reference} resolves outside the project root`,
      };
    else if (!exists(resolvedPath))
      evaluation = {
        origin: identity.origin,
        effect: "deny",
        reason: `Instruction import ${reference} does not exist`,
      };
    else evaluation = evaluateCandidate(policy, identity, "instructions", true);
    const candidate = toCandidate(
      spec,
      reference,
      resolvedPath,
      evaluation,
      source.path,
    );
    out.push(candidate);
    if (candidate.effect === "deny" || seen.has(resolvedPath)) continue;
    seen.add(resolvedPath);
    if (isFile(resolvedPath))
      discoverImports(
        candidate,
        identity,
        policy,
        homeDir,
        seen,
        depth + 1,
        out,
      );
  }
}

/** Bounds for the walk of a project resource directory. */
const MAX_WALK_ENTRIES = 50_000;
const MAX_WALK_DEPTH = 32;

/**
 * Walk a project resource directory, following links that stay inside the
 * root, and return the first entry whose link target leaves the root (or a
 * reason the walk could not finish within its bounds). Pi's loaders follow
 * links inside these directories, so a nested link must meet the same rule
 * as the directory itself.
 */
function escapingEntry(root: string, directory: string): string | undefined {
  const visited = new Set<string>([directory]);
  const pending: { readonly path: string; readonly depth: number }[] = [
    { path: directory, depth: 0 },
  ];
  let entries = 0;
  for (let next = pending.pop(); next; next = pending.pop()) {
    let children: Dirent[];
    try {
      children = readdirSync(next.path, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const child of children) {
      entries += 1;
      if (entries > MAX_WALK_ENTRIES)
        return `has more than ${MAX_WALK_ENTRIES} entries to check for links; keep large trees (such as dependencies) out of project resource directories`;
      const path = joinPosix(next.path, child.name);
      let target = path;
      if (child.isSymbolicLink()) {
        target = real(path);
        if (!isWithin(root, target))
          return `contains a link that leaves the project root (${path.slice(root.length).replace(/^\//, "")})`;
        if (!isDirectory(target) || visited.has(target)) continue;
      } else if (!child.isDirectory()) continue;
      if (next.depth + 1 > MAX_WALK_DEPTH)
        return `nests deeper than ${MAX_WALK_DEPTH} levels to check for links; flatten it to load it`;
      visited.add(target);
      pending.push({ path: target, depth: next.depth + 1 });
    }
  }
  return undefined;
}

/**
 * Discover project-supplied resources and decide each by its trust
 * dimension. Only existing candidates are returned. Every candidate is
 * realpath'd; a target outside the project root is re-evaluated as unknown
 * origin (and denied for executable dimensions). Instruction imports must
 * stay inside the root. Content is never read through a link that leaves it.
 */
export function discoverProjectResources(
  identity: ProjectIdentity,
  policy: Pick<PolicyConfig, "resourceTrust" | "projectTrust">,
  options: { readonly homeDir: string },
): ProjectResourceCandidate[] {
  const homeDir = real(options.homeDir);
  const out: ProjectResourceCandidate[] = [];
  const seen = new Set<string>();
  for (const spec of CANDIDATES) {
    const path = joinPosix(identity.root, spec.relative);
    if (!exists(path)) {
      // A dangling link is still reported so it cannot hide.
      const resolvedPath = real(path);
      if (resolvedPath === path) continue;
      out.push(
        toCandidate(spec, path, resolvedPath, {
          origin: "unknown",
          effect: "deny",
          reason: "The candidate is a dangling link",
        }),
      );
      continue;
    }
    const resolvedPath = real(path);
    const inside = isWithin(identity.root, resolvedPath);
    // A directory is only inside the root when every link within it is too.
    const escaping =
      inside && isDirectory(resolvedPath)
        ? escapingEntry(identity.root, resolvedPath)
        : undefined;
    let evaluation = evaluateCandidate(
      policy,
      identity,
      spec.dimension,
      inside && escaping === undefined,
    );
    if (escaping !== undefined)
      evaluation = {
        ...evaluation,
        reason: evaluation.reason.replace(
          /^Resolves outside the project root/,
          `The directory ${escaping}`,
        ),
      };
    const candidate = toCandidate(spec, path, resolvedPath, evaluation);
    out.push(candidate);
    if (spec.kind === "instructions" && inside && escaping === undefined) {
      seen.add(resolvedPath);
      discoverImports(candidate, identity, policy, homeDir, seen, 1, out);
    }
  }
  return out;
}

/**
 * Read the project restriction file of a discovered candidate list. Rules
 * are always narrowing only; the file is not read when it escapes the root.
 */
export function readProjectRestrictions(
  candidates: readonly ProjectResourceCandidate[],
): ParsedRuleList {
  const candidate = candidates.find((item) => item.kind === "restrictions");
  if (!candidate || candidate.effect === "deny")
    return { rules: [], ignored: [], diagnostics: [] };
  const text = readText(candidate.resolvedPath);
  if (text === undefined) return { rules: [], ignored: [], diagnostics: [] };
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new PiShipError(
      "CONFIG_INVALID",
      `Invalid policy rules in ${candidate.path}: the file is not valid JSON`,
      { component: "policy" },
    );
  }
  return parseRuleList(value, candidate.path, { narrowingOnly: true });
}
