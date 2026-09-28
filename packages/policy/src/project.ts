// Project identity, origin classification, and project resource discovery.
// No git binary is executed: the origin remote is read from the git config.
import { readFileSync, statSync } from "node:fs";
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

function gitConfigPath(gitDir: string): string {
  const commondir = readText(join(gitDir, "commondir"))?.trim();
  if (!commondir) return join(gitDir, "config");
  const common = isAbsolute(commondir) ? commondir : resolve(gitDir, commondir);
  return join(common, "config");
}

/**
 * The git files that decide how `root` is classified: the `.git` entry
 * itself (a `gitdir:` pointer when it is a file), the git directory's
 * `config` and `commondir`, and the shared `config` a worktree points to.
 * Rewriting any of them could change the origin remote a later launch
 * reads. Paths are normalized (symlink-resolved, POSIX separators).
 */
export function projectGitControlFiles(root: string): string[] {
  const dotGit = join(root, ".git");
  const files = [real(dotGit), real(join(dotGit, "config"))];
  const gitDir = gitDirectory(root);
  if (gitDir) {
    files.push(
      real(join(gitDir, "config")),
      real(join(gitDir, "commondir")),
      real(gitConfigPath(gitDir)),
    );
  }
  return [...new Set(files)];
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
    const candidate = toCandidate(
      spec,
      path,
      resolvedPath,
      evaluateCandidate(policy, identity, spec.dimension, inside),
    );
    out.push(candidate);
    if (spec.kind === "instructions" && inside) {
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
