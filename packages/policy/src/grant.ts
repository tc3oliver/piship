import { posix, win32 } from "node:path";
import { chainsBeyondPattern } from "./engine.js";
import { gitPushResources } from "./git-push.js";

/**
 * A task grant turns an `ask` into `allow` strictly inside its scope. This
 * module is the pure matcher and validator; state, audit and the `/grant`
 * command live in `packages/pi`.
 *
 * Callers MUST pass grant roots and path resources through
 * `fs.realpath.native` first. Matching is textual (case, 8.3 short names and
 * symlinks are not resolved here), so an unresolved path can compare wrong.
 */
export interface TaskGrant {
  readonly id: string;
  readonly task: string;
  readonly createdBy: "user-command" | "manifest";
  /** ISO 8601 instant; the grant covers nothing at or after it. */
  readonly expiresAt: string;
  readonly scope: {
    /** Canonical absolute roots, no globs. */
    readonly paths?: readonly string[];
    /** Exact tool names. */
    readonly tools?: readonly string[];
    /** Exact server ids; `tools` omitted means every tool of the server. */
    readonly mcp?: readonly { server: string; tools?: readonly string[] }[];
    /** Exact `host[:port]`, or `*.suffix` when the manifest allows it. */
    readonly hosts?: readonly string[];
    readonly git?: readonly { remote: string; branches: readonly string[] }[];
    /**
     * Exact program names a shell command may start with. A covered program
     * runs whatever code it is given (an npm script, a Makefile target).
     */
    readonly commands?: readonly string[];
  };
  readonly inheritToSubagents: boolean;
  /**
   * The roots as the user spelled them, where that differs from their
   * realpath (`/var/x` for `/private/var/x`). An ask's lexical form may lie
   * under one of these; its resolved form must still lie under a root in
   * `scope.paths`.
   */
  readonly pathAliases?: readonly string[];
}

/** One ask of a (possibly combined) prompt. */
export interface GrantAsk {
  readonly action: string;
  readonly resource: string;
  /** Realpath form of a path resource; a path ask without it is not covered. */
  readonly resolvedResource?: string;
  readonly keepsPrompt: boolean;
  readonly effect: "allow" | "ask" | "deny";
  /**
   * A governed tool's own `tool.execute` ask, decided together with the file
   * or command ask it makes: covered with that ask, never alone, and never
   * when it keeps its prompt.
   */
  readonly companion?: boolean;
}

export type GrantPlatform = "posix" | "win32";

const GLOB_CHARS = /[*?[{]/;
const DEFAULT_BRANCHES = ["main", "master"];

/** A scope list as the matcher reads it: anything but an array grants nothing. */
const list = <T>(value: readonly T[] | undefined): readonly T[] =>
  Array.isArray(value) ? value : [];

const SCOPE_KEYS = new Set([
  "paths",
  "tools",
  "mcp",
  "hosts",
  "git",
  "commands",
]);

/** A plain program name: no path, no glob, no shell syntax. */
const PROGRAM = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

/**
 * Programs that run another command or a shell given as their arguments, so
 * naming one would cover every command.
 */
const WRAPPERS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "mksh",
  "ash",
  "yash",
  "nu",
  "fish",
  "csh",
  "tcsh",
  "env",
  "sudo",
  "doas",
  "su",
  "xargs",
  "eval",
  "exec",
  "nohup",
  "time",
  "timeout",
  "nice",
  "command",
  "builtin",
  "busybox",
  "pwsh",
  "powershell",
  "cmd",
  "watch",
  "script",
  "chroot",
  "flock",
  "setsid",
  "strace",
  "stdbuf",
  "unbuffer",
  "parallel",
]);

const isStrings = (value: unknown): boolean =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

const flavor = (platform: GrantPlatform) =>
  platform === "win32" ? win32 : posix;

/** Normalised form for the forbidden-root comparison; win32 drops trailing dots/spaces per segment. */
function canon(path: string, platform: GrantPlatform): string {
  const n = flavor(platform).normalize(path);
  return platform === "win32"
    ? n
        .split(/[\\/]/)
        .map((seg) => seg.replace(/[. ]+$/, ""))
        .join("\\")
    : n;
}

/** True when `path` lies at or below `root`, by path segment, as the platform compares. */
function isUnder(root: string, path: string, platform: GrantPlatform): boolean {
  const p = flavor(platform);
  if (!p.isAbsolute(root) || !p.isAbsolute(path)) return false;
  if (hasDotDot(path)) return false;
  const rel = p.relative(root, path);
  return (
    rel === "" ||
    (rel !== ".." && !rel.startsWith(`..${p.sep}`) && !p.isAbsolute(rel))
  );
}

function hasDotDot(path: string): boolean {
  return path.split(/[\\/]/).includes("..");
}

const splitPort = (hostPort: string) =>
  /^(.*?)(?::(\d+))?$/.exec(hostPort) ?? [hostPort, hostPort, undefined];

/** A wildcard covers default ports 80/443 implicitly; any other port must be in the pattern. */
function hostCovers(pattern: string, host: string): boolean {
  if (!pattern.startsWith("*.")) return pattern === host;
  const [, suffix = "", patternPort] = splitPort(pattern.slice(1));
  const [, name = "", port] = splitPort(host);
  const portOk =
    patternPort === undefined
      ? port === undefined || port === "80" || port === "443"
      : port === patternPort;
  return portOk && name.endsWith(suffix) && name.length > suffix.length;
}

// No `i` flag: case is folded after the test, so U+212A (Kelvin) cannot become "k".
const BARE_HOST = /^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d+)?$/;

const DEFAULT_PORTS: Record<string, string> = {
  "http:": "80",
  "https:": "443",
  "ws:": "80",
  "wss:": "443",
};

/**
 * The `host[:port]` forms a resource can be compared as. A URL yields its
 * host, plus `host:port` with the scheme's default port filled in; a URL with
 * userinfo, or a bare resource that is not plain `host[:port]`, yields none.
 */
function hostForms(resource: string): string[] {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(resource)) {
    // A bare resource must be only host[:port]; a trailing dot is refused.
    return BARE_HOST.test(resource) && !/\.(?::\d+)?$/.test(resource)
      ? [resource.toLowerCase()]
      : [];
  }
  let url: URL;
  try {
    url = new URL(resource);
  } catch {
    return [];
  }
  if (url.username || url.password) return [];
  if (url.port) return [`${url.hostname}:${url.port}`];
  // Other schemes (ftp, ssh, redis) lose their default port in URL parsing; unknown, so no match.
  const port = DEFAULT_PORTS[url.protocol];
  return port ? [url.hostname, `${url.hostname}:${port}`] : [];
}

function askCovered(
  grant: TaskGrant,
  ask: GrantAsk,
  platform: GrantPlatform,
): boolean {
  const { scope } = grant;
  switch (ask.action) {
    case "filesystem.read":
    case "filesystem.write": {
      // Fail closed: the caller must supply the realpath.
      if (ask.resolvedResource === undefined) return false;
      const { resource, resolvedResource } = ask;
      const roots = list(scope.paths);
      return (
        roots.some((root) => isUnder(root, resolvedResource, platform)) &&
        [...roots, ...list(grant.pathAliases)].some((root) =>
          isUnder(root, resource, platform),
        )
      );
    }
    case "tool.execute":
      return list(scope.tools).includes(ask.resource);
    case "shell.execute": {
      // One plain command: no chaining, redirect, substitution, variable,
      // or grouping, not even quoted, and never a git push.
      const [program = ""] = ask.resource
        .replace(/^[ \t]+/, "")
        .split(/[ \t]+/);
      return (
        !chainsBeyondPattern("", ask.resource, platform) &&
        // A program the shell expands (`n?m`, `{git,x}`) is unknown; a
        // globbed git subcommand counts as a push (gitPushResources).
        !/[{}*?[]/.test(program) &&
        gitPushResources(ask.resource).length === 0 &&
        list(scope.commands).includes(program)
      );
    }
    case "mcp.tool.call":
      // Resource is `<server>:<tool>`; server ids cannot contain ":".
      return list(scope.mcp).some(({ server, tools }) =>
        tools
          ? list(tools).some((tool) => `${server}:${tool}` === ask.resource)
          : ask.resource.startsWith(`${server}:`),
      );
    case "network.connect":
    case "web.request": {
      const hosts = hostForms(ask.resource);
      return list(scope.hosts).some((pattern) =>
        hosts.some((host) => hostCovers(pattern, host)),
      );
    }
    default:
      // Git is a typed stub that never covers: the `git.push` resource shape
      // (D2) is not final, so matching it now would pin a guess.
      return false;
  }
}

/**
 * Whether `grant` approves every ask of one prompt. False for an empty ask
 * list, a deny, any ask that keeps its prompt, an expired grant, or any ask
 * outside the scope.
 */
export function grantCovers(
  grant: TaskGrant,
  asks: readonly GrantAsk[],
  now: number,
  platform: GrantPlatform = process.platform === "win32" ? "win32" : "posix",
): boolean {
  const expires = Date.parse(grant.expiresAt);
  if (!(now < expires)) return false; // also false for an unparsable date
  if (asks.length === 0) return false;
  const carried = asks.some((ask) => ask.companion !== true);
  return asks.every(
    (ask) =>
      ask.effect === "ask" &&
      ask.keepsPrompt === false &&
      (ask.companion === true ? carried : askCovered(grant, ask, platform)),
  );
}

/**
 * `self-and-above` refuses the path and any root containing it (the home
 * dir: a project below it is fine); `subtree` also refuses everything below
 * it (the state dir).
 */
export interface ForbiddenRoot {
  readonly path: string;
  readonly mode: "subtree" | "self-and-above";
}

export interface GrantLimits {
  readonly now: number;
  readonly maxTtlMs: number;
  readonly forbiddenRoots: readonly ForbiddenRoot[];
  readonly wildcardHosts: boolean;
  /** The repository's default branch, besides `main` and `master`. */
  readonly defaultBranch?: string;
  readonly platform?: GrantPlatform;
}

/**
 * The reasons `grant` may not be created; empty when it is acceptable. Roots
 * and forbidden paths must already be `fs.realpath.native` forms: the overlap
 * check is textual. No public-suffix list yet, so `*.co.uk` passes the
 * two-label rule; the manifest opt-in is the control. (win32 trailing dots/spaces are stripped, `~1` short names
 * refused).
 */
export function validateGrant(grant: TaskGrant, limits: GrantLimits): string[] {
  const platform =
    limits.platform ?? (process.platform === "win32" ? "win32" : "posix");
  const p = flavor(platform);
  const errors: string[] = [];
  const { scope } = grant;
  // Interactive approvals must never become inheritable task authority.
  if (grant.createdBy !== "user-command" && grant.createdBy !== "manifest")
    errors.push("grant source is invalid");
  if (typeof grant.inheritToSubagents !== "boolean")
    errors.push("grant inheritance flag must be boolean");
  else if (grant.inheritToSubagents && grant.createdBy !== "manifest")
    errors.push("only manifest grants may be inherited by subagents");
  // The shape first: the type is not checked at run time.
  if (typeof grant.id !== "string" || grant.id === "")
    return ["grant id is missing"];
  if (!scope || typeof scope !== "object" || Array.isArray(scope))
    return ["scope is not an object"];
  for (const key of Object.keys(scope))
    if (!SCOPE_KEYS.has(key)) errors.push(`unknown scope kind: ${key}`);
  for (const key of ["paths", "tools", "hosts", "commands"] as const)
    if (scope[key] !== undefined && !isStrings(scope[key]))
      errors.push(`scope ${key} is not a list of strings`);
  if (
    scope.mcp !== undefined &&
    !(
      Array.isArray(scope.mcp) &&
      scope.mcp.every(
        (entry) =>
          entry &&
          typeof entry.server === "string" &&
          (entry.tools === undefined || isStrings(entry.tools)),
      )
    )
  )
    errors.push("scope mcp is not a list of servers");
  if (
    scope.git !== undefined &&
    !(
      Array.isArray(scope.git) &&
      scope.git.every(
        (entry) =>
          entry &&
          typeof entry.remote === "string" &&
          isStrings(entry.branches),
      )
    )
  )
    errors.push("scope git is not a list of remotes");
  if (grant.pathAliases !== undefined && !isStrings(grant.pathAliases))
    errors.push("path aliases are not a list of strings");
  if (errors.length) return errors;

  const expires = Date.parse(grant.expiresAt);
  if (Number.isNaN(expires)) errors.push("expiry is missing or invalid");
  else if (expires <= limits.now) errors.push("expiry is in the past");
  else if (expires > limits.now + limits.maxTtlMs)
    errors.push("expiry exceeds the maximum lifetime");

  for (const root of [...(scope.paths ?? []), ...(grant.pathAliases ?? [])]) {
    if (!p.isAbsolute(root)) errors.push(`path root is not absolute: ${root}`);
    else if (
      platform === "win32" &&
      (/^[\\/]{2}[?.][\\/]/.test(root) ||
        !/^(?:[A-Za-z]:|[\\/]{2}[^\\/]+[\\/]+[^\\/]+)/.test(root))
    )
      errors.push(`path root needs a drive letter or UNC share: ${root}`);
    else if (hasDotDot(root)) errors.push(`path root contains "..": ${root}`);
    else if (GLOB_CHARS.test(root))
      errors.push(`path root contains a glob character: ${root}`);
    else if (p.parse(p.normalize(root)).root === p.normalize(root))
      errors.push(`path root is a filesystem root: ${root}`);
    else if (platform === "win32" && /~\d/.test(root))
      errors.push(`path root contains an 8.3 short name: ${root}`);
    else if (
      limits.forbiddenRoots.some((f) => {
        const [r, fp] = [canon(root, platform), canon(f.path, platform)];
        return (
          isUnder(r, fp, platform) ||
          (f.mode === "subtree" && isUnder(fp, r, platform))
        );
      })
    )
      errors.push(`path root overlaps a forbidden directory: ${root}`);
  }

  for (const host of scope.hosts ?? []) {
    if (host.startsWith("*.")) {
      if (!limits.wildcardHosts)
        errors.push(`wildcard host not allowed: ${host}`);
      else if (
        !/^\*(?:\.[a-z0-9-]+){2,}(?::\d+)?$/i.test(host) ||
        !/[a-z]/i.test(host.replace(/:\d+$/, "").split(".").pop() ?? "")
      )
        errors.push(
          `wildcard host needs two labels after "*." and a lettered last label: ${host}`,
        );
    } else if (GLOB_CHARS.test(host) || host === "")
      errors.push(`invalid host: ${host}`);
  }

  const blocked = [...DEFAULT_BRANCHES, limits.defaultBranch];
  for (const { branches } of scope.git ?? []) {
    for (const branch of branches) {
      if (blocked.includes(branch))
        errors.push(`default branch is not grantable: ${branch}`);
      else if (GLOB_CHARS.test(branch))
        errors.push(`branch contains a glob character: ${branch}`);
    }
  }

  for (const { server } of scope.mcp ?? []) {
    if (server.includes(":") || GLOB_CHARS.test(server))
      errors.push(`invalid MCP server id: ${server}`);
  }
  for (const program of scope.commands ?? []) {
    if (!PROGRAM.test(program))
      errors.push(`command is not a plain program name: ${program}`);
    else if (
      WRAPPERS.has(program.toLowerCase().replace(/\.(?:exe|cmd|bat)$/, ""))
    )
      errors.push(
        `command runs other commands, so it cannot be granted: ${program}`,
      );
  }
  for (const tool of scope.tools ?? []) {
    if (GLOB_CHARS.test(tool))
      errors.push(`tool name contains a glob: ${tool}`);
  }
  return errors;
}
