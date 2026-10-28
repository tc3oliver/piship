// Policy: rules, resource and provider trust, and project trust dimensions.
import {
  normalizePolicyAction,
  POLICY_ACTIONS,
  type PolicyAction,
  type PolicyEffect,
  SESSION_EXPORT_RESOURCES,
} from "@piship/contracts";
import type { DeploymentMode } from "../access.js";
import {
  CLAUDE_TRUST_DIMENSIONS,
  type PolicyConfig,
  type PolicyRule,
  PROJECT_TRUST_DIMENSIONS,
  type ProjectDimensionEffect,
  type ProjectDimensions,
  type ProjectMatcher,
  type ProjectResourceTrust,
  type ProjectTrustPolicy,
  PROVIDER_TRUST_CLASSES,
  TASK_GRANT_MODES,
  type DeclaredTaskGrant,
  type TaskGrantsPolicy,
  type TrustSetting,
  USER_AUTO_SETTINGS,
} from "../governance.js";
import {
  bool,
  conflict,
  fail,
  type Json,
  list,
  modulePath,
  oneOf,
  optionalRecord,
  plainString,
  positiveInteger,
  record,
  unsafe,
} from "./fields.js";

const EFFECTS: readonly PolicyEffect[] = ["allow", "ask", "deny"];
export const TRUST: readonly TrustSetting[] = ["allow", "deny"];
const RULE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const ACTION_PREFIXES = new Set(
  POLICY_ACTIONS.flatMap((action) => {
    const parts = action.split(".");
    return parts
      .slice(1)
      .map((_part, index) => parts.slice(0, index + 1).join("."));
  }),
);

function ruleAction(value: unknown, path: string): PolicyRule["action"] {
  // `model.use` (piship/v1alpha5 and earlier) is read as `model.select`.
  const action = normalizePolicyAction(plainString(value, path, 128));
  if (action === "*") return action;
  if ((POLICY_ACTIONS as readonly string[]).includes(action))
    return action as PolicyRule["action"];
  if (action.endsWith(".*") && ACTION_PREFIXES.has(action.slice(0, -2)))
    return action as PolicyRule["action"];
  fail(
    path,
    `Expected a policy action (${POLICY_ACTIONS.join(", ")}), a known <prefix>.*, or *`,
  );
}

function resourceGlob(value: unknown, path: string): string {
  if (value === undefined) return "**";
  return plainString(value, path, 1024);
}

/**
 * Whether a `session.export` resource glob matches a known export resource,
 * as the policy engine's glob does: the names hold no separator, so `*` and
 * `**` both match any run of characters, and a trailing `/**` also matches
 * the name itself. A rule matching none of them would govern nothing.
 */
function coversSessionExport(resource: string): boolean {
  const patterns = [resource];
  if (resource.endsWith("/**")) patterns.push(resource.slice(0, -3));
  return patterns.some((pattern) => {
    const source = pattern
      .split(/\*+/)
      .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*");
    const regexp = new RegExp(`^${source}$`, "s");
    return SESSION_EXPORT_RESOURCES.some((name) => regexp.test(name));
  });
}

function parseRule(entry: unknown, path: string): PolicyRule {
  const rule = record(entry, path, [
    "id",
    "action",
    "resource",
    "effect",
    "reason",
  ]);
  const id = plainString(rule.id, `${path}.id`, 128);
  if (!RULE_ID.test(id))
    fail(
      `${path}.id`,
      "Rule IDs use lowercase letters, digits, and . _ - (at most 128)",
    );
  const action = ruleAction(rule.action, `${path}.action`);
  const resource = resourceGlob(rule.resource, `${path}.resource`);
  if (action === "session.export" && !coversSessionExport(resource))
    fail(
      `${path}.resource`,
      `A session.export rule names ${SESSION_EXPORT_RESOURCES.join(", ")}, or a glob covering one of them`,
    );
  return {
    id,
    action,
    resource,
    effect: oneOf(rule.effect, `${path}.effect`, EFFECTS),
    ...(rule.reason === undefined
      ? {}
      : { reason: plainString(rule.reason, `${path}.reason`, 240) }),
  };
}

type Dimensions = Record<
  (typeof PROJECT_TRUST_DIMENSIONS)[number],
  ProjectDimensionEffect
>;
function dimensions(
  base: ProjectDimensionEffect,
  overrides: Partial<Dimensions>,
): Dimensions {
  const output = {} as Dimensions;
  for (const dimension of PROJECT_TRUST_DIMENSIONS)
    output[dimension] = overrides[dimension] ?? base;
  return output;
}

export function defaultProjectDimensions(
  mode: DeploymentMode,
): Record<"company" | "external" | "unknown", ProjectDimensions> {
  if (mode === "managed")
    return {
      company: dimensions("deny", {
        passiveContext: "allow",
        instructions: "allow",
        skills: "allow",
        extensions: "company-approved",
        mcp: "company-approved",
      }),
      external: dimensions("deny", {
        passiveContext: "allow",
        instructions: "ask",
      }),
      unknown: dimensions("deny", { passiveContext: "allow" }),
    };
  return {
    company: dimensions("allow", { hooks: "deny" }),
    external: dimensions("allow", { hooks: "deny" }),
    unknown: dimensions("ask", { passiveContext: "allow", hooks: "deny" }),
  };
}

const DIMENSION_EFFECTS: readonly ProjectDimensionEffect[] = [
  "allow",
  "ask",
  "deny",
  "company-approved",
];

function matcher(entry: unknown, path: string): ProjectMatcher {
  const item = record(entry, path, ["remote", "path"]);
  if (item.remote === undefined && item.path === undefined)
    fail(path, "A matcher declares remote, path, or both");
  let remote: string | undefined;
  if (item.remote !== undefined) {
    remote = plainString(item.remote, `${path}.remote`, 512);
    if (
      remote.includes("://") ||
      remote.includes("@") ||
      /\s/.test(remote) ||
      remote.endsWith(".git") ||
      remote.startsWith("/")
    )
      fail(
        `${path}.remote`,
        "Use a normalized host/path glob without scheme, credentials, or .git suffix",
      );
  }
  if (item.path === undefined) return { remote: remote as string };
  const glob = plainString(item.path, `${path}.path`, 1024);
  if (
    !(glob.startsWith("/") || /^[A-Za-z]:\//.test(glob)) ||
    glob.includes("\\") ||
    glob.split("/").some((segment) => segment === "." || segment === "..")
  )
    unsafe(
      `${path}.path`,
      "Use an absolute POSIX-style path glob without . or .. segments",
    );
  // With both, the project must match both (the remote alone is a claim).
  return remote === undefined ? { path: glob } : { remote, path: glob };
}

function projectClass(
  value: unknown,
  path: string,
  defaults: ProjectDimensions,
  withMatch: boolean,
): { match: ProjectMatcher[]; dimensions: ProjectDimensions } {
  const item = optionalRecord(value, path, [
    ...(withMatch ? ["match"] : []),
    ...PROJECT_TRUST_DIMENSIONS,
    ...CLAUDE_TRUST_DIMENSIONS,
  ]);
  const output = {} as Dimensions & Record<string, ProjectDimensionEffect>;
  for (const dimension of PROJECT_TRUST_DIMENSIONS)
    output[dimension] = oneOf(
      item[dimension],
      `${path}.${dimension}`,
      DIMENSION_EFFECTS,
      defaults[dimension],
    );
  // Declared only: an omitted Claude dimension stays absent, so the parsed
  // policy and the lock of an existing distribution do not change.
  for (const dimension of CLAUDE_TRUST_DIMENSIONS)
    if (item[dimension] !== undefined)
      output[dimension] = oneOf(
        item[dimension],
        `${path}.${dimension}`,
        DIMENSION_EFFECTS,
        "deny",
      );
  return {
    match: withMatch
      ? list(item.match, `${path}.match`, matcher, (entry) =>
          JSON.stringify(entry),
        )
      : [],
    dimensions: output,
  };
}

function parseProjectTrust(
  value: unknown,
  mode: DeploymentMode,
): ProjectTrustPolicy {
  const trust = optionalRecord(value, "policy.projectTrust", [
    "company",
    "external",
    "unknown",
  ]);
  const defaults = defaultProjectDimensions(mode);
  const company = projectClass(
    trust.company,
    "policy.projectTrust.company",
    defaults.company,
    true,
  );
  const external = projectClass(
    trust.external,
    "policy.projectTrust.external",
    defaults.external,
    true,
  );
  const unknown = projectClass(
    trust.unknown,
    "policy.projectTrust.unknown",
    defaults.unknown,
    false,
  );
  return { company, external, unknown: { dimensions: unknown.dimensions } };
}

/**
 * `policy.userAuto` (piship/v1alpha5). In personal mode the user already
 * owns the policy (user rules replace a matching default), so the field is
 * rejected there rather than silently meaning nothing.
 */
function parseUserAuto(
  value: unknown,
  mode: DeploymentMode,
): PolicyConfig["userAuto"] {
  if (value === undefined) return undefined;
  if (mode !== "managed")
    fail(
      "policy.userAuto",
      "userAuto applies to managed distributions only; in personal mode the user relaxes ask with allow rules in config/policy.json",
    );
  return oneOf(value, "policy.userAuto", USER_AUTO_SETTINGS);
}

/** Workspace-relative roots only; reject Windows aliases and non-canonical spellings. */
function declaredRoot(value: unknown, path: string): string {
  const root = plainString(value, path, 512);
  const segments = root.split("/");
  if (
    root !== "." &&
    (root.startsWith("/") ||
      root.includes("\\") ||
      root.includes(":") ||
      /[*?[{}\0]/.test(root) ||
      /[<>"|\u0000-\u001f]/.test(root) ||
      segments.some(
        (segment) =>
          !segment ||
          segment === "." ||
          segment === ".." ||
          /[. ]$/.test(segment) ||
          /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(segment),
      ))
  )
    fail(
      path,
      "Expected a canonical workspace-relative path without globs or traversal",
    );
  return root;
}

function exactGrantName(value: unknown, path: string): string {
  const name = plainString(value, path, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(name))
    fail(path, "Expected an exact name without globs or shell syntax");
  return name;
}

function declaredTaskGrant(value: unknown, path: string): DeclaredTaskGrant {
  const item = record(value, path, [
    "id",
    "task",
    "ttlMinutes",
    "scope",
    "inheritToSubagents",
  ]);
  const id = plainString(item.id, `${path}.id`, 64);
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id))
    fail(`${path}.id`, "Expected a plain grant ID");
  const scope = record(item.scope, `${path}.scope`, [
    "paths",
    "tools",
    "commands",
    "mcp",
  ]);
  const strings = (key: "tools" | "commands") =>
    scope[key] === undefined
      ? undefined
      : list(scope[key], `${path}.scope.${key}`, exactGrantName);
  const paths =
    scope.paths === undefined
      ? undefined
      : list(scope.paths, `${path}.scope.paths`, declaredRoot);
  const tools = strings("tools");
  const commands = strings("commands");
  const wrappers = new Set([
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
  for (const [index, command] of (commands ?? []).entries())
    if (wrappers.has(command.toLowerCase().replace(/\\.(?:exe|cmd|bat)$/, "")))
      fail(
        `${path}.scope.commands[${index}]`,
        "Shell wrappers cannot be granted",
      );
  const mcp =
    scope.mcp === undefined
      ? undefined
      : list(scope.mcp, `${path}.scope.mcp`, (entry, at) => {
          const server = record(entry, at, ["server", "tools"]);
          const name = exactGrantName(server.server, `${at}.server`);
          const allowed = list(server.tools, `${at}.tools`, exactGrantName);
          if (!allowed.length)
            fail(`${at}.tools`, "Declare explicit MCP tool names");
          return { server: name, tools: allowed };
        });
  if (![paths, tools, commands, mcp].some((entries) => entries?.length))
    fail(`${path}.scope`, "A declared grant needs a non-empty scope");
  return {
    id,
    task: plainString(item.task, `${path}.task`, 128),
    ttlMinutes: positiveInteger(item.ttlMinutes, `${path}.ttlMinutes`, 1, 1440),
    scope: {
      ...(paths === undefined ? {} : { paths }),
      ...(tools === undefined ? {} : { tools }),
      ...(commands === undefined ? {} : { commands }),
      ...(mcp === undefined ? {} : { mcp }),
    },
    inheritToSubagents: bool(
      item.inheritToSubagents,
      `${path}.inheritToSubagents`,
      false,
    ),
  };
}

/** `policy.taskGrants` (piship/v1alpha5): the cap a session applies to task grants. */
function parseTaskGrants(value: unknown): TaskGrantsPolicy | undefined {
  if (value === undefined) return undefined;
  const grants = record(value, "policy.taskGrants", [
    "mode",
    "maxTtlMinutes",
    "actions",
    "wildcardHosts",
    "declared",
  ]);
  const mode = oneOf(grants.mode, "policy.taskGrants.mode", TASK_GRANT_MODES);
  const actions =
    grants.actions === undefined
      ? undefined
      : list(grants.actions, "policy.taskGrants.actions", (entry, path) => {
          const action = plainString(entry, path, 64);
          if (!(POLICY_ACTIONS as readonly string[]).includes(action))
            fail(
              path,
              `Expected one policy action (${POLICY_ACTIONS.join(", ")})`,
            );
          return action as PolicyAction;
        });
  if (actions?.length === 0)
    fail(
      "policy.taskGrants.actions",
      "Expected at least one action; use mode off to forbid grants, or omit actions for no restriction",
    );
  const declared =
    grants.declared === undefined
      ? undefined
      : list(
          grants.declared,
          "policy.taskGrants.declared",
          declaredTaskGrant,
          (entry) => entry.id,
        );
  if (declared?.length && mode !== "session")
    fail("policy.taskGrants.mode", "Declared grants require mode session");
  const cap =
    grants.maxTtlMinutes === undefined
      ? 480
      : positiveInteger(
          grants.maxTtlMinutes,
          "policy.taskGrants.maxTtlMinutes",
          1,
          24 * 60,
        );
  for (const [index, entry] of (declared ?? []).entries())
    if (entry.ttlMinutes > cap)
      fail(
        `policy.taskGrants.declared[${index}].ttlMinutes`,
        "Grant lifetime exceeds maxTtlMinutes",
      );
  return {
    mode,
    ...(declared === undefined ? {} : { declared }),
    ...(grants.maxTtlMinutes === undefined ? {} : { maxTtlMinutes: cap }),
    ...(actions === undefined ? {} : { actions }),
    ...(grants.wildcardHosts === undefined
      ? {}
      : {
          wildcardHosts: bool(
            grants.wildcardHosts,
            "policy.taskGrants.wildcardHosts",
            false,
          ),
        }),
  };
}

/**
 * `policy.acknowledgeUnenforced` (piship/v1alpha6): `<action>:<resource>`
 * entries naming one exact action. Whether the action is actually
 * unenforceable is decided by validation, not here.
 */
function acknowledged(entry: unknown, path: string): string {
  const text = plainString(entry, path, 1024);
  const colon = text.indexOf(":");
  const action = normalizePolicyAction(colon < 0 ? text : text.slice(0, colon));
  if (colon <= 0 || colon === text.length - 1)
    fail(path, "Expected <action>:<resource>, such as session.export:public");
  if (!(POLICY_ACTIONS as readonly string[]).includes(action))
    fail(path, `Expected one policy action (${POLICY_ACTIONS.join(", ")})`);
  return `${action}${text.slice(colon)}`;
}

export function parsePolicy(
  value: unknown,
  mode: DeploymentMode,
  app: { readonly id: string },
  options: {
    readonly userAuto?: boolean;
    /** piship/v1alpha6 and later: accepts `policy.acknowledgeUnenforced`. */
    readonly acknowledgeUnenforced?: boolean;
  } = {},
): PolicyConfig {
  const policy = optionalRecord(value, "policy", [
    "id",
    "version",
    "default",
    "adapter",
    "resourceTrust",
    "providerTrust",
    "projectTrust",
    "enforced",
    "defaults",
    ...(options.userAuto ? ["userAuto", "taskGrants"] : []),
    ...(options.acknowledgeUnenforced ? ["acknowledgeUnenforced"] : []),
  ]);
  const userAuto = parseUserAuto(policy.userAuto, mode);
  const taskGrants = parseTaskGrants(policy.taskGrants);
  const id =
    policy.id === undefined ? app.id : plainString(policy.id, "policy.id", 128);
  if (!RULE_ID.test(id))
    fail("policy.id", "Policy IDs use lowercase letters, digits, and . _ -");
  const managed = mode === "managed";
  const resourceTrust = optionalRecord(
    policy.resourceTrust,
    "policy.resourceTrust",
    ["upstream", "builtin", "certified", "company", "user", "project"],
  );
  const providerTrust = optionalRecord(
    policy.providerTrust,
    "policy.providerTrust",
    PROVIDER_TRUST_CLASSES,
  );
  const trustOf = (
    section: Json,
    key: string,
    at: string,
    fallback: TrustSetting,
  ) => oneOf(section[key], `${at}.${key}`, TRUST, fallback);
  const enforced = list(
    policy.enforced,
    "policy.enforced",
    parseRule,
    (rule) => rule.id,
  );
  const defaults = list(
    policy.defaults,
    "policy.defaults",
    parseRule,
    (rule) => rule.id,
  );
  for (const [index, rule] of defaults.entries())
    if (enforced.some((other) => other.id === rule.id))
      conflict(
        `policy.defaults[${index}].id`,
        `Rule ID ${rule.id} is already used in policy.enforced`,
      );
  return {
    id,
    version: positiveInteger(
      policy.version,
      "policy.version",
      1,
      1_000_000_000,
    ),
    default: oneOf(
      policy.default,
      "policy.default",
      EFFECTS,
      managed ? "ask" : "allow",
    ),
    enforced,
    defaults,
    ...(policy.adapter === undefined
      ? {}
      : { adapter: modulePath(policy.adapter, "policy.adapter") }),
    ...(userAuto === undefined ? {} : { userAuto }),
    ...(taskGrants === undefined ? {} : { taskGrants }),
    ...(options.acknowledgeUnenforced
      ? {
          acknowledgeUnenforced: list(
            policy.acknowledgeUnenforced,
            "policy.acknowledgeUnenforced",
            acknowledged,
          ),
        }
      : {}),
    resourceTrust: {
      upstream: trustOf(
        resourceTrust,
        "upstream",
        "policy.resourceTrust",
        "allow",
      ),
      builtin: trustOf(
        resourceTrust,
        "builtin",
        "policy.resourceTrust",
        "allow",
      ),
      certified: trustOf(
        resourceTrust,
        "certified",
        "policy.resourceTrust",
        "allow",
      ),
      company: trustOf(
        resourceTrust,
        "company",
        "policy.resourceTrust",
        "allow",
      ),
      user: trustOf(
        resourceTrust,
        "user",
        "policy.resourceTrust",
        managed ? "deny" : "allow",
      ),
      project: oneOf<ProjectResourceTrust>(
        resourceTrust.project,
        "policy.resourceTrust.project",
        ["allow", "deny", "policy"],
        "policy",
      ),
    },
    providerTrust: {
      upstream: trustOf(
        providerTrust,
        "upstream",
        "policy.providerTrust",
        "allow",
      ),
      builtin: trustOf(
        providerTrust,
        "builtin",
        "policy.providerTrust",
        "allow",
      ),
      certified: trustOf(
        providerTrust,
        "certified",
        "policy.providerTrust",
        "allow",
      ),
      company: trustOf(
        providerTrust,
        "company",
        "policy.providerTrust",
        "allow",
      ),
      user: trustOf(
        providerTrust,
        "user",
        "policy.providerTrust",
        managed ? "deny" : "allow",
      ),
    },
    projectTrust: parseProjectTrust(policy.projectTrust, mode),
  };
}
