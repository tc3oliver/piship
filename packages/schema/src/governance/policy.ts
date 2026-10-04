// Policy: rules, resource and provider trust, and project trust dimensions.
import {
  normalizePolicyAction,
  POLICY_ACTIONS,
  type PolicyEffect,
  SESSION_EXPORT_RESOURCES,
} from "@piship/contracts";
import type { DeploymentMode } from "../access.js";
import {
  type PolicyConfig,
  type PolicyRule,
  PROJECT_TRUST_DIMENSIONS,
  type ProjectDimensionEffect,
  type ProjectDimensions,
  type ProjectMatcher,
  type ProjectResourceTrust,
  type ProjectTrustPolicy,
  PROVIDER_TRUST_CLASSES,
  type TrustSetting,
  USER_AUTO_SETTINGS,
} from "../governance.js";
import {
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
  ]);
  const output = {} as Dimensions;
  for (const dimension of PROJECT_TRUST_DIMENSIONS)
    output[dimension] = oneOf(
      item[dimension],
      `${path}.${dimension}`,
      DIMENSION_EFFECTS,
      defaults[dimension],
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
    ...(options.userAuto ? ["userAuto"] : []),
    ...(options.acknowledgeUnenforced ? ["acknowledgeUnenforced"] : []),
  ]);
  const userAuto = parseUserAuto(policy.userAuto, mode);
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
