// The policy engine: layered rule precedence, enforcement planes, and rule
// list parsing for user, project, and adapter rule files.
import {
  normalizePolicyAction,
  POLICY_ACTIONS,
  PiShipError,
  redact,
  type EnforcementPlane,
  type PolicyAction,
  type PolicyDecision,
  type PolicyEffect,
  type PolicyLayer,
  type PolicyRequest,
} from "@piship/contracts";
import type { PolicyConfig, PolicyRule } from "@piship/schema";
import {
  expandPathTokens,
  matchAction,
  matchGlob,
  normalizePathResource,
  normalizeTokenContext,
  type PathTokenContext,
} from "./glob.js";

/** Which planes an active OS sandbox adapter enforces. */
export interface PolicyContainment {
  readonly filesystem: boolean;
  readonly network: boolean;
  readonly shell: boolean;
}

export interface PolicyContext extends PathTokenContext {
  readonly containment: PolicyContainment;
}

export const NO_CONTAINMENT: PolicyContainment = {
  filesystem: false,
  network: false,
  shell: false,
};

/**
 * Actions PiShip decides at a runtime hook before they happen. Actions
 * without such a hook (`agent.invoke`, `memory.read`, `memory.write`) are
 * evaluated for explanation and audit only, so they are not listed here.
 */
const CONTROL_PLANE_ACTIONS: ReadonlySet<string> = new Set([
  "model.select",
  "resource.load",
  "extension.load",
  "skill.load",
  "instruction.load",
  "provider.load",
  "mcp.server.start",
  "mcp.tool.call",
  "tool.execute",
]);

/**
 * The plane that enforces `action` under the active containment. Filesystem
 * actions fall back to the control plane (built-in file tools are gated
 * in-process); shell command gating falls back to the control plane (the
 * tool call is intercepted before it runs); network connections without a
 * sandbox, web/browser actions, and actions no runtime hook evaluates are
 * audit-only.
 */
export function enforcementPlane(
  action: PolicyAction,
  containment: PolicyContainment,
): EnforcementPlane {
  if (CONTROL_PLANE_ACTIONS.has(action)) return "control-plane";
  switch (action) {
    case "filesystem.read":
    case "filesystem.write":
      return containment.filesystem ? "sandbox" : "control-plane";
    case "shell.execute":
      return containment.shell ? "sandbox" : "control-plane";
    case "network.connect":
      return containment.network ? "sandbox" : "audit-only";
    default:
      return "audit-only";
  }
}

const STRICTNESS: Readonly<Record<PolicyEffect, number>> = {
  allow: 0,
  ask: 1,
  deny: 2,
};

export function strictest(
  ...effects: readonly (PolicyEffect | undefined)[]
): PolicyEffect {
  let result: PolicyEffect = "allow";
  for (const effect of effects)
    if (effect && STRICTNESS[effect] > STRICTNESS[result]) result = effect;
  return result;
}

/**
 * Characters that chain, substitute, redirect, or group shell commands in
 * POSIX shells and cmd.exe (`^` escapes and `%` expands there).
 */
const SHELL_METACHARACTERS = /[;&|$`<>()\r\n^%]/g;

/**
 * True when `command` uses a shell metacharacter that `pattern` does not
 * spell out. An allow or ask rule such as `git *` is a prefix hint, not
 * containment, so it must not cover `git status; rm -rf ~`. The bare `**`
 * pattern means every command and is exempt.
 */
export function chainsBeyondPattern(pattern: string, command: string): boolean {
  if (pattern === "**") return false;
  for (const [char] of command.matchAll(SHELL_METACHARACTERS))
    if (!pattern.includes(char)) return true;
  return false;
}

/**
 * A rule with a former action name (`model.use`) under its current name.
 * Rules from a lock written before the rename still match the action the
 * runtime evaluates.
 */
function normalizeRuleAction(rule: PolicyRule): PolicyRule {
  const action = normalizePolicyAction(rule.action);
  return action === rule.action
    ? rule
    : { ...rule, action: action as PolicyRule["action"] };
}

export function isPathAction(action: string): boolean {
  return action === "filesystem.read" || action === "filesystem.write";
}

// ------------------------------------------------------------ rule parsing

/** Where a rule list came from; team-project sources are narrowing only. */
export type RuleSource =
  | "enforced"
  | "defaults"
  | "team"
  | "project"
  | "user"
  | (string & {});

export interface PolicyDiagnostic {
  readonly level: "warning" | "error";
  readonly source: string;
  readonly ruleId?: string;
  readonly message: string;
}

export interface ParsedRuleList {
  readonly rules: readonly PolicyRule[];
  /** Rules that were dropped (for example an `allow` in a narrowing-only list). */
  readonly ignored: readonly IgnoredRule[];
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export interface IgnoredRule {
  readonly source: string;
  readonly layer: PolicyLayer;
  readonly rule: PolicyRule;
  readonly why: string;
}

// Mirrors the manifest rule grammar of @piship/schema.
const RULE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const RULE_KEYS = new Set(["id", "action", "resource", "effect", "reason"]);
const EFFECTS: readonly string[] = ["allow", "ask", "deny"];
const ACTION_PREFIXES: ReadonlySet<string> = new Set(
  POLICY_ACTIONS.flatMap((action) => {
    const parts = action.split(".");
    return parts
      .slice(1)
      .map((_part, index) => parts.slice(0, index + 1).join("."));
  }),
);
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting them is the point
const CONTROL = /[\u0000-\u001f\u007f]/;
const RUNTIME_REFERENCE = /\$\{/;

function isActionPattern(value: string): boolean {
  if (value === "*") return true;
  if ((POLICY_ACTIONS as readonly string[]).includes(value)) return true;
  return value.endsWith(".*") && ACTION_PREFIXES.has(value.slice(0, -2));
}

function invalid(source: string, path: string, message: string): PiShipError {
  return new PiShipError(
    "CONFIG_INVALID",
    `Invalid policy rules in ${source} at ${path}: ${message}`,
    { component: "policy" },
  );
}

function plainText(
  value: unknown,
  source: string,
  path: string,
  max: number,
): string {
  if (typeof value !== "string" || value.trim() === "")
    throw invalid(source, path, "expected a non-empty string");
  if (RUNTIME_REFERENCE.test(value))
    throw invalid(source, path, "runtime references are not allowed");
  if (CONTROL.test(value))
    throw invalid(source, path, "control characters are not allowed");
  if (value.length > max)
    throw invalid(source, path, `use at most ${max} characters`);
  return value;
}

function parseRule(value: unknown, source: string, path: string): PolicyRule {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw invalid(source, path, "a rule must be an object");
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record))
    if (!RULE_KEYS.has(key))
      throw invalid(source, `${path}.${key}`, "unknown field");
  const id = plainText(record.id, source, `${path}.id`, 128);
  if (!RULE_ID.test(id))
    throw invalid(
      source,
      `${path}.id`,
      "rule ids use lowercase letters, digits, and . _ - (at most 128)",
    );
  const { effect } = record;
  // A former action name (`model.use`) is read as its current name, so a
  // rule file written for an older release keeps applying; it is never
  // rewritten on disk.
  const action =
    typeof record.action === "string"
      ? normalizePolicyAction(record.action)
      : record.action;
  if (typeof action !== "string" || !isActionPattern(action))
    throw invalid(
      source,
      `${path}.action`,
      `action must be one of ${POLICY_ACTIONS.join(", ")}, a known <prefix>.*, or *`,
    );
  const resource =
    record.resource === undefined
      ? "**"
      : plainText(record.resource, source, `${path}.resource`, 1024);
  if (typeof effect !== "string" || !EFFECTS.includes(effect))
    throw invalid(
      source,
      `${path}.effect`,
      "effect must be allow, ask, or deny",
    );
  return {
    id,
    action: action as PolicyRule["action"],
    resource,
    effect: effect as PolicyEffect,
    ...(record.reason === undefined
      ? {}
      : { reason: plainText(record.reason, source, `${path}.reason`, 240) }),
  };
}

/**
 * Validate a JSON rule list: either an array of rules or `{ "rules": [...] }`.
 * Malformed input throws CONFIG_INVALID. With `narrowingOnly`, `allow` rules
 * are dropped and reported, because a narrowing layer never grants anything.
 */
export function parseRuleList(
  value: unknown,
  source: string,
  options: { readonly narrowingOnly: boolean; readonly layer?: PolicyLayer },
): ParsedRuleList {
  let list: unknown = value;
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record))
      if (key !== "rules") throw invalid(source, key, "unknown field");
    list = record.rules ?? [];
  }
  if (!Array.isArray(list))
    throw invalid(source, "rules", "rules must be an array");
  const layer =
    options.layer ??
    (options.narrowingOnly ? "team-project" : "user-preference");
  const rules: PolicyRule[] = [];
  const ignored: IgnoredRule[] = [];
  const diagnostics: PolicyDiagnostic[] = [];
  const seen = new Set<string>();
  list.forEach((item, index) => {
    const rule = parseRule(item, source, `rules[${index}]`);
    if (seen.has(rule.id))
      throw invalid(
        source,
        `rules[${index}].id`,
        `duplicate rule id ${rule.id}`,
      );
    seen.add(rule.id);
    if (options.narrowingOnly && rule.effect === "allow") {
      const why = `${source} is narrowing only; allow rules are ignored`;
      ignored.push({ source, layer, rule, why });
      diagnostics.push({
        level: "warning",
        source,
        ruleId: rule.id,
        message: `Ignored allow rule ${rule.id}: ${why}`,
      });
      return;
    }
    rules.push(rule);
  });
  return { rules, ignored, diagnostics };
}

// ------------------------------------------------------------------ engine

export interface PolicyEngineInput {
  readonly policy: PolicyConfig;
  /** Rules from the policy adapter (team layer, narrowing only). */
  readonly teamRules?: readonly PolicyRule[];
  /** Rules from the project restriction file (team layer, narrowing only). */
  readonly projectRules?: readonly PolicyRule[];
  /** Rules from the user's `config/policy.json` (lowest precedence). */
  readonly userRules?: readonly PolicyRule[];
  /**
   * How user rules combine with the distribution. `replace-default` (the
   * default; personal mode, where the local owner owns the policy) lets a
   * matching user rule take the place of the matching distribution default.
   * `narrowing` (managed mode) treats user rules like team and project rules:
   * `allow` rules are ignored and reported, and the rest can only tighten.
   */
  readonly userRuleMode?: "replace-default" | "narrowing";
  /**
   * Problems reading the rule inputs (such as a project restriction file
   * that could not be read), reported first among the engine's diagnostics.
   */
  readonly diagnostics?: readonly PolicyDiagnostic[];
  readonly context: PolicyContext;
}

interface LayerRule {
  readonly rule: PolicyRule;
  readonly layer: PolicyLayer;
  readonly source: string;
  /** Resource pattern with path tokens expanded, for filesystem actions. */
  readonly pathPattern: string;
}

export interface RuleMatch {
  readonly layer: PolicyLayer;
  readonly source: string;
  readonly ruleId: string;
  readonly effect: PolicyEffect;
  readonly resource: string;
  readonly reason?: string;
  /** True for the first match of its layer, the one that counts. */
  readonly first: boolean;
}

export interface PolicyExplanation {
  readonly decision: PolicyDecision;
  /** The resource as matched (filesystem paths are normalized). */
  readonly resource: string;
  readonly matches: readonly RuleMatch[];
  readonly ignored: readonly (IgnoredRule & { readonly matches: boolean })[];
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export const BUILTIN_DEFAULT_RULE = "builtin:default";
export const BUILTIN_UNKNOWN_ACTION_RULE = "builtin:unknown-action";

export class PolicyEngine {
  readonly id: string;
  readonly context: PolicyContext;
  readonly diagnostics: readonly PolicyDiagnostic[];
  readonly #policy: PolicyConfig;
  readonly #layers: Readonly<Record<PolicyLayer, readonly LayerRule[]>>;
  readonly #ignored: readonly IgnoredRule[];
  readonly #userNarrowing: boolean;

  constructor(input: PolicyEngineInput) {
    this.#policy = input.policy;
    this.id = `${input.policy.id}@${input.policy.version}`;
    this.context = {
      ...normalizeTokenContext(input.context),
      containment: { ...input.context.containment },
    };
    const diagnostics: PolicyDiagnostic[] = [...(input.diagnostics ?? [])];
    const ignored: IgnoredRule[] = [];
    const wrap = (
      rules: readonly PolicyRule[],
      layer: PolicyLayer,
      source: string,
    ): LayerRule[] =>
      rules.map((rule) => ({
        rule: normalizeRuleAction(rule),
        layer,
        source,
        pathPattern: expandPathTokens(rule.resource, this.context),
      }));
    const narrowing = (
      rules: readonly PolicyRule[],
      source: string,
      layer: PolicyLayer = "team-project",
    ): LayerRule[] => {
      const kept: PolicyRule[] = [];
      for (const rule of rules) {
        if (rule.effect !== "allow") {
          kept.push(rule);
          continue;
        }
        const why =
          layer === "user-preference"
            ? `${source} rules are narrowing only in managed mode; allow is ignored`
            : `${source} rules are narrowing only; allow is ignored`;
        ignored.push({ source, layer, rule, why });
        diagnostics.push({
          level: "warning",
          source,
          ruleId: rule.id,
          message: `Ignored allow rule ${rule.id}: ${why}`,
        });
      }
      return wrap(kept, layer, source);
    };
    this.#userNarrowing = input.userRuleMode === "narrowing";
    this.#layers = {
      "distribution-enforced": wrap(
        input.policy.enforced,
        "distribution-enforced",
        "enforced",
      ),
      "team-project": [
        ...narrowing(input.teamRules ?? [], "team"),
        ...narrowing(input.projectRules ?? [], "project"),
      ],
      "distribution-default": wrap(
        input.policy.defaults,
        "distribution-default",
        "defaults",
      ),
      "user-preference": this.#userNarrowing
        ? narrowing(input.userRules ?? [], "user", "user-preference")
        : wrap(input.userRules ?? [], "user-preference", "user"),
    };
    this.#ignored = ignored;
    this.diagnostics = diagnostics;
  }

  /** The resource as rules see it: filesystem paths are normalized. */
  normalizeResource(request: PolicyRequest): string {
    return isPathAction(request.action)
      ? normalizePathResource(request.resource, this.context)
      : request.resource;
  }

  #matches(entry: LayerRule, action: string, resource: string): boolean {
    if (!matchAction(entry.rule.action, action)) return false;
    const pattern = isPathAction(action)
      ? entry.pathPattern
      : entry.rule.resource;
    // Deny rules still match chained commands: the strictest rule wins.
    if (
      action === "shell.execute" &&
      entry.rule.effect !== "deny" &&
      chainsBeyondPattern(pattern, resource)
    )
      return false;
    return matchGlob(pattern, resource);
  }

  /**
   * The first rule of `layer` that matches; with `source`, the first of that
   * source's rules only. Team and project rules share a layer but are matched
   * separately, so a team `ask` never hides a project `deny`.
   */
  #firstMatch(
    layer: PolicyLayer,
    action: string,
    resource: string,
    source?: string,
  ): LayerRule | undefined {
    return this.#layers[layer].find(
      (entry) =>
        (source === undefined || entry.source === source) &&
        this.#matches(entry, action, resource),
    );
  }

  /**
   * The first `ask` rule of a narrowing layer that covers `resource` only
   * because the command chains past its pattern (`git push**` against
   * `git push origin main; true`). First-match skips such a rule, as it skips
   * an allow, so the chained command could fall through to a weaker rule or
   * to a distribution default that auto mode approves. An explicit ask from
   * `policy.enforced`, the team, the project, or the managed user's own rules
   * still applies to it, as a deny does: the extra match can only add an ask
   * to the strictest-wins combination, never hide a stricter effect.
   */
  #chainedAsk(
    layer: PolicyLayer,
    action: string,
    resource: string,
    source?: string,
  ): LayerRule | undefined {
    if (action !== "shell.execute") return undefined;
    return this.#layers[layer].find(
      (entry) =>
        (source === undefined || entry.source === source) &&
        entry.rule.effect === "ask" &&
        matchAction(entry.rule.action, action) &&
        chainsBeyondPattern(entry.rule.resource, resource) &&
        matchGlob(entry.rule.resource, resource),
    );
  }

  /** The explicit asks that keep applying to a chained command. */
  #chainedAsks(action: string, resource: string): (LayerRule | undefined)[] {
    return [
      this.#chainedAsk("distribution-enforced", action, resource),
      this.#chainedAsk("team-project", action, resource, "team"),
      this.#chainedAsk("team-project", action, resource, "project"),
      this.#userNarrowing
        ? this.#chainedAsk("user-preference", action, resource)
        : undefined,
    ];
  }

  evaluate(request: PolicyRequest): PolicyDecision {
    const resource = this.normalizeResource(request);
    return this.#decide(request.action, resource);
  }

  #decide(action: PolicyAction, resource: string): PolicyDecision {
    const common = {
      policyId: this.id,
      action,
      resource,
    };
    if (!(POLICY_ACTIONS as readonly string[]).includes(action))
      return {
        ...common,
        effect: "deny",
        ruleId: BUILTIN_UNKNOWN_ACTION_RULE,
        reason: "Unknown policy action",
        enforcement: "control-plane",
        layer: "builtin",
      };
    const enforced = this.#firstMatch(
      "distribution-enforced",
      action,
      resource,
    );
    const team = this.#firstMatch("team-project", action, resource, "team");
    const project = this.#firstMatch(
      "team-project",
      action,
      resource,
      "project",
    );
    const userRule = this.#firstMatch("user-preference", action, resource);
    // In managed mode a user rule only narrows; otherwise it replaces the
    // matching distribution default.
    const narrowingUser = this.#userNarrowing ? userRule : undefined;
    const base =
      (this.#userNarrowing ? undefined : userRule) ??
      this.#firstMatch("distribution-default", action, resource);
    const baseEffect = base?.rule.effect ?? this.#policy.default;
    const chainedAsks = this.#chainedAsks(action, resource);
    const effect = strictest(
      enforced?.rule.effect,
      team?.rule.effect,
      project?.rule.effect,
      narrowingUser?.rule.effect,
      ...chainedAsks.map((entry) => entry?.rule.effect),
      baseEffect,
    );
    const deciding = [
      enforced,
      team,
      project,
      base,
      narrowingUser,
      ...chainedAsks,
    ].find((entry) => entry?.rule.effect === effect);
    const enforcement = enforcementPlane(action, this.context.containment);
    if (!deciding)
      return {
        ...common,
        effect,
        ruleId: BUILTIN_DEFAULT_RULE,
        reason: `No rule matched; the policy default is ${effect}`,
        enforcement,
        layer: "builtin",
      };
    return {
      ...common,
      effect,
      ruleId: deciding.rule.id,
      ...(deciding.rule.reason === undefined
        ? {}
        : { reason: redact(deciding.rule.reason) }),
      enforcement,
      layer: deciding.layer,
    };
  }

  /**
   * Whether an explicit `ask` keeps the prompt for `request` even while the
   * user's auto mode (`policy.userAuto`) is on: a matching `ask` rule in
   * `policy.enforced`, the team adapter, the project restrictions, or the
   * managed user's own rules. Auto mode approves only an `ask` that comes
   * from the distribution defaults (`policy.defaults` or `policy.default`).
   */
  keepsPrompt(request: PolicyRequest): boolean {
    const resource = this.normalizeResource(request);
    const { action } = request;
    return [
      this.#firstMatch("distribution-enforced", action, resource),
      this.#firstMatch("team-project", action, resource, "team"),
      this.#firstMatch("team-project", action, resource, "project"),
      this.#userNarrowing
        ? this.#firstMatch("user-preference", action, resource)
        : undefined,
      ...this.#chainedAsks(action, resource),
    ].some((entry) => entry?.rule.effect === "ask");
  }

  explain(request: PolicyRequest): PolicyExplanation {
    const resource = this.normalizeResource(request);
    const decision = this.#decide(request.action, resource);
    const matches: RuleMatch[] = [];
    for (const layer of Object.keys(this.#layers) as PolicyLayer[]) {
      // First per source: team and project rules are matched separately.
      const matched = new Set<string>();
      for (const entry of this.#layers[layer]) {
        if (!this.#matches(entry, request.action, resource)) continue;
        const first = !matched.has(entry.source);
        matched.add(entry.source);
        matches.push({
          layer,
          source: entry.source,
          ruleId: entry.rule.id,
          effect: entry.rule.effect,
          resource: entry.rule.resource,
          ...(entry.rule.reason === undefined
            ? {}
            : { reason: redact(entry.rule.reason) }),
          first,
        });
      }
    }
    const ignored = this.#ignored.map((item) => ({
      ...item,
      matches: this.#matches(
        {
          rule: item.rule,
          layer: item.layer,
          source: item.source,
          pathPattern: expandPathTokens(item.rule.resource, this.context),
        },
        request.action,
        resource,
      ),
    }));
    return {
      decision,
      resource,
      matches,
      ignored,
      diagnostics: this.diagnostics,
    };
  }

  /** A `PolicyEvaluator` bound to this engine. */
  get evaluator(): (request: PolicyRequest) => PolicyDecision {
    return (request) => this.evaluate(request);
  }
}
