import { dirname, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import {
  BUILTIN_DEFAULT_RULE,
  manifestContainment,
  PolicyEngine,
  type UnenforcedFinding,
  unenforcedAction,
  unenforcedRules,
} from "@piship/policy";
import type { Manifest, ValidationDiagnostic } from "@piship/schema";
import { withSessionExportRules } from "./data/session-export.js";
import { checkPackageTrust } from "./pi-packages/trust.js";
import type { LockedResource } from "./lock-schema.js";
import { resolveResources } from "./resources.js";
import {
  assertIntegrity,
  assertNoInstallScripts,
  filesUnder,
  type GovernanceLock,
  treeDigest,
} from "./trust.js";

/** Certified digests and provider versions; any tampering or install script fails. */
export function governanceLock(
  manifest: Manifest,
  base: string,
  resources: readonly LockedResource[],
): GovernanceLock | undefined {
  const governance = manifest.governance;
  if (!governance) return undefined;
  checkPackageTrust(manifest);
  const certified = governance.resources.declared
    .filter((item) => item.class === "certified" && item.certified)
    .map((item) => {
      const field = `resources.${item.kind}.certified`;
      const files = filesUnder(
        resources.filter((entry) => entry.kind === item.kind),
        item.path,
      );
      assertNoInstallScripts(resolve(base, item.path), files, field);
      const integrity = treeDigest(files);
      const evidence = item.certified as NonNullable<typeof item.certified>;
      assertIntegrity(integrity, evidence.integrity, field);
      return { kind: item.kind, path: item.path, evidence, integrity };
    });
  const providers = governance.capabilities.flatMap((capability) => {
    const provider = capability.provider;
    if (!provider) return [];
    const field = `capabilities.${capability.name}.provider`;
    let integrity: string | undefined;
    if (provider.path) {
      const files = filesUnder(
        resources.filter((entry) => entry.kind === "providers"),
        provider.path,
      );
      assertNoInstallScripts(resolve(base, provider.path), files, field);
      integrity = treeDigest(files);
      if (provider.certified)
        assertIntegrity(integrity, provider.certified.integrity, field);
    }
    // A package provider is the package's extensions, reviewed and locked as
    // the package: its class and evidence are the package's own.
    const evidence =
      provider.certified ??
      governance.resources.packages?.find(
        (item) => item.id === provider.package,
      )?.certified;
    return [
      {
        capability: capability.name,
        id: provider.id,
        class: provider.class,
        version: provider.version,
        implements: provider.implements,
        ...(provider.path ? { path: provider.path } : {}),
        ...(provider.package ? { package: provider.package } : {}),
        ...(integrity ? { integrity } : {}),
        ...(evidence ? { certified: evidence } : {}),
      },
    ];
  });
  return { manifest: governance, certified, providers };
}
/**
 * Check-only form of the lock-time governance checks: certified resource and
 * capability-provider tree integrity and install-script rejection. Throws the
 * same errors as `piship lock` and writes nothing.
 */
export function checkGovernance(
  manifest: Manifest,
  manifestPath: string,
  resources: readonly LockedResource[] = resolveResources(
    manifest,
    manifestPath,
  ),
): void {
  governanceLock(manifest, dirname(resolve(manifestPath)), resources);
}

const LOAD_ACTION = {
  instructions: "instruction.load",
  skills: "skill.load",
  extensions: "extension.load",
  prompts: "resource.load",
  themes: "resource.load",
} as const;

/**
 * Declared resources, MCP servers, and directly exposed MCP tools that only
 * `policy.default` decides, when that default is `ask`: each asks at every
 * launch and headless runs leave it out. An explicit `ask` or `deny` rule is
 * the administrator's choice and is not reported.
 */
export function unapprovedLoadWarnings(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const governance = manifest.governance;
  if (!governance) return [];
  // Load and MCP decisions do not depend on paths or containment.
  const engine = new PolicyEngine({
    policy: governance.policy,
    context: {
      workspaceRoot: "/",
      homeDir: "/",
      tmpDir: "/",
      containment: manifestContainment(governance, manifest.deployment.mode),
    },
  });
  const warnings: ValidationDiagnostic[] = [];
  const check = (
    path: string,
    what: string,
    action:
      | (typeof LOAD_ACTION)[keyof typeof LOAD_ACTION]
      | "mcp.server.start"
      | "mcp.tool.call",
    resource: string,
    glob: string,
  ) => {
    const decision = engine.evaluate({ action, resource });
    if (decision.effect === "ask" && decision.ruleId === BUILTIN_DEFAULT_RULE)
      warnings.push({
        path,
        message: `${what}: no policy rule allows ${action} ${resource}, so policy.default (ask) asks at every launch and headless runs leave it out; add a policy.defaults allow rule for ${action} on "${glob}"`,
      });
  };
  for (const item of governance.resources.declared)
    check(
      `resources.${item.kind}.${item.class}`,
      item.path,
      LOAD_ACTION[item.kind],
      `${item.class}:${item.path}`,
      `${item.class}:**`,
    );
  for (const name of governance.resources.builtin)
    check(
      "resources.extensions.builtin",
      name,
      "extension.load",
      `builtin:${name}`,
      "builtin:**",
    );
  if (governance.mcp.mode !== "off")
    for (const server of governance.mcp.servers) {
      check(
        `mcp.servers.${server.id}`,
        `MCP server ${server.id}`,
        "mcp.server.start",
        server.id,
        server.id,
      );
      for (const rule of server.toolExposure ?? [])
        if (rule.exposure !== "hidden" && !/[*?[\]{}]/.test(rule.pattern))
          check(
            `mcp.servers.${server.id}.tools.${rule.pattern}`,
            `MCP tool ${server.id}:${rule.pattern}`,
            "mcp.tool.call",
            `${server.id}:${rule.pattern}`,
            `${server.id}:*`,
          );
    }
  return warnings;
}

/**
 * A shell.execute deny or ask rule whose resource uses `*` but no `**`: `*`
 * stops at `/`, so `rm -rf *` lets `rm -rf /` and `rm -rf ./x` through.
 */
export function shellGlobWarnings(manifest: Manifest): ValidationDiagnostic[] {
  const policy = manifest.governance?.policy;
  if (!policy) return [];
  return [
    ...policy.enforced.map((rule) => ["enforced", rule] as const),
    ...policy.defaults.map((rule) => ["defaults", rule] as const),
  ].flatMap(([layer, rule]) =>
    rule.action === "shell.execute" &&
    rule.effect !== "allow" &&
    rule.resource.includes("*") &&
    !rule.resource.includes("**")
      ? [
          {
            path: `policy.${layer}.${rule.id}`,
            message: `"${rule.resource}" does not match arguments containing /; use ** (for example "${rule.resource.replaceAll("*", "**")}")`,
          },
        ]
      : [],
  );
}

const LOAD_ACTIONS = new Set<string>([
  "resource.load",
  "skill.load",
  "instruction.load",
  "extension.load",
]);

/**
 * Rules that parse but can never match: a `git.push` resource is
 * `<remote>/<branch>`, and a load resource is `<class>:./<path>` or
 * `<class>:**`.
 */
export function inertRuleWarnings(manifest: Manifest): ValidationDiagnostic[] {
  const policy = manifest.governance?.policy;
  if (!policy) return [];
  return [
    ...policy.enforced.map((rule) => ["enforced", rule] as const),
    ...policy.defaults.map((rule) => ["defaults", rule] as const),
  ].flatMap(([layer, rule]) => {
    const path = `policy.${layer}.${rule.id}`;
    if (rule.action === "git.push" && /\s/.test(rule.resource))
      return [
        {
          path,
          message: `"${rule.resource}" never matches: a git.push resource is <remote>/<branch> (for example "origin/main"), not a command`,
        },
      ];
    if (
      rule.action === "git.push" &&
      !rule.resource.includes("/") &&
      !rule.resource.includes("**")
    )
      return [
        {
          path,
          message: `"${rule.resource}" never matches: a git.push resource is <remote>/<branch> (for example "origin/${rule.resource}", or "**/${rule.resource}" for any remote)`,
        },
      ];
    // `<class>:` then `./...` or a glob; builtin and project resources are
    // named differently (`builtin:<name>`, `project:<path>`).
    const colon = rule.resource.indexOf(":");
    const rest = rule.resource.slice(colon + 1);
    if (
      LOAD_ACTIONS.has(rule.action) &&
      ["certified", "company", "user"].includes(
        rule.resource.slice(0, colon),
      ) &&
      !rest.startsWith("./") &&
      !rest.startsWith("*")
    )
      return [
        {
          path,
          message: `"${rule.resource}" never matches: a ${rule.action} resource is <class>:./<path> or <class>:** (for example "company:./resources/skills/**")`,
        },
      ];
    return [];
  });
}

/**
 * Rules that deny or ask for an action no runtime seam enforces. A managed
 * finding that is neither acknowledged nor audit-only throws
 * POLICY_UNENFORCEABLE; the rest are returned for display.
 */
export function checkEnforceability(manifest: Manifest): UnenforcedFinding[] {
  const governance = manifest.governance;
  if (!governance) return [];
  const findings = unenforcedRules(
    manifest.deployment.mode,
    withSessionExportRules(governance.policy, manifest.data),
    manifestContainment(governance, manifest.deployment.mode),
  );
  const errors = findings.filter((item) => item.level === "error");
  if (errors.length)
    throw new PiShipError(
      "POLICY_UNENFORCEABLE",
      errors.map((item) => item.message).join("\n"),
      {
        component: "policy",
        userAction: unenforcedAction(errors),
      },
    );
  return findings;
}
