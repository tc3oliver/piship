// Policy group: the policy engine, its rule counts, rules no runtime seam
// enforces, and layering diagnostics.
import {
  describeUserAuto,
  sessionExportStatus,
  withSessionExportRules,
} from "@piship/core";
import {
  manifestContainment,
  matchAction,
  unenforcedRules,
} from "@piship/policy";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

// What a package permission provider decides for the user: tool calls, bash
// commands, paths, and MCP calls.
const PROVIDER_GOVERNED_ACTIONS = new Set([
  "tool.execute",
  "shell.execute",
  "filesystem.read",
  "filesystem.write",
  "mcp.tool.call",
]);

export function policyGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  if (!governance) return;
  if (governance.inspectionError) {
    out.bad("policy", governance.inspectionError);
    return;
  }
  const inspection = governance.inspection;
  if (!inspection) return;
  const policy = governance.manifest.policy;
  out.ok("policy", `${inspection.engine.id}; default ${policy.default}`);
  out.ok(
    "rules",
    `${policy.enforced.length} enforced, ${policy.defaults.length} defaults${policy.adapter ? ", team adapter" : ""}`,
  );
  // Rules on an action no runtime seam enforces never read as enforced;
  // `data.export.<r>` counts as the enforced rule it is sugar for.
  const containment = manifestContainment(governance.manifest, data.ctx.mode);
  const declaredData = data.ctx.metadata.data?.declared;
  for (const item of unenforcedRules(
    data.ctx.mode,
    withSessionExportRules(policy, declaredData),
    containment,
  )) {
    const line = `${item.status}${item.level === "info" ? " (acknowledged)" : ""}: rule ${item.ruleId} (${item.effect} ${item.resource})`;
    if (item.level === "info") out.info(item.action, line);
    else if (item.level === "warning") out.warn(item.action, line);
    else out.bad(item.action, line);
  }
  // Always shown, whatever the manifest declares: Pi's /share gist fallback
  // and /export have no seam, and leaving the rule out must not hide that.
  const acknowledged = new Set(policy.acknowledgeUnenforced ?? []);
  out.info(
    "session export",
    Object.entries(sessionExportStatus(containment))
      .map(
        ([resource, status]) =>
          `${resource} ${status}${status !== "enforced" && acknowledged.has(`session.export:${resource}`) ? " (acknowledged)" : ""}`,
      )
      .join(", "),
  );
  // Shown where auto mode exists or a stored switch no longer applies.
  const auto = inspection.userAuto;
  if (auto.allowed || auto.state === "inert") {
    const line = describeUserAuto(auto);
    if (auto.state === "on" || auto.state === "off") out.ok("auto", line);
    else out.warn("auto", line);
  }
  // PiShip cannot answer the provider's own prompts, so an `ask` on both sides
  // can prompt twice for one action. Only the distribution's own policy is
  // read, not user, team, or project rules.
  const permissions = governance.manifest.capabilities.find(
    (item) => item.name === "permissions",
  );
  if (permissions?.enabled && permissions.provider?.package) {
    const asks = [...policy.enforced, ...policy.defaults]
      .filter(
        (rule) =>
          rule.effect === "ask" &&
          [...PROVIDER_GOVERNED_ACTIONS].some((action) =>
            matchAction(rule.action, action),
          ),
      )
      .map((rule) => `${rule.action} ${rule.resource} (rule ${rule.id})`);
    if (policy.default === "ask")
      asks.push(
        "the provider's actions not covered by a rule (policy.default)",
      );
    if (asks.length > 0)
      out.warn(
        "double ask",
        `PiShip asks for ${asks.join(", ")}, and the permission provider ${permissions.provider.package} also decides these actions, so you can be asked twice. This reads only the distribution's own policy, not user, team, or project rules. Set the PiShip rule or policy.default to allow for them, or let the provider own the question`,
      );
  }
  for (const diagnostic of inspection.engine.diagnostics)
    out.warn(diagnostic.source, diagnostic.message);
}
