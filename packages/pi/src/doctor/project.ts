// Project group: the project's origin and each discovered project item with
// its effect.
import { decisionRule } from "@piship/policy";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

/** Who can change a project trust deny: the person in personal mode, IT otherwise. */
function trustHint(
  data: DoctorData,
  origin: string,
  dimension: string,
): string {
  const field = `policy.projectTrust.${origin}.${dimension}`;
  return data.ctx.mode === "managed"
    ? `your administrator sets this (${field} in piship.yaml)`
    : `set ${field} in piship.yaml to load it`;
}

export function projectGroup(data: DoctorData, out: DoctorSection): void {
  const inspection = data.governance?.inspection;
  if (!inspection) return;
  if (
    data.ctx.mode === "managed" &&
    inspection.resources.some(
      (item) =>
        item.kind === "extensions" &&
        item.loaded &&
        /(?:^|\/)extensions\/mcp(?:\/|\.)/.test(item.path),
    )
  )
    out.warn(
      "extension MCP",
      "A package MCP extension can start project servers outside PiShip governance using user consent. Managed pi-code distributions must exclude !extensions/mcp/**.",
    );
  out.ok("origin", `${inspection.project.origin} (${inspection.project.root})`);
  for (const candidate of inspection.candidates) {
    if (candidate.dimension === "restrictions") continue;
    const line = `${candidate.path}: ${candidate.effect} (${candidate.reason})`;
    // Project trust admits the item; policy still decides it at launch.
    const decision = inspection.projectDecisions.get(candidate.path);
    if (candidate.effect === "deny")
      out.warn(
        candidate.kind,
        `${line}; ${trustHint(data, candidate.origin, candidate.dimension)}`,
      );
    else if (decision?.effect === "deny")
      out.warn(
        candidate.kind,
        `${candidate.path}: not loaded, denied by ${decisionRule(decision)}`,
      );
    else if (decision?.effect === "ask")
      out.warn(
        candidate.kind,
        `${candidate.path}: asks at each launch and is left out of headless runs (${decisionRule(decision)}); a policy.defaults allow for ${decision.action} project:** loads it without a prompt`,
      );
    else out.ok(candidate.kind, line);
  }
  const trust = inspection.extensionTrust;
  if (!trust) return;
  // Whether extensions such as pi-code get the project's Claude Code
  // configuration; not the `extensions` trust dimension.
  const label = "Claude Code config";
  const reason = `${trust.decidedBy ? `${trust.decidedBy.path}: ` : ""}${trust.reason}`;
  // Nothing found and the managed default withholding trust is the intended
  // state of a project the policy does not know, not a problem to fix.
  if (trust.effect === "deny" && trust.surfaces.length === 0)
    out.info(
      label,
      `not trusted (${inspection.project.origin} project; nothing to load here)`,
    );
  else if (trust.effect === "deny")
    out.warn(
      label,
      `not trusted for extensions that honor Pi project trust; user-consented extension MCP servers can still load (${reason})`,
    );
  else if (trust.effect === "ask")
    out.info(
      label,
      "asks at launch; extensions such as pi-code load the project Claude Code configuration only when it is approved",
    );
  else if (trust.surfaces.length === 0) out.info(label, "none found");
  else out.ok(label, `trusted (${trust.reason})`);
}
