// Project group: the project's origin and each discovered project item with
// its effect.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

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
    if (candidate.effect === "deny") out.warn(candidate.kind, line);
    else out.ok(candidate.kind, line);
  }
  const trust = inspection.extensionTrust;
  if (!trust) return;
  const label = "project trust for extensions";
  const reason = `${trust.decidedBy ? `${trust.decidedBy.path}: ` : ""}${trust.reason}`;
  if (trust.effect === "deny")
    out.warn(
      label,
      `not trusted for extensions that honor Pi project trust; user-consented extension MCP servers can still load (${reason})`,
    );
  else if (trust.effect === "ask")
    out.info(
      label,
      "asks at launch; extensions such as pi-code load the project Claude Code configuration only when it is approved",
    );
  else out.ok(label, `trusted (${trust.reason})`);
}
