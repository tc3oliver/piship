// Project group: the project's origin and each discovered project item with
// its effect.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function projectGroup(data: DoctorData, out: DoctorSection): void {
  const inspection = data.governance?.inspection;
  if (!inspection) return;
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
      `not trusted, so extensions such as pi-code load no project Claude Code configuration (${reason})`,
    );
  else if (trust.effect === "ask")
    out.info(
      label,
      "asks at launch; extensions such as pi-code load the project Claude Code configuration only when it is approved",
    );
  else out.ok(label, `trusted (${trust.reason})`);
}
