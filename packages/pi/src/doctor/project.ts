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
}
