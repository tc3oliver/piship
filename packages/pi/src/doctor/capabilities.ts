// Capabilities group: whether each capability is effective, and why not.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function capabilitiesGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  const inspection = governance?.inspection;
  if (!governance || !inspection) return;
  for (const state of inspection.capabilities) {
    const effective = state.axes.effective;
    const provider = state.provider ? ` via ${state.provider}` : "";
    const declared = governance.manifest.capabilities.find(
      (item) => item.name === state.name,
    );
    if (effective.value === "yes") out.ok(state.name, `effective${provider}`);
    else if (!declared?.enabled) out.ok(state.name, `disabled${provider}`);
    else
      out.bad(
        state.name,
        `not effective${provider}: ${effective.reason ?? ""}`,
      );
  }
}
