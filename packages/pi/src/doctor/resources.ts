// Resources group: each declared and builtin resource with its trust class,
// integrity, and whether it loads.
import { KIND_ACTION } from "../governance/options.js";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function resourcesGroup(data: DoctorData, out: DoctorSection): void {
  const inspection = data.governance?.inspection;
  if (!inspection) return;
  for (const item of inspection.resources) {
    const label = `${item.class} ${item.kind}`;
    const detail = `${item.path}${item.integrity === "verified" ? " (integrity verified)" : ""}`;
    if (item.asks)
      out.warn(
        label,
        `${detail}: asks at each launch and is left out of headless runs (${item.reason}); a policy.defaults allow for ${KIND_ACTION[item.kind] ?? "resource.load"} ${item.class}:** loads it without a prompt`,
      );
    else if (item.loaded) out.ok(label, detail);
    else if (item.class === "certified" && item.integrity !== "verified")
      out.bad(label, `${detail}: ${item.reason}`);
    else out.warn(label, `${detail}: not loaded, ${item.reason}`);
  }
}
