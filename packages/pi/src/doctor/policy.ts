// Policy group: the policy engine, its rule counts, and layering diagnostics.
import { describeUserAuto } from "@piship/core";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

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
  // Shown where auto mode exists or a stored switch no longer applies.
  const auto = inspection.userAuto;
  if (auto.allowed || auto.state === "inert") {
    const line = describeUserAuto(auto);
    if (auto.state === "on" || auto.state === "off") out.ok("auto", line);
    else out.warn("auto", line);
  }
  for (const diagnostic of inspection.engine.diagnostics)
    out.warn(diagnostic.source, diagnostic.message);
}
