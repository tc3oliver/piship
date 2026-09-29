// Policy group: the policy engine, its rule counts, and layering diagnostics.
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
  for (const diagnostic of inspection.engine.diagnostics)
    out.warn(diagnostic.source, diagnostic.message);
}
