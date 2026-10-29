// DoctorVerification group: the runtime, the company configuration, and the
// integration on this machine, as three separate states.
import { verificationStates } from "@piship/core";
import type { DoctorData } from "./data.js";
import type { DoctorReport } from "./report.js";

export function verificationGroup(
  data: DoctorData,
  report: DoctorReport,
): void {
  const out = report.section("Verification");
  const states = verificationStates(data.ctx, data.metrics);
  report.setVerification(states);
  for (const [label, item] of [
    ["runtime", states.runtime],
    ["company config", states.config],
    ["integration", states.integration],
  ] as const) {
    const line =
      item.state === "local"
        ? out.warn
        : item.state === "verified"
          ? out.ok
          : out.info;
    line(label, `${item.state}: ${item.detail}`);
  }
}
