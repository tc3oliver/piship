// Secret Store group: where PiShip keeps identity and credential secrets,
// and how well that place protects them. Never a secret, a reference, or a
// store entry name.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function secretStoreGroup(data: DoctorData, out: DoctorSection): void {
  const access = data.access;
  if (!access) {
    out.info(
      "backend",
      "not used; Pi keeps its own auth in the isolated state",
    );
    return;
  }
  if (access.configError) return;
  const store = access.store;
  if (!store)
    out.info("backend", "not used; this distribution stores no PiShip secret");
  else if (store.kind === "file") out.warn("backend", store.description);
  else out.ok("backend", store.description);
  // Reserved for the pending revocation retries line: a credential whose
  // broker or gateway revoke failed at a user switch is recorded as a
  // non-secret retry entry and retried at the next login. When that record
  // exists, report its count here, with no credential identifier.
}
