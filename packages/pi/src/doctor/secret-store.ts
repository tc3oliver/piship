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
  // A credential whose remote revocation failed at a sign-in or user switch
  // is recorded as a non-secret retry entry and re-checked at every login.
  // Its count and age are reported here, never a credential identifier.
  const pending = access.pendingRevocations;
  if (!pending) return;
  if (!pending.readable) {
    out.warn(
      "revocation retries",
      "the pending revocation record is unreadable",
    );
    return;
  }
  if (!pending.count && !pending.dropped) {
    out.ok("revocation retries", "none pending");
    return;
  }
  out.warn(
    "revocation retries",
    `pending revocation retries: ${pending.count}${pending.oldestAgeSeconds === null ? "" : `, oldest ${age(pending.oldestAgeSeconds)}`}${pending.dropped ? `; ${pending.dropped} older not listed` : ""}`,
  );
  out.warn(
    "revocation",
    "a replaced credential could not be revoked and may still be valid at the provider until it expires or an administrator revokes it",
  );
}

/** A short age: seconds, minutes, hours, or days. */
function age(seconds: number): string {
  if (seconds < 120) return `${seconds}s`;
  if (seconds < 7200) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 172_800) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86_400)}d`;
}
