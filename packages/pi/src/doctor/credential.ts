// Credential group: the runtime credential's provider and state, never its
// value, reference, or identifier.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function credentialGroup(data: DoctorData, out: DoctorSection): void {
  const access = data.access;
  if (!access) return;
  out.ok("provider", access.manifest.credential.provider);
  if (!access.configError) {
    const credential = access.credential;
    const login = `run ${data.ctx.metadata.app.command} login`;
    if (credential?.state === "valid")
      out.ok(
        "valid",
        credential.remainingSeconds === undefined
          ? "no expiry"
          : `${Math.floor(credential.remainingSeconds / 60)}m remaining`,
      );
    else if (credential?.state === "expiring")
      out.warn(
        "valid",
        `expiring in ${credential.remainingSeconds ?? 0}s; refresh on next use`,
      );
    else if (credential?.state === "delegated")
      out.ok("state", "delegated (no PiShip secret)");
    else if (credential?.state === "rejected")
      out.warn("state", "rejected by the gateway; renewed on next use");
    else out.bad("state", `${credential?.state ?? "unknown"}; ${login}`);
  }
  if (data.ctx.mode === "managed")
    out.ok(
      "ambient credentials",
      "removed from the managed runtime environment",
    );
}
