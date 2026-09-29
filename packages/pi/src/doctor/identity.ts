// Identity group: the identity mode and whether a session is stored. No
// claim of the session is shown (subject, name, email, groups): the issuer
// comes from the distribution's configuration.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function identityGroup(data: DoctorData, out: DoctorSection): void {
  const access = data.access;
  if (!access) {
    out.ok(
      "mode",
      "personal Pi-native (no identity; Pi auth in isolated state)",
    );
    return;
  }
  if (access.configError) out.bad("configuration", access.configError);
  const { mode } = access.manifest.identity;
  out.ok("mode", mode);
  if (mode === "none" || access.configError) return;
  if (access.signedIn) out.ok("session", "signed in");
  else
    out.bad(
      "session",
      `not signed in; run ${data.ctx.metadata.app.command} login`,
    );
  if (access.issuer) out.ok("issuer", access.issuer);
}
