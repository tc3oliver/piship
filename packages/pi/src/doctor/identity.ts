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
  // A workload identity is never stored: whether a (stale) session is on
  // disk says nothing about it, and the activation shows whether it works.
  if (access.workload)
    if (access.identityError) out.bad("session", access.identityError);
    else out.ok("session", "workload identity, obtained per run");
  else if (access.signedIn)
    if (access.identityError)
      // A stored session is only shown working when activation used it.
      out.bad(
        "session",
        "stored, but activation could not use it; see the Inference activation line",
      );
    else if (access.activationError || access.tlsError)
      out.warn(
        "session",
        "stored; not verified, because activation failed before using it",
      );
    else out.ok("session", "signed in");
  else
    out.bad(
      "session",
      `not signed in; run ${data.ctx.metadata.app.command} login`,
    );
  if (!access.issuer) return;
  // The issuer is shown as answering only when doctor reached it.
  const path = access.network.paths?.find((item) => item.label === "identity");
  if (path?.error)
    (access.activationError ? out.bad : out.warn)(
      "issuer",
      `${access.issuer} does not answer (${path.error}); sign-in and session refresh fail until it does`,
    );
  else if (path) out.ok("issuer", `${access.issuer} answers`);
  else out.info("issuer", access.issuer);
}
