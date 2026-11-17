// Distribution group: what is running, and where it keeps its state.
import { join } from "node:path";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function distributionGroup(data: DoctorData, out: DoctorSection): void {
  const { app, runtime } = data.ctx.metadata;
  out.ok(app.name, `${app.version} (${data.ctx.mode})`);
  out.ok("PiShip", runtime.pishipVersion);
  out.ok("Pi", data.piVersion);
  out.info("state", data.ctx.stateDir);
  // As the session command resolves it: per principal once signed in.
  const sessions = join(data.ctx.stateDir, "sessions", "user");
  const principal = data.access?.sessionPrincipal;
  out.info(
    "sessions",
    principal
      ? join(sessions, principal)
      : data.access && data.access.manifest.identity.mode !== "none"
        ? `${sessions} (a subdirectory per signed-in user)`
        : sessions,
  );
}
