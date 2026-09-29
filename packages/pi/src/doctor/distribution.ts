// Distribution group: what is running.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function distributionGroup(data: DoctorData, out: DoctorSection): void {
  const { app, runtime } = data.ctx.metadata;
  out.ok(app.name, `${app.version} (${data.ctx.mode})`);
  out.ok("PiShip", runtime.pishipVersion);
  out.ok("Pi", data.piVersion);
}
