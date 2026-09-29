// Update group: release tracking, channel, update trust, and rollback.
import { lifecycleDoctor } from "@piship/core";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function updateGroup(data: DoctorData, out: DoctorSection): void {
  lifecycleDoctor(data.ctx, "Update", out.ok, out.warn);
}
