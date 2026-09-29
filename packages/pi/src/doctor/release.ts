// Release group: where the running payload came from.
import { lifecycleDoctor } from "@piship/core";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function releaseGroup(data: DoctorData, out: DoctorSection): void {
  lifecycleDoctor(data.ctx, "Release", out.ok, out.warn);
}
