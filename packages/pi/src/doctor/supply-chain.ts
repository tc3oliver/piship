// Supply Chain group: manifest, lock, and payload verification.
import { lifecycleDoctor } from "@piship/core";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function supplyChainGroup(data: DoctorData, out: DoctorSection): void {
  lifecycleDoctor(data.ctx, "Supply Chain", out.ok, out.warn);
}
