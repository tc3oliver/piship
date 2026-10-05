// Supply Chain group: manifest, lock, and payload verification, and the
// bundled search tools.
import { lifecycleDoctor } from "@piship/core";
import { searchToolStatus } from "../launch/search-tools.js";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function supplyChainGroup(data: DoctorData, out: DoctorSection): void {
  lifecycleDoctor(data.ctx, "Supply Chain", out.ok, out.warn);
  for (const tool of searchToolStatus(data.ctx.metadata, data.ctx.agentDir))
    if (tool.pinned)
      out.ok(
        `search tool ${tool.tool}`,
        `${tool.version} bundled; Pi runs it from its tool directory before PATH`,
      );
    else
      out.bad(
        `search tool ${tool.tool}`,
        `${tool.version} is bundled but Pi's tool directory does not hold the pinned executable; start the command again to restore it`,
      );
}
