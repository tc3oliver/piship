// MCP group: each declared server as doctor's governed session started it.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function mcpGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  if (!governance?.inspection) return;
  if (governance.sessionError) {
    out.bad("launch controls", governance.sessionError);
    return;
  }
  if (!governance.mcp) {
    out.info("mcp", "not started; the governed session did not open");
    return;
  }
  for (const server of governance.mcp) {
    const label = `mcp ${server.id}`;
    const detail = `${server.state} (${server.transport}${server.tools.length ? `; ${server.tools.length} tool(s)` : ""})${server.reason ? `: ${server.reason}` : ""}`;
    if (server.state === "healthy") out.ok(label, detail);
    else if (server.state === "denied") out.warn(label, detail);
    else if (server.required) out.bad(label, detail);
    else out.warn(label, detail);
  }
  if (!governance.manifest.mcp.servers.length)
    out.ok("mcp", "no servers declared");
  if (governance.shutdownError) out.bad("shutdown", governance.shutdownError);
}
