// Sandbox group: the backend, containment level and guarantees, how commands
// are isolated from this host, and what the sandbox does not contain.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

const ISOLATION_TEXT = {
  local: "local (commands run on this host inside the sandbox)",
  remote: "remote (commands run on another machine; host files unreachable)",
  none: "none (tool subprocesses run with the user's privileges)",
} as const;

export function sandboxGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  const inspection = governance?.inspection;
  if (!governance || !inspection) return;
  const report = inspection.sandbox;
  out.ok("provider", report.provider);
  const containment = `${report.level} (${report.adapter}${report.planes.length ? `: ${report.planes.join(", ")}` : ""})`;
  if (report.level === "enforced") out.ok("containment", containment);
  else if (report.required)
    out.bad("containment", `${containment}: ${report.reason ?? "required"}`);
  else
    out.warn(
      "containment",
      `${containment}${report.reason ? `: ${report.reason}` : ""}`,
    );
  if (governance.isolation)
    out.ok("isolation", ISOLATION_TEXT[governance.isolation]);
  out.ok("network", report.network);
  out.ok(
    "scope",
    "tool subprocesses and MCP stdio servers; Pi and in-process extensions are not contained",
  );
  out.info("summary", inspection.containment);
  for (const warning of report.warnings) out.warn("sandbox", warning);
}
