// Workspace group: whether the sandbox sees the project files the agent
// edits, and how (shared, synchronized, or a snapshot). The containment
// report does not carry workspace fields yet, so the group says it is not
// reported rather than guess from the backend. When the sandbox reports them,
// only `workspaceData` changes.
import type { GovernanceInspection } from "../governance-session.js";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export interface WorkspaceData {
  /** The effective workspace mode the sandbox verified, when it reports one. */
  readonly consistency?: string;
}

/** The workspace facts of the inspected sandbox; none are reported yet. */
export function workspaceData(
  _inspection: GovernanceInspection | undefined,
): WorkspaceData {
  return {};
}

export function workspaceGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  if (!governance?.inspection) return;
  const { consistency } = governance.workspace;
  if (consistency) out.ok("consistency", consistency);
  else
    out.info(
      "consistency",
      "not reported; the sandbox backend does not report workspace consistency yet",
    );
}
