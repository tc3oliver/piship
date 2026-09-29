// Workspace group: whether the sandbox sees the project files the agent
// edits, and how (shared, synchronized, or a snapshot), from the containment
// report. Doctor never runs the workspace check itself: it writes nothing
// into the project, so a shared or synchronized remote workspace shows as
// pending until a session's first sandboxed command verifies it.
import type { WorkspaceReport } from "@piship/sandbox";
import type { GovernanceInspection } from "../governance-session.js";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export interface WorkspaceData {
  /** The effective workspace mode, or `pending` before verification. */
  readonly consistency?: string;
  readonly declared?: WorkspaceReport["declared"];
  readonly verification?: WorkspaceReport["verification"];
  readonly verifiedAt?: string;
  /** Why the effective mode is lower than declared; never a path or token. */
  readonly reason?: string;
  readonly complete?: boolean;
  readonly gitControl?: WorkspaceReport["gitControlProtection"];
  /** Commands run on this host (a local backend). */
  readonly local?: boolean;
  /** No sandbox is enforced, so commands run on this host's files. */
  readonly uncontained?: boolean;
}

/** The workspace facts of the inspected sandbox. */
export function workspaceData(
  inspection: GovernanceInspection | undefined,
): WorkspaceData {
  const report = inspection?.sandbox;
  if (!report) return {};
  if (report.level !== "enforced") return { uncontained: true };
  const workspace = report.workspace;
  if (!workspace) return {};
  return {
    consistency:
      workspace.verification === "pending" ? "pending" : workspace.effective,
    declared: workspace.declared,
    verification: workspace.verification,
    ...(workspace.verifiedAt ? { verifiedAt: workspace.verifiedAt } : {}),
    ...(workspace.reason ? { reason: workspace.reason } : {}),
    complete: workspace.complete,
    gitControl: workspace.gitControlProtection,
    local: report.isolation === "local",
  };
}

const VERIFICATION_TEXT = {
  "not-required": "not required",
  pending:
    "pending: verified before the first sandboxed command; not run by doctor",
  verified: "verified",
  unverifiable: "unverifiable",
  failed: "failed",
} as const;

const GIT_CONTROL_TEXT = {
  verified: "verified by the live probe",
  "attested-renames":
    "verified from outside (writes); renames ruled out by mount and permission structure, not tried",
  pending: "pending: checked before the first sandboxed command",
  "not-verified": "not verified; sandboxed commands may be able to change them",
  "not-applicable": "n/a (the sandbox cannot reach this host's files)",
} as const;

export function workspaceGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  if (!governance?.inspection) return;
  const workspace = governance.workspace;
  if (workspace.uncontained) {
    out.info(
      "consistency",
      "none: no sandbox is enforced; commands run on this host's files",
    );
    return;
  }
  const { consistency, verification } = workspace;
  if (!consistency || !verification) {
    out.info("consistency", "not reported by the sandbox backend");
    return;
  }
  if (workspace.local)
    out.ok("consistency", "shared (commands run on this host's files)");
  else if (consistency === "pending")
    out.info("consistency", `pending (${workspace.declared} declared)`);
  else if (workspace.complete) out.ok("consistency", consistency);
  else if (workspace.declared !== "snapshot")
    out.warn(
      "consistency",
      `${consistency}, lower than the declared ${workspace.declared}${workspace.reason ? `: ${workspace.reason}` : ""}`,
    );
  else out.info("consistency", consistency);
  if (!workspace.local) out.info("declared", workspace.declared ?? "snapshot");
  // Doctor never runs the check; a launch records its last result in local
  // metrics, shown when it was made under the same declaration.
  const last = data.metrics.workspace;
  const recorded =
    verification === "pending" && last && last.declared === workspace.declared
      ? `; last session check ${last.verification} (${last.effective}) at ${last.checkedAt}`
      : "";
  out.info(
    "verification",
    `${VERIFICATION_TEXT[verification]}${workspace.verifiedAt ? ` at ${workspace.verifiedAt}` : ""}${recorded}`,
  );
  if (workspace.complete)
    out.ok("complete", "yes: a complete coding-agent workspace");
  else if (consistency === "pending")
    out.info("complete", "not until verified");
  else
    out.info(
      "complete",
      "no: remote commands do not see the files the agent edits",
    );
  const gitControl = workspace.gitControl ?? "not-verified";
  if (gitControl === "not-verified")
    out.warn("git control files", GIT_CONTROL_TEXT[gitControl]);
  else out.info("git control files", GIT_CONTROL_TEXT[gitControl]);
}
