// PiShip's project-trust decision, handed to Pi's public trust seam. Extensions
// ask Pi whether the project is trusted (`ctx.isProjectTrusted()`, the
// in-memory settings' flag) and, for configuration Pi itself never gates, keep
// their own decision in Pi's trust store under the agent directory (pi-code
// does both). PiShip sets the flag and writes that store from its policy, so
// the answer an extension reads is PiShip's, never the person's click or a
// file the project ships.
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { ProjectTrustStore } from "@earendil-works/pi-coding-agent";
import type { GovernanceSession } from "../governance-session.js";

function samePath(left: string, right: string): boolean {
  const real = (path: string): string => {
    try {
      return realpathSync(path);
    } catch {
      return resolve(path);
    }
  };
  return real(left) === real(right);
}

/**
 * Keep Pi's trust store in step with the decision for `cwd`. A decision is
 * written only where an extension would otherwise ask the person itself (the
 * project holds items PiShip decided on), and a stale approval is withdrawn
 * when the project is no longer trusted. Returns false when an approval could
 * not be recorded, so the caller reports the project as untrusted rather than
 * leave the extension to ask.
 */
function syncTrustStore(
  agentDir: string,
  cwd: string,
  trusted: boolean,
  applicable: boolean,
  personal: boolean,
): boolean {
  try {
    const store = new ProjectTrustStore(agentDir);
    const entry = store.getEntry(cwd);
    const exact = entry !== null && samePath(entry.path, cwd);
    if (trusted) {
      if (personal && exact && !entry.decision) return false;
      if (applicable && !(exact && entry.decision)) store.set(cwd, true);
    } else if (exact && entry.decision) store.set(cwd, false);
    return true;
  } catch {
    return !(trusted && applicable);
  }
}

/**
 * Whether Pi reports the session's project as trusted: the decision PiShip
 * made at launch for the project it governs. A session in any other
 * directory (a resumed session recorded elsewhere) was never decided, so its
 * project is untrusted. An ungoverned distribution (v1alpha1, v1alpha2) has no
 * project trust and keeps Pi's default.
 */
export function sessionProjectTrust(
  gov: Pick<
    GovernanceSession,
    "projectTrust" | "options" | "emit" | "notice" | "resources"
  > | null,
  cwd: string,
  agentDir: string,
): boolean {
  if (!gov) return true;
  const decision = gov.projectTrust;
  if (!samePath(cwd, gov.options.cwd)) {
    gov.emit("resource.denied", {
      resource: "project:.claude",
      detail: {
        kind: "claude",
        class: "project",
        seam: "project-trust",
        reason: "session-directory",
      },
    });
    gov.notice(
      "This session's directory is not the project this launch decided on, so its project configuration is not trusted.",
    );
    return false;
  }
  const applicable = decision.surfaces > 0;
  if (
    !syncTrustStore(
      agentDir,
      cwd,
      decision.trusted,
      applicable,
      gov.options.lock?.deployment.mode === "personal",
    )
  ) {
    gov.projectTrust = {
      ...decision,
      trusted: false,
      reason: "project trust state did not admit this session",
    };
    for (const [index, item] of (gov.resources ?? []).entries()) {
      if (
        item.class === "project" &&
        (item.kind === "claude" || item.kind === "extension-config")
      )
        gov.resources[index] = {
          ...item,
          loaded: false,
          reason: "project trust store denied or could not record approval",
        };
    }
    gov.emit("resource.denied", {
      resource: "project:.claude",
      detail: {
        kind: "claude",
        class: "project",
        seam: "project-trust",
        reason: "trust-store",
      },
    });
    gov.notice(
      "The project trust decision could not be recorded in the distribution's state, so project configuration is not trusted this session.",
    );
    return false;
  }
  return decision.trusted;
}
