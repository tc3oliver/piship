// PiShip's project-trust decision, handed to Pi's public trust seam. Extensions
// ask Pi whether the project is trusted (`ctx.isProjectTrusted()`, the
// in-memory settings' flag) and, for configuration Pi itself never gates, keep
// their own decision in Pi's trust store under the agent directory (pi-code
// does both). PiShip sets the flag and writes that store from its policy, so
// the answer an extension reads is PiShip's, never the person's click or a
// file the project ships.
import { realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { ProjectTrustStore } from "@earendil-works/pi-coding-agent";
import { piTrustWritten, recordPiTrustWrite } from "@piship/core";
import type { GovernanceSession } from "../governance-session.js";

/** Whether two paths name the same directory (a missing one by its resolved path). */
export function samePath(left: string, right: string): boolean {
  const real = (path: string): string => {
    try {
      return realpathSync(path);
    } catch {
      return resolve(path);
    }
  };
  return real(left) === real(right);
}

/** The decision this distribution wrote to Pi's store for `cwd`, if known. */
function written(stateDir: string, cwd: string): boolean | undefined {
  try {
    return piTrustWritten(stateDir, cwd);
  } catch {
    return undefined;
  }
}

function record(stateDir: string, cwd: string, decision: boolean): void {
  try {
    recordPiTrustWrite(stateDir, cwd, decision);
  } catch {
    // Unrecorded: a refusal written now reads as the person's next time.
  }
}

/**
 * Keep Pi's trust store in step with the decision for `cwd`. A decision is
 * written only where an extension would otherwise ask the person itself (the
 * project holds items PiShip decided on), and a stale approval is withdrawn
 * when the project is no longer trusted. Each write is recorded in the
 * distribution state, so a refusal this distribution wrote is replaced when
 * the project is trusted again, while one the person saved in Pi's store
 * keeps a personal distribution from trusting the project ("refused").
 * "unrecorded" when an approval could not be written, so the caller reports
 * the project as untrusted rather than leave the extension to ask.
 */
function syncTrustStore(
  agentDir: string,
  stateDir: string,
  cwd: string,
  trusted: boolean,
  applicable: boolean,
  personal: boolean,
): "ok" | "refused" | "unrecorded" {
  try {
    const store = new ProjectTrustStore(agentDir);
    const entry = store.getEntry(cwd);
    const exact = entry !== null && samePath(entry.path, cwd);
    if (trusted) {
      const ours = exact && written(stateDir, cwd) === false;
      if (personal && exact && !entry.decision && !ours) return "refused";
      if ((applicable || ours) && !(exact && entry.decision)) {
        store.set(cwd, true);
        record(stateDir, cwd, true);
      }
    } else if (exact && entry.decision) {
      store.set(cwd, false);
      record(stateDir, cwd, false);
    }
    return "ok";
  } catch {
    return trusted && applicable ? "unrecorded" : "ok";
  }
}

/**
 * Withdraw from Pi's trust store the decisions this distribution wrote there
 * (`config trust forget`), each only while it is still the one written.
 */
export function forgetPiTrust(
  agentDir: string,
  written: Readonly<Record<string, boolean>>,
): void {
  const store = new ProjectTrustStore(agentDir);
  for (const [dir, decision] of Object.entries(written)) {
    const entry = store.getEntry(dir);
    if (entry && samePath(entry.path, dir) && entry.decision === decision)
      store.set(dir, null);
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
  const synced = syncTrustStore(
    agentDir,
    gov.options.stateDir,
    cwd,
    decision.trusted,
    applicable,
    gov.options.lock?.deployment.mode === "personal",
  );
  if (synced !== "ok") {
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
          reason:
            synced === "refused"
              ? "Pi's trust store holds a refusal for the project"
              : "project trust approval could not be written to Pi's trust store",
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
    const trustFile = join(agentDir, "trust.json");
    gov.notice(
      synced === "refused"
        ? `Project configuration is not trusted this session: Pi's trust store (${trustFile}) says not to trust ${cwd}, and that refusal is kept. To trust the project, remove its entry from that file.`
        : `Project configuration is not trusted this session: the trust decision could not be written to Pi's trust store (${trustFile}).`,
    );
    return false;
  }
  return decision.trusted;
}
