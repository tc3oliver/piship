// What an extension that follows Pi's project-trust decision (pi-code, for one)
// loads from a project by itself, and whether policy admits it. Pi gives an
// extension one boolean per session, so the project's Claude Code
// configuration is admitted as a unit: every item found must be admitted.
import {
  CLAUDE_TRUST_DIMENSIONS,
  type DeploymentMode,
  type PolicyConfig,
} from "@piship/schema";
import type { ProjectIdentity, ProjectResourceCandidate } from "./project.js";
import { projectDimensionEffect } from "./project.js";

/**
 * Whether an extension loads this candidate on its own once Pi reports the
 * project as trusted: the Claude Code configuration (`.claude/*`), the
 * project MCP files (`.mcp.json`, `.pi/mcp.json`), and `.pi/agents`, at
 * every level between the working directory and the root.
 */
export function readByExtensions(
  candidate: Pick<ProjectResourceCandidate, "kind">,
): boolean {
  return (
    candidate.kind === "claude" ||
    candidate.kind === "mcp" ||
    candidate.kind === "extension-config" ||
    candidate.kind === "agents"
  );
}

export interface ExtensionTrustAssessment {
  /** What policy says before any approval: `ask` means a person decides. */
  readonly effect: "allow" | "ask" | "deny";
  /** Why, in fixed text; never content. `decidedBy` is the item it is about. */
  readonly reason: string;
  /** The discovered items the decision covers; empty when none was found. */
  readonly surfaces: readonly ProjectResourceCandidate[];
  /** The item that decided a denial or an `ask`, when one did. */
  readonly decidedBy?: ProjectResourceCandidate;
}

/**
 * The static decision for the project, from what discovery found:
 * - an item whose dimension is `deny` or `company-approved` (which admits no
 *   project content) denies the whole;
 * - when nothing was found, a managed distribution still denies unless policy
 *   admits every Claude dimension for the origin, since an extension can look
 *   where PiShip did not (the main checkout of a worktree, a nested
 *   directory) and PiShip cannot prove nothing is there;
 * - an `ask` item asks once for the whole;
 * - otherwise it is allowed.
 * Per-item policy rules and the person's answer are applied at launch.
 */
export function assessExtensionProjectTrust(
  candidates: readonly ProjectResourceCandidate[],
  context: {
    readonly policy: Pick<PolicyConfig, "resourceTrust" | "projectTrust">;
    readonly identity: Pick<ProjectIdentity, "origin">;
    readonly mode: DeploymentMode;
  },
): ExtensionTrustAssessment {
  const surfaces = candidates.filter(readByExtensions);
  const blocked = surfaces.find(
    (candidate) =>
      candidate.effect === "deny" || candidate.effect === "company-approved",
  );
  if (blocked)
    return {
      effect: "deny",
      reason: blocked.reason,
      surfaces,
      decidedBy: blocked,
    };
  if (surfaces.length === 0) {
    const unmet =
      context.mode === "managed"
        ? CLAUDE_TRUST_DIMENSIONS.find(
            (dimension) =>
              projectDimensionEffect(
                context.policy,
                context.identity,
                dimension,
                context.mode,
              ) !== "allow",
          )
        : undefined;
    return unmet
      ? {
          effect: "deny",
          reason: `no Claude Code configuration was found, but the policy does not admit ${unmet} for ${context.identity.origin} projects`,
          surfaces,
        }
      : {
          effect: "allow",
          reason: "no Claude Code configuration was found",
          surfaces,
        };
  }
  const asked = surfaces.find((candidate) => candidate.effect === "ask");
  return asked
    ? {
        effect: "ask",
        reason: asked.reason,
        surfaces,
        decidedBy: asked,
      }
    : {
        effect: "allow",
        reason: "policy admits every item found",
        surfaces,
      };
}
