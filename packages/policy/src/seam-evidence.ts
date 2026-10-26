// The runtime seam table and the lock evidence derived from it. This module
// has no runtime package imports, so a unit test can hash the current table
// without a build.
import { createHash } from "node:crypto";
import type {
  PolicyAction,
  RuntimeSeamKind,
  SessionExportResource,
} from "@piship/contracts";

/** The seam table against Pi 1.1.0. */
export const RUNTIME_SEAMS: Readonly<Record<PolicyAction, RuntimeSeamKind>> = {
  "model.select": "hook",
  "model.dispatch": "hook",
  "resource.load": "hook",
  "extension.load": "hook",
  "skill.load": "hook",
  "instruction.load": "hook",
  "provider.load": "hook",
  "agent.invoke": "none",
  "mcp.server.start": "hook",
  "mcp.tool.call": "hook",
  "tool.execute": "hook",
  "shell.execute": "hook",
  // Read from the shell command text only, never contained: a push from a
  // script, alias, or wrapper is not seen (gitPushResources).
  "git.push": "hook",
  "filesystem.read": "hook",
  "filesystem.write": "hook",
  // Only an OS sandbox contains connections; PiShip has no in-process seam.
  "network.connect": "none",
  "memory.read": "none",
  "memory.write": "none",
  "web.request": "none",
  "browser.execute": "none",
  // Raised per resource below; a resource outside that table has no seam.
  "session.export": "none",
};

/**
 * Per-resource seams for actions whose resources differ. `/share` falls back
 * to the host `gh` CLI (a gist) outside PiShip, and `/export` writes session
 * files the user can read anyway, so only `support` is enforced, and only
 * where Pi runs offline (`OFFLINE_SEAMS`).
 */
export const RESOURCE_SEAMS: Readonly<{
  "session.export": Readonly<Record<SessionExportResource, RuntimeSeamKind>>;
}> = {
  "session.export": { public: "none", local: "none", support: "hook" },
};

/**
 * Resources whose seam holds only while Pi runs offline. PiShip's own support
 * commands are gated in-process, but Pi's `/bug` upload is closed only by
 * `PI_OFFLINE=1`, which a managed launch sets and a personal one does not.
 */
export const OFFLINE_SEAMS: Readonly<{
  "session.export": readonly SessionExportResource[];
}> = { "session.export": ["support"] };

/**
 * Seam evidence for the lock (`LockedEnforcement`): the Pi version, the
 * per-action table, and a digest that also covers the per-resource seams.
 */
export interface SeamEvidence {
  readonly pi: string;
  readonly seams: Readonly<Record<PolicyAction, RuntimeSeamKind>>;
  readonly digest: string;
}

function sorted<T>(record: Readonly<Record<string, T>>): Record<string, T> {
  return Object.fromEntries(
    Object.entries(record).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
}

export function seamEvidence(pi: string): SeamEvidence {
  const seams = sorted(RUNTIME_SEAMS) as Record<PolicyAction, RuntimeSeamKind>;
  const resources = Object.fromEntries(
    Object.entries(sorted(RESOURCE_SEAMS)).map(([action, table]) => [
      action,
      sorted(table),
    ]),
  );
  const offline = sorted(OFFLINE_SEAMS);
  const digest = `sha256-${createHash("sha256")
    .update(JSON.stringify({ pi, seams, resources, offline }))
    .digest("hex")}`;
  return { pi, seams, digest };
}
