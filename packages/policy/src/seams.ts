// The runtime seam table: which policy actions Pi exposes a public seam for,
// and the reported enforcement status derived from it. Pi has no capability
// discovery API, so this is static data; packages/pi proves every `hook`
// entry against a real session in the compatibility tier.
import {
  type EnforcementPlane,
  type EnforcementStatus,
  POLICY_ACTIONS,
  type PolicyAction,
  type RuntimeSeamKind,
} from "@piship/contracts";
import type { PolicyContainment } from "./engine.js";
import { matchGlob } from "./glob.js";
import {
  OFFLINE_SEAMS,
  RESOURCE_SEAMS,
  RUNTIME_SEAMS,
} from "./seam-evidence.js";

export * from "./seam-evidence.js";

function needsOffline(action: PolicyAction, resource: string): boolean {
  return (
    action === "session.export" &&
    (OFFLINE_SEAMS[action] as readonly string[]).includes(resource)
  );
}

function resourceSeams(
  action: PolicyAction,
): Readonly<Record<string, RuntimeSeamKind>> | undefined {
  return action === "session.export" ? RESOURCE_SEAMS[action] : undefined;
}

/** The containment plane that can enforce an action without a hook. */
const SANDBOX_PLANES: Readonly<
  Partial<Record<PolicyAction, keyof PolicyContainment>>
> = {
  "filesystem.read": "filesystem",
  "filesystem.write": "filesystem",
  "shell.execute": "shell",
  "network.connect": "network",
};

const STATUS_RANK: Readonly<Record<EnforcementStatus, number>> = {
  unsupported: 0,
  "audit-only": 1,
  enforced: 2,
};

/**
 * The seam for `action`, narrowed by `resource` when the table has one. This
 * is the static table; `seamPlane` also applies containment and `piOffline`.
 */
export function runtimeSeam(
  action: PolicyAction,
  resource?: string,
): RuntimeSeamKind {
  const perResource = resourceSeams(action);
  if (resource !== undefined && perResource?.[resource])
    return perResource[resource];
  return RUNTIME_SEAMS[action];
}

/**
 * The plane that enforces `action` under `containment`, or undefined when
 * nothing does (the action is unsupported). An active sandbox plane wins over
 * the in-process hook.
 */
export function seamPlane(
  action: PolicyAction,
  containment: PolicyContainment,
  resource?: string,
): EnforcementPlane | undefined {
  const plane = SANDBOX_PLANES[action];
  if (plane && containment[plane]) return "sandbox";
  if (
    resource !== undefined &&
    needsOffline(action, resource) &&
    !containment.piOffline
  )
    return undefined;
  switch (runtimeSeam(action, resource)) {
    case "hook":
      return "control-plane";
    case "observe":
      return "audit-only";
    default:
      return undefined;
  }
}

/** The reported status of a plane; no plane is `unsupported`. */
export function planeStatus(
  plane: EnforcementPlane | undefined,
): EnforcementStatus {
  if (plane === undefined) return "unsupported";
  return plane === "audit-only" ? "audit-only" : "enforced";
}

/** The reported status of `action` (on `resource`) under `containment`. */
export function enforcementStatus(
  action: PolicyAction,
  containment: PolicyContainment,
  resource?: string,
): EnforcementStatus {
  return planeStatus(seamPlane(action, containment, resource));
}

/**
 * The weakest status a rule's resource glob reaches. For an action with
 * per-resource seams, every known resource the glob covers counts, so `**`
 * over `session.export` is as weak as `public`.
 */
export function ruleStatus(
  action: PolicyAction,
  resource: string,
  containment: PolicyContainment,
): EnforcementStatus {
  const known = Object.keys(resourceSeams(action) ?? {}).filter((name) =>
    matchGlob(resource, name),
  );
  if (!known.length) return enforcementStatus(action, containment, resource);
  return known
    .map((name) => enforcementStatus(action, containment, name))
    .reduce((weakest, status) =>
      STATUS_RANK[status] < STATUS_RANK[weakest] ? status : weakest,
    );
}

/**
 * The status of a decision already carrying a plane. Planes predate the
 * `unsupported` status, so an `audit-only` decision on an action with no seam
 * is reported as `unsupported`.
 */
export function decisionStatus(decision: {
  readonly action: string;
  readonly resource: string;
  readonly enforcement: EnforcementPlane;
}): EnforcementStatus {
  // An offline-gated resource is audit-only only when Pi was online.
  if (
    decision.enforcement === "audit-only" &&
    isPolicyAction(decision.action) &&
    (runtimeSeam(decision.action, decision.resource) === "none" ||
      needsOffline(decision.action, decision.resource))
  )
    return "unsupported";
  return planeStatus(decision.enforcement);
}

export function isPolicyAction(action: string): action is PolicyAction {
  return (POLICY_ACTIONS as readonly string[]).includes(action);
}

