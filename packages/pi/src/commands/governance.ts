// `policy explain` and `capabilities`: offline governance reports.
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import {
  normalizePolicyAction,
  PiShipError,
  POLICY_ACTIONS,
  type PolicyAction,
  redact,
} from "@piship/contracts";
import { type GovernedLock, governedLock, usageRefusal } from "@piship/core";
import {
  decisionToJSON,
  formatCapabilities,
  formatDecision,
  projectDimensionEffect,
  projectEffectReason,
  projectPathDimension,
} from "@piship/policy";
import { nearestField } from "@piship/schema";
import { GovernanceSession, inspectGovernance } from "../governance-session.js";
import type { LaunchContext } from "../launch/context.js";
import { governanceOptions } from "../launch/governance.js";

function requireGovernedLock(
  ctx: LaunchContext,
  command: string,
): GovernedLock {
  const lock = governedLock(ctx);
  if (!lock)
    throw new PiShipError(
      "CONFIG_INVALID",
      `${ctx.metadata.app.command} ${command} needs a piship/v1alpha3 distribution`,
      {
        userAction:
          "This release has no governance to inspect; ask the distribution owner for one built from a piship/v1alpha3 or later manifest",
      },
    );
  return lock;
}

export async function runPolicy(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  const json = args.includes("--json");
  const words = args.filter((arg) => arg !== "--json");
  const usage = `Usage: ${ctx.metadata.app.command} policy explain <action> <resource> [--json]`;
  if (args.includes("--help") || args.includes("-h") || args[0] === "help") {
    ctx.out(
      `${usage}\n\nShow how policy decides <action> on <resource>, and which rules matched. Actions: ${POLICY_ACTIONS.join(", ")}`,
    );
    return;
  }
  if (words[0] !== "explain" || words.length < 3)
    throw new PiShipError("CONFIG_INVALID", usage, { usage: true });
  // An unquoted resource with spaces (`shell.execute npm install x`) is one.
  const [, named] = words as [string, string];
  const target = words.slice(2).join(" ");
  // A former action name (`model.use`) explains its current action.
  const requested = normalizePolicyAction(named);
  const near = nearestField(requested, POLICY_ACTIONS);
  if (!(POLICY_ACTIONS as readonly string[]).includes(requested))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Unknown policy action ${named}.${near ? ` Did you mean ${near}?` : ""} Actions: ${POLICY_ACTIONS.join(", ")}`,
      { usage: true },
    );
  const lock = requireGovernedLock(ctx, "policy explain");
  const inspection = await inspectGovernance(
    governanceOptions(ctx, lock, null, false),
  );
  // Paths are explained as tools see them: `~` is the home directory and
  // relative paths are resolved against the working directory.
  const resource = requested.startsWith("filesystem.")
    ? target === "~" || target.startsWith("~/")
      ? join(homedir(), target.slice(2))
      : resolve(target)
    : target;
  const explanation = inspection.engine.explain({
    action: requested as PolicyAction,
    resource,
  });
  // While the user's auto mode is on, an ask from the distribution defaults
  // runs without a prompt, for an action the session resolves through its
  // decisions; any other ask keeps its own handling.
  const format = {
    autoApproved:
      inspection.userAuto.active &&
      GovernanceSession.AUTO_RESOLVED_ACTIONS.has(requested as PolicyAction) &&
      !inspection.engine.keepsPrompt({
        action: requested as PolicyAction,
        resource,
      }),
  };
  // Project trust decides whether a project item is offered at all, before
  // these rules; show it so the answer matches doctor.
  const dimension = resource.startsWith("project:")
    ? projectPathDimension(resource.slice("project:".length))
    : undefined;
  const trust = dimension
    ? {
        dimension,
        origin: inspection.project.origin,
        effect: projectDimensionEffect(
          lock.governance.manifest.policy,
          inspection.project,
          dimension,
          lock.deployment.mode,
        ),
      }
    : undefined;
  ctx.out(
    json
      ? redact(
          JSON.stringify(
            {
              ...decisionToJSON(explanation, format),
              ...(trust ? { projectTrust: trust } : {}),
            },
            null,
            2,
          ),
        )
      : redact(
          formatDecision(explanation, format) +
            (trust
              ? `\n\nProject trust:\n  ${trust.effect}: ${projectEffectReason(trust.origin, trust.dimension, trust.effect)} (policy.projectTrust.${trust.origin}.${trust.dimension})`
              : ""),
        ),
  );
}

export async function runCapabilities(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  const usage = `Usage: ${ctx.metadata.app.command} capabilities [--json]`;
  if (
    args.length === 1 &&
    (args[0] === "--help" || args[0] === "-h" || args[0] === "help")
  ) {
    ctx.out(
      `${usage}\n\nShow each capability this distribution declares: whether it is supported, resolved, enabled, compatible with the selected model, healthy, and effective, with a reason for every no. --json prints the same as JSON.`,
    );
    return;
  }
  if (args.some((arg) => arg !== "--json"))
    throw usageRefusal("capabilities", usage, args, ["--json"]);
  const lock = requireGovernedLock(ctx, "capabilities");
  const inspection = await inspectGovernance(
    governanceOptions(ctx, lock, null, false),
  );
  ctx.out(
    args.includes("--json")
      ? JSON.stringify(inspection.capabilities, null, 2)
      : formatCapabilities(inspection.capabilities),
  );
}
