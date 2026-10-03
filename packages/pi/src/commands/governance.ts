// `policy explain` and `capabilities`: offline governance reports.
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import {
  PiShipError,
  type PolicyAction,
  POLICY_ACTIONS,
  redact,
} from "@piship/contracts";
import { type GovernedLock, governedLock } from "@piship/core";
import {
  decisionToJSON,
  formatCapabilities,
  formatDecision,
} from "@piship/policy";
import { inspectGovernance } from "../governance-session.js";
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
    );
  return lock;
}

export async function runPolicy(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  const json = args.includes("--json");
  const words = args.filter((arg) => arg !== "--json");
  if (words[0] !== "explain" || words.length !== 3)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Usage: ${ctx.metadata.app.command} policy explain <action> <resource> [--json]`,
    );
  const [, requested, target] = words as [string, string, string];
  if (!(POLICY_ACTIONS as readonly string[]).includes(requested))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Unknown policy action ${requested}. Actions: ${POLICY_ACTIONS.join(", ")}`,
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
  // runs without a prompt.
  const format = {
    autoApproved:
      inspection.userAuto.active &&
      !inspection.engine.keepsPrompt({
        action: requested as PolicyAction,
        resource,
      }),
  };
  ctx.out(
    json
      ? redact(JSON.stringify(decisionToJSON(explanation, format), null, 2))
      : redact(formatDecision(explanation, format)),
  );
}

export async function runCapabilities(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  if (args.some((arg) => arg !== "--json"))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Usage: ${ctx.metadata.app.command} capabilities [--json]`,
    );
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
