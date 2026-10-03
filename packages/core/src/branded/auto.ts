// `<command> auto on|off|status`: the user's auto mode switch, which the
// distribution must allow (`policy.userAuto: allowed`).
import { PiShipError, principalId } from "@piship/contracts";
import {
  describeUserAuto,
  setUserAuto,
  userAutoPrincipal,
  userAutoStatus,
} from "../user-auto.js";
import { type BrandedContext, governedLock, recordAudit } from "./context.js";
import { lifecycleNetwork } from "./lifecycle.js";

/** Why this distribution's user cannot switch auto mode on. */
export function userAutoDenied(
  command: string,
  mode: "personal" | "managed",
): PiShipError {
  return mode === "personal"
    ? new PiShipError(
        "POLICY_DENIED",
        "Auto mode is for managed distributions; in personal mode you own the policy",
        {
          component: "policy",
          userAction: `Add allow rules for what should run without a prompt to config/policy.json in the ${command} state directory`,
        },
      )
    : new PiShipError(
        "POLICY_DENIED",
        "This distribution does not allow auto mode (policy.userAuto is off)",
        {
          component: "policy",
          userAction:
            "Ask the distribution administrator to allow auto mode, or to allow the actions you need in the policy",
        },
      );
}

export async function runAuto(
  ctx: BrandedContext,
  args: readonly string[],
): Promise<void> {
  const command = ctx.metadata.app.command;
  const [action] = args;
  if (
    args.length !== 1 ||
    (action !== "on" && action !== "off" && action !== "status")
  )
    throw new PiShipError(
      "CONFIG_INVALID",
      `Usage: ${command} auto on | auto off | auto status`,
    );
  const lock = governedLock(ctx);
  const policy = lock?.governance.manifest.policy;
  const status = userAutoStatus(ctx.stateDir, policy, ctx.mode);
  if (action === "status") {
    ctx.out(`Auto mode: ${describeUserAuto(status)}`);
    return;
  }
  if (!lock || !policy || !status.allowed) {
    if (action === "on") throw userAutoDenied(command, ctx.mode);
    // Turning off is always possible; a switch left from an earlier
    // release that allowed it has no effect, so nothing is audited.
    setUserAuto(ctx.stateDir, false);
    ctx.out("Auto mode is off.");
    return;
  }
  const enabled = action === "on";
  const principal = userAutoPrincipal(ctx.stateDir);
  // Recorded before the switch changes: when a required audit sink does
  // not take the event, the switch stays as it was.
  await recordAudit(ctx, lifecycleNetwork(ctx), [
    {
      event: enabled ? "policy.auto_enabled" : "policy.auto_disabled",
      user: principal ? principalId(principal) : null,
      session: null,
      policy: `${policy.id}@${policy.version}`,
      detail: { source: "command" },
    },
  ]);
  setUserAuto(ctx.stateDir, enabled);
  ctx.out(
    enabled
      ? `Auto mode is on: asks from the distribution defaults are approved without a prompt and audited; deny and enforced rules still apply. It takes effect at the next ${command} start; turn it off with ${command} auto off.`
      : `Auto mode is off from the next ${command} start; in a session that is already running, use /auto off.`,
  );
}
