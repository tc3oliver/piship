// `<command> auto on|off|status`: the user's auto mode switch, which the
// distribution must allow (`policy.userAuto: allowed`).
import { formatError, PiShipError, principalId } from "@piship/contracts";
import type { DistributionLock } from "../index.js";
import {
  describeUserAuto,
  setUserAuto,
  userAutoAllowed,
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

/**
 * Why `--yolo` cannot start this distribution's session, or undefined when
 * it can. It relaxes a policy, so a distribution that declares none has
 * nothing for it to do; and where the administrator owns the policy
 * (managed), it works only if the distribution allows auto-approval
 * (`policy.userAuto: allowed`), as `auto on` does.
 */
export function yoloRefusal(
  metadata: DistributionLock,
): PiShipError | undefined {
  const command = metadata.app.command;
  const policy = metadata.governance?.manifest.policy;
  if (!policy)
    return new PiShipError(
      "CONFIG_INVALID",
      `--yolo has no meaning for ${command}: it declares no policy (piship/v1alpha3 or later), so nothing asks for approval`,
      { userAction: `Start ${command} without --yolo` },
    );
  if (
    metadata.deployment.mode === "personal" ||
    userAutoAllowed(policy, metadata.deployment.mode)
  )
    return undefined;
  return new PiShipError(
    "POLICY_DENIED",
    "--yolo is not allowed: this distribution does not allow auto-approval (policy.userAuto is off)",
    {
      component: "policy",
      userAction: `Start ${command} without --yolo and answer the prompts, or ask the distribution administrator to allow auto-approval (policy.userAuto: allowed) or to allow the actions you need in the policy`,
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
  const record = (prefix?: string) =>
    recordAudit(
      ctx,
      lifecycleNetwork(ctx),
      [
        {
          event: enabled ? "policy.auto_enabled" : "policy.auto_disabled",
          user: principal ? principalId(principal) : null,
          session: null,
          policy: `${policy.id}@${policy.version}`,
          detail: { source: "command" },
        },
      ],
      prefix,
    );
  if (enabled) {
    // Recorded before the switch changes: when a required audit sink does
    // not take the event, auto mode stays off.
    await record(
      "Auto mode was not switched on, because its audit was not recorded",
    );
    setUserAuto(ctx.stateDir, true);
  } else {
    // Turning off only restores prompts, so an audit sink that is down
    // never blocks it: the switch changes first, the event is best effort.
    setUserAuto(ctx.stateDir, false);
    await record().catch((error: unknown) =>
      ctx.err(`Warning: ${formatError(error)}`),
    );
  }
  ctx.out(
    enabled
      ? `Auto mode is on: asks from the distribution defaults are approved without a prompt and audited; deny and enforced rules still apply. It takes effect at the next ${command} start; turn it off with ${command} auto off.`
      : `Auto mode is off from the next ${command} start; in a session that is already running, use /auto off.`,
  );
}
