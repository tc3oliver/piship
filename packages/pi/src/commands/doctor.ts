import { PiShipError } from "@piship/contracts";
import {
  verifyPayload,
  describeReclaimed,
  describeStoreMaintenance,
  maintainRuntimeStore,
  reclaimLaunchTemporaries,
  reclaimObsoleteVersions,
  refreshInstalledLauncher,
  sweepStateTemporaries,
  usageRefusal,
} from "@piship/core";
import { auditGroup } from "../doctor/audit.js";
import { capabilitiesGroup } from "../doctor/capabilities.js";
import { credentialGroup } from "../doctor/credential.js";
import { collectDoctorData, type DoctorData } from "../doctor/data.js";
import { distributionGroup } from "../doctor/distribution.js";
import { gatewayGroup } from "../doctor/gateway.js";
import { governanceGroup } from "../doctor/governance.js";
import { identityGroup } from "../doctor/identity.js";
import { inferenceGroup } from "../doctor/inference.js";
import { mcpGroup } from "../doctor/mcp.js";
import { networkGroup } from "../doctor/network.js";
import { policyGroup } from "../doctor/policy.js";
import { projectGroup } from "../doctor/project.js";
import { releaseGroup } from "../doctor/release.js";
import { DoctorReport } from "../doctor/report.js";
import { resourcesGroup } from "../doctor/resources.js";
import { sandboxGroup } from "../doctor/sandbox.js";
import { secretStoreGroup } from "../doctor/secret-store.js";
import { supplyChainGroup } from "../doctor/supply-chain.js";
import { updateGroup } from "../doctor/update.js";
import { verificationGroup } from "../doctor/verification.js";
import { workspaceGroup } from "../doctor/workspace.js";
import type { LaunchContext } from "../launch/context.js";

/** Format collected doctor data; each group is written by exactly one call. */
export function renderDoctor(data: DoctorData): DoctorReport {
  const report = new DoctorReport(`${data.ctx.metadata.app.name} Doctor`);
  distributionGroup(data, report.section("Distribution"));
  supplyChainGroup(data, report.section("Supply Chain"));
  identityGroup(data, report.section("Identity"));
  credentialGroup(data, report.section("Credential"));
  inferenceGroup(data, report.section("Inference"));
  gatewayGroup(data, report.section("Gateway"));
  resourcesGroup(data, report.section("Resources"));
  policyGroup(data, report.section("Policy"));
  governanceGroup(data, report.section("Governance"));
  projectGroup(data, report.section("Project"));
  capabilitiesGroup(data, report.section("Capabilities"));
  sandboxGroup(data, report.section("Sandbox"));
  workspaceGroup(data, report.section("Workspace"));
  mcpGroup(data, report.section("MCP"));
  secretStoreGroup(data, report.section("Secret Store"));
  auditGroup(data, report.section("Audit"));
  networkGroup(data, report.section("Network"));
  releaseGroup(data, report.section("Release"));
  verificationGroup(data, report);
  updateGroup(data, report.section("Update"));
  return report;
}

export async function runDoctor(
  ctx: LaunchContext,
  args: readonly string[] = [],
): Promise<void> {
  const command = ctx.metadata.app.command;
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    ctx.out(
      `Usage: ${command} doctor [--json]\n\nCheck this distribution's configuration, sign-in, network, governance, and release, and exit non-zero on any failure. --json prints the same checks as JSON.`,
    );
    return;
  }
  if (args.length && !(args.length === 1 && args[0] === "--json"))
    throw usageRefusal("doctor", `Usage: ${command} doctor [--json]`, args, [
      "--json",
    ]);
  // Full payload verification is a requested diagnostic, never a prerequisite
  // for entering Pi. It runs first and ends the command when it fails: the
  // rest of the report loads payload code (the policy adapter, the MCP
  // servers), which a payload that does not match its lock must never run,
  // and an installation found damaged is not changed first.
  verifyPayload(ctx.distributionDir);
  sweepStateTemporaries(ctx.stateDir);
  const notice = reclaimLaunchTemporaries(ctx.metadata.app.id);
  if (notice) ctx.err(notice);
  try {
    // Release directories nothing records any more, removed within a
    // longer budget than the end of an update or rollback has.
    const reclaimed = describeReclaimed(
      reclaimObsoleteVersions(ctx.metadata.app.id),
    );
    if (reclaimed) ctx.err(reclaimed);
  } catch (error) {
    ctx.err(
      `Could not remove obsolete releases: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  // The shared file store is a cache of file bytes, never what an installed
  // release runs from. This is the only place it is collected or verified.
  try {
    const stored = describeStoreMaintenance(maintainRuntimeStore());
    if (stored) ctx.err(stored);
  } catch (error) {
    ctx.err(
      `Could not maintain the file store: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  // An installed launcher an earlier PiShip wrote is replaced, as at the end
  // of a session, so the report below names the one that runs next. It never
  // throws; a launcher it could not replace is reported under Update.
  refreshInstalledLauncher(ctx.metadata.app.id, ctx.distributionDir);
  const data = await collectDoctorData(ctx);
  const report = renderDoctor(data);
  if (args[0] === "--json") ctx.out(JSON.stringify(report, null, 2));
  else {
    const warnings = report.warnings();
    ctx.out(warnings ? `${report.render()}\n\n${warnings}` : report.render());
  }
  if (report.failed) {
    const message = `${ctx.metadata.app.name} doctor found problems: ${report.summary()}`;
    const signIn = signInFailure(data, report);
    throw signIn
      ? new PiShipError(signIn, message, {
          component: "identity",
          userAction: `Run ${command} login`,
        })
      : new PiShipError("CONFIG_UNAVAILABLE", message);
  }
}

// The checks a missing or expired sign-in fails on its own.
const SIGN_IN_CHECKS = new Set([
  "Identity/session",
  "Credential/state",
  "Inference/activation",
]);

/**
 * IDENTITY_REQUIRED or IDENTITY_EXPIRED when signing in again is all the
 * failed checks need; undefined when anything else failed too.
 */
export function signInFailure(
  data: DoctorData,
  report: DoctorReport,
): "IDENTITY_REQUIRED" | "IDENTITY_EXPIRED" | undefined {
  const access = data.access;
  // A workload identity is obtained per run; `login` does not fix it.
  if (!access || access.workload || access.tlsError) return undefined;
  const code = access.identityErrorCode;
  if (
    code !== undefined &&
    code !== "IDENTITY_REQUIRED" &&
    code !== "IDENTITY_EXPIRED"
  )
    return undefined;
  // Signed in, with activation failing for a reason other than the identity.
  if (code === undefined && (access.signedIn || access.activationError))
    return undefined;
  const failed = report
    .toJSON()
    .groups.flatMap(({ group, checks }) =>
      checks
        .filter((check) => check.status === "fail")
        .map((check) => `${group}/${check.label}`),
    );
  return failed.every((check) => SIGN_IN_CHECKS.has(check))
    ? (code ?? "IDENTITY_REQUIRED")
    : undefined;
}
