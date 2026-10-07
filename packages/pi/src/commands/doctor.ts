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
    throw new PiShipError(
      "CONFIG_INVALID",
      `Usage: ${command} doctor [--json]`,
    );
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
  // of a session, so the report below names the one that runs next.
  try {
    refreshInstalledLauncher(ctx.metadata.app.id, ctx.distributionDir);
  } catch (error) {
    ctx.err(
      `Could not replace the installed launcher: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const report = renderDoctor(await collectDoctorData(ctx));
  ctx.out(
    args[0] === "--json" ? JSON.stringify(report, null, 2) : report.render(),
  );
  if (report.failed)
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `${ctx.metadata.app.name} doctor found problems`,
    );
}
