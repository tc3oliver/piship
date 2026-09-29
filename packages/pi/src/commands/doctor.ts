import { PiShipError } from "@piship/contracts";
import { auditGroup } from "../doctor/audit.js";
import { capabilitiesGroup } from "../doctor/capabilities.js";
import { credentialGroup } from "../doctor/credential.js";
import { collectDoctorData, type DoctorData } from "../doctor/data.js";
import { distributionGroup } from "../doctor/distribution.js";
import { gatewayGroup } from "../doctor/gateway.js";
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

export async function runDoctor(ctx: LaunchContext): Promise<void> {
  const report = renderDoctor(await collectDoctorData(ctx));
  ctx.out(report.render());
  if (report.failed)
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `${ctx.metadata.app.name} doctor found problems`,
    );
}
