import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { redact } from "@piship/contracts";
import {
  type CapabilityState,
  type PolicyEngine,
  type ProjectIdentity,
  type ProjectResourceCandidate,
  resourceTrustDecision,
} from "@piship/policy";
import {
  type ContainmentReport,
  activateSandbox,
  adapterIdFor,
  describeContainment,
} from "@piship/sandbox";
import { capabilityStates, staticProviderDenials } from "./capabilities.js";
import {
  buildEngine,
  discoverProject,
  gitProtection,
  sandboxConfig,
} from "./engine.js";
import {
  type GovernanceOptions,
  KIND_ACTION,
  type ResourceEvidence,
} from "./options.js";
import { payloadTree } from "./resources.js";

export interface GovernanceInspection {
  readonly project: ProjectIdentity;
  readonly candidates: readonly ProjectResourceCandidate[];
  readonly sandbox: ContainmentReport;
  readonly containment: string;
  readonly engine: PolicyEngine;
  readonly capabilities: readonly CapabilityState[];
  /** Declared resources as trust and integrity see them, before approvals. */
  readonly resources: readonly ResourceEvidence[];
}

/**
 * Static governance state for doctor, `policy explain`, and `capabilities`:
 * no audit, no MCP start, no approvals. The sandbox probe runs so the
 * reported containment is the real one; a required sandbox that is
 * unavailable is reported, not thrown.
 */
export async function inspectGovernance(
  options: GovernanceOptions,
): Promise<GovernanceInspection> {
  const homeDir = options.homeDir ?? homedir();
  const manifest = options.lock.governance.manifest;
  const { project, candidates } = discoverProject(options, homeDir);
  let report: ContainmentReport;
  let tmpDir = tmpdir();
  try {
    const sandbox = await activateSandbox(sandboxConfig(options), {
      workspace: project.root,
      homeDir,
      // MCP modules run from the installed payload, which may sit under a
      // directory the sandbox otherwise replaces (such as /tmp).
      extraReadOnly: [options.distributionDir],
      protectedPaths: gitProtection(project.root),
    });
    report = sandbox.report;
    tmpDir = sandbox.profile.tmpDir;
    sandbox.dispose();
  } catch (error) {
    report = {
      level: "unavailable",
      adapter: adapterIdFor(process.platform),
      required: manifest.sandbox.required,
      planes: [],
      network: manifest.sandbox.network.mode,
      reason: redact(String((error as Error)?.message ?? error)),
      warnings: [],
    };
  }
  const engine = await buildEngine(
    options,
    project,
    candidates,
    report,
    tmpDir,
    homeDir,
  );
  const resourceDir = join(options.distributionDir, "resources");
  const certified = new Map(
    options.lock.governance.certified.map((entry) => [
      `${entry.kind}:${entry.path}`,
      entry,
    ]),
  );
  const resources: ResourceEvidence[] = [];
  for (const item of manifest.resources.declared) {
    const trust = resourceTrustDecision(manifest.policy, item.class, item.kind);
    const base = { kind: item.kind, class: item.class, path: item.path };
    if (!trust.allowed) {
      resources.push({ ...base, loaded: false, reason: trust.reason });
      continue;
    }
    let integrity: ResourceEvidence["integrity"] = "not-applicable";
    let compatible = true;
    let reason = trust.reason;
    const entry = certified.get(`${item.kind}:${item.path}`);
    if (item.class === "certified") {
      const ok =
        !!entry && payloadTree(resourceDir, item.path) === entry.integrity;
      if (!ok) {
        resources.push({
          ...base,
          loaded: false,
          reason: "certified content does not match its reviewed integrity",
        });
        continue;
      }
      integrity = "verified";
      compatible =
        entry.evidence.pi.includes(options.piVersion) &&
        (entry.evidence.platforms.length === 0 ||
          entry.evidence.platforms.includes(process.platform));
      if (!compatible) reason = "not certified for this Pi version or platform";
    }
    const decision = engine.evaluate({
      action: KIND_ACTION[item.kind] ?? "resource.load",
      resource: `${item.class}:${item.path}`,
    });
    const loaded = compatible && decision.effect !== "deny";
    resources.push({
      ...base,
      loaded,
      reason:
        decision.effect === "allow"
          ? reason
          : `policy ${decision.ruleId} (${decision.effect})`,
      integrity,
      compatible,
    });
  }
  for (const name of manifest.resources.builtin) {
    const decision = engine.evaluate({
      action: "extension.load",
      resource: `builtin:${name}`,
    });
    resources.push({
      kind: "extensions",
      class: "builtin",
      path: name,
      loaded: decision.effect !== "deny",
      reason:
        decision.effect === "allow"
          ? "builtin"
          : `policy ${decision.ruleId} (${decision.effect})`,
      integrity: "not-applicable",
    });
  }
  const workflowLoaded =
    resources.some((item) => item.path === "piship-workflow" && item.loaded) ||
    options.lock.governance.providers.some(
      (item) => item.capability === "workflow" && item.class !== "builtin",
    );
  return {
    project,
    candidates,
    sandbox: report,
    containment: describeContainment(report),
    engine,
    capabilities: capabilityStates(
      options,
      workflowLoaded,
      staticProviderDenials(options, engine),
    ),
    resources,
  };
}
