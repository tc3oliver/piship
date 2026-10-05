// Capability state: provider trust, provider payload verification, and the
// provider policy decisions of a governed session.
import { join, resolve } from "node:path";
import type { ApprovalChannel, PolicyAction } from "@piship/contracts";
import type { GovernanceLock } from "@piship/core";
import {
  type CapabilityState,
  type PolicyEngine,
  type ProviderTrustDecision,
  type VerificationResult,
  computeCapabilityStates,
  providerTrustDecision,
} from "@piship/policy";
import type { GovernanceSession } from "../governance-session.js";
import type { GovernanceOptions } from "./options.js";
import {
  fileMatches,
  loadPackageFiles,
  packageRoot,
  payloadTree,
} from "./resources.js";

/** Provider trust and payload verification, from the lock and the payload. */
interface ProviderEvidence {
  trust: Record<string, ProviderTrustDecision>;
  verification: Record<string, VerificationResult>;
}

/** The extension files of the package a provider is, from the lock. */
function providerPackageFiles(
  lock: GovernanceOptions["lock"],
  provider: GovernanceLock["providers"][number],
) {
  return (lock.packages ?? [])
    .filter((item) => item.id === provider.package)
    .flatMap((item) => item.resources)
    .filter((file) => file.kind === "extensions");
}

function providerEvidence(options: GovernanceOptions): ProviderEvidence {
  const { lock, distributionDir } = options;
  const resourceDir = join(distributionDir, "resources");
  const trust: Record<string, ProviderTrustDecision> = {};
  const verification: Record<string, VerificationResult> = {};
  for (const entry of lock.governance.providers) {
    trust[entry.id] = providerTrustDecision(
      lock.governance.manifest.policy,
      entry.class as Parameters<typeof providerTrustDecision>[1],
    );
    if (entry.path && entry.integrity) {
      const found = payloadTree(resourceDir, entry.path);
      verification[entry.id] =
        found === entry.integrity
          ? { ok: true }
          : { ok: false, reason: "provider files do not match the lock" };
    }
    if (entry.package) {
      const files = providerPackageFiles(lock, entry);
      const root = packageRoot(
        distributionDir,
        lock.governance.manifest,
        entry.package,
      );
      verification[entry.id] =
        files.length > 0 &&
        files.every((file) =>
          fileMatches(join(root, ...file.path.split("/")), file.sha256),
        )
          ? { ok: true }
          : {
              ok: false,
              reason: files.length
                ? "provider package files do not match the lock"
                : "the provider package has no extension to load",
            };
    }
  }
  return { trust, verification };
}

export function capabilityStates(
  options: GovernanceOptions,
  workflowLoaded: boolean,
  policyDenied: Readonly<Record<string, string>> = {},
  // Hashing provider payloads is costly; a caller that needs the evidence too
  // computes it once and passes it in.
  evidence: ProviderEvidence = providerEvidence(options),
): CapabilityState[] {
  const manifest = options.lock.governance.manifest;
  const { trust, verification } = evidence;
  return computeCapabilityStates({
    capabilities: manifest.capabilities,
    providerTrust: trust,
    verification,
    piVersion: options.piVersion,
    platform: process.platform,
    policyDenied,
    ...(options.model ? { model: options.model } : {}),
    health: {
      permissions: { ok: true },
      // A workflow provider the policy refused is reported as not enabled.
      ...(manifest.capabilities.some(
        (item) => item.name === "workflow" && item.enabled,
      ) && policyDenied.workflow === undefined
        ? {
            workflow: workflowLoaded
              ? { ok: true }
              : {
                  ok: false,
                  reason: "the workflow extension is not loaded",
                },
          }
        : {}),
    },
  });
}

/** Provider requests the policy decides before a provider's extension loads. */
function providerRequests(
  provider: GovernanceLock["providers"][number],
): [PolicyAction, string][] {
  const requests: [PolicyAction, string][] = [["provider.load", provider.id]];
  if (provider.path)
    requests.push(["extension.load", `${provider.class}:${provider.path}`]);
  return requests;
}

/** Capabilities whose non-builtin provider the policy always denies. */
export function staticProviderDenials(
  options: GovernanceOptions,
  engine: PolicyEngine,
): Record<string, string> {
  const denied: Record<string, string> = {};
  for (const provider of options.lock.governance.providers) {
    if (provider.class === "builtin") continue;
    // A package provider's extension files are decided one by one as they
    // load; a policy that always denies one of them denies the provider.
    const requests: [PolicyAction, string][] = [
      ...providerRequests(provider),
      ...providerPackageFiles(options.lock, provider).map(
        (file): [PolicyAction, string] => [
          "extension.load",
          `${provider.class}:packages/${provider.package}/${file.path}`,
        ],
      ),
    ];
    for (const [action, resource] of requests) {
      const decision = engine.evaluate({ action, resource });
      if (decision.effect !== "deny") continue;
      denied[provider.capability] = `policy ${decision.ruleId} (${action})`;
      break;
    }
  }
  return denied;
}

export async function computeCapabilities(
  session: GovernanceSession,
): Promise<void> {
  const workflowLoaded = () =>
    session.loader.builtin.has("piship-workflow") ||
    providerExtension(session, "workflow") !== undefined;
  const evidence = providerEvidence(session.options);
  const { verification } = evidence;
  const states = capabilityStates(
    session.options,
    workflowLoaded(),
    {},
    evidence,
  );
  const denied: Record<string, string> = {};
  const channel = session.startupChannel();
  for (const state of states) {
    const provider = session.options.lock.governance.providers.find(
      (entry) => entry.capability === state.name,
    );
    if (!provider || provider.class === "builtin") continue;
    if (state.axes.effective.value !== "yes") {
      // Files that do not match the lock are a load failure, not a decision.
      if (
        state.axes.enabled.value === "yes" &&
        verification[provider.id]?.ok === false
      )
        session.metrics.recordLoadFailure("provider", "INTEGRITY_FAILED");
      session.emit("provider.denied", {
        resource: provider.id,
        detail: { capability: state.name, version: provider.version },
      });
      continue;
    }
    // Provider trust made the capability effective; policy still decides
    // whether the provider and its extension load.
    const refusal = await providerPolicy(session, provider, channel);
    if (refusal) {
      denied[state.name] = refusal.reason;
      session.emit("provider.denied", {
        resource: provider.id,
        policy: refusal.policyId,
        rule: refusal.ruleId,
        detail: { capability: state.name, version: provider.version },
      });
      session.resources.push({
        kind: "providers",
        class: provider.class,
        path: provider.id,
        loaded: false,
        reason: refusal.reason,
      });
      continue;
    }
    session.emit("provider.load", {
      resource: provider.id,
      detail: { capability: state.name, version: provider.version },
    });
    const extension = providerExtension(session, state.name);
    if (extension) session.loader.extensions.push(extension);
    // A package provider's extensions load now, file by file, each after its
    // own `extension.load` decision.
    const locked = session.options.lock.packages?.find(
      (item) => item.id === provider.package,
    );
    if (locked)
      await loadPackageFiles(
        session,
        locked,
        (file) => file.kind === "extensions",
      );
  }
  session.capabilities = capabilityStates(
    session.options,
    workflowLoaded() && denied.workflow === undefined,
    denied,
    evidence,
  );
}

/** `provider.load` for the provider ID, then `extension.load` for its extension. */
async function providerPolicy(
  session: GovernanceSession,
  provider: GovernanceLock["providers"][number],
  channel: ApprovalChannel | undefined,
): Promise<{ reason: string; policyId: string; ruleId: string } | undefined> {
  for (const [action, resource] of providerRequests(provider)) {
    const decision = await session.decide(action, resource, channel);
    if (decision.outcome !== "allow")
      return {
        reason: `policy ${decision.ruleId} (${action})`,
        policyId: decision.policyId,
        ruleId: decision.ruleId,
      };
  }
  return undefined;
}

function providerExtension(
  session: GovernanceSession,
  capability: string,
): string | undefined {
  const entry = session.options.lock.governance.providers.find(
    (item) => item.capability === capability,
  );
  if (!entry?.path) return undefined;
  return resolve(
    session.options.distributionDir,
    "resources",
    ...entry.path.slice(2).split("/"),
  );
}
