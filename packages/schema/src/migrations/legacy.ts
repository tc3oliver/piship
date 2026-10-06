// Migration steps up to piship/v1alpha5. Each is behavior-preserving: it
// writes the values that keep the earlier schema's behavior.
import { isCollection } from "yaml";
import type { DeploymentMode } from "../access.js";
import {
  DEFAULT_PACKAGE_SOURCES,
  DEFAULT_RELEASE_TARGETS,
} from "../lifecycle.js";
import {
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
} from "../versions.js";
import type { YamlDocument } from "./types.js";

const RESOURCE_KIND_KEYS = [
  "instructions",
  "skills",
  "extensions",
  "prompts",
  "themes",
] as const;

/**
 * v1alpha1 -> v1alpha2: an equivalent personal profile with no identity,
 * explicit Pi-native credential delegation, and Pi-native inference.
 */
export function migrateToV1alpha2(document: YamlDocument): string[] {
  document.set("schema", PISHIP_SCHEMA_V1ALPHA2);
  document.set("identity", document.createNode({ mode: "none" }));
  document.set("credential", document.createNode({ provider: "pi-native" }));
  document.set("inference", document.createNode({ provider: "pi-native" }));
  return [
    "schema: piship/v1alpha1 -> piship/v1alpha2",
    "identity.mode: none (unchanged behavior: no enterprise identity)",
    "credential.provider: pi-native (explicit delegation to Pi auth in isolated state)",
    "inference.provider: pi-native (Pi model catalog, as in v0.1)",
  ];
}

/**
 * v1alpha2 -> v1alpha3: flat resource lists gain a trust class, and the new
 * governance sections are written with values that keep v1alpha2 behavior
 * (no tool policy, no sandbox, no audit, no MCP).
 */
export function migrateToV1alpha3(
  document: YamlDocument,
  mode: DeploymentMode,
): string[] {
  const trust = mode === "managed" ? "company" : "user";
  const changes = ["schema: piship/v1alpha2 -> piship/v1alpha3"];
  document.set("schema", PISHIP_SCHEMA_V1ALPHA3);
  for (const kind of RESOURCE_KIND_KEYS) {
    const node = document.getIn(["resources", kind], true);
    if (node === undefined || node === null) continue;
    document.setIn(["resources", kind], document.createNode({ [trust]: node }));
    changes.push(
      `resources.${kind}: flat list -> ${trust} trust class (${mode} distribution resources)`,
    );
  }
  // v1alpha2 never loaded project resources, not even themes (its resource
  // loader ran with noThemes against the distribution directory); only tool
  // access to project files.
  const closed = {
    passiveContext: "deny",
    instructions: "deny",
    skills: "deny",
    agents: "deny",
    hooks: "deny",
    extensions: "deny",
    mcp: "deny",
    providers: "deny",
    claudeRules: "deny",
    claudeCommands: "deny",
    claudeSkills: "deny",
    claudeAgents: "deny",
    claudeHooks: "deny",
  };
  document.set(
    "policy",
    document.createNode({
      default: "allow",
      projectTrust: {
        company: closed,
        external: closed,
        unknown: closed,
      },
    }),
  );
  document.set("sandbox", document.createNode({ required: false }));
  document.set("audit", document.createNode({ enabled: false }));
  document.set("mcp", document.createNode({ mode: "off" }));
  changes.push(
    "policy.default: allow (v1alpha2 had no tool policy)",
    "policy.projectTrust: project files stay tool-readable; project instructions, skills, extensions, themes, and MCP stay unloaded (as in v1alpha2)",
    "sandbox.required: false (v1alpha2 had no OS sandbox)",
    "audit.enabled: false (v1alpha2 had no audit log)",
    "mcp.mode: off (v1alpha2 had no MCP servers)",
    `Review the new governance defaults for ${mode} mode: resource, provider, and project trust (policy.resourceTrust, policy.providerTrust, policy.projectTrust) and capabilities now apply`,
  );
  return changes;
}

/**
 * v1alpha3 -> v1alpha4: adds the required update channel section with no
 * trust keys and no source, so updates stay disabled; release policy defaults.
 */
export function migrateToV1alpha4(document: YamlDocument): string[] {
  document.set("schema", PISHIP_SCHEMA_V1ALPHA4);
  document.set(
    "updates",
    document.createNode({
      channel: "stable",
      channels: ["stable"],
      rollback: true,
    }),
  );
  return [
    "schema: piship/v1alpha3 -> piship/v1alpha4",
    "updates.channel: stable, updates.channels: [stable], updates.rollback: true",
    "Updates stay disabled until updates.trust.keys and updates.source are configured",
    `release defaults apply: targets ${DEFAULT_RELEASE_TARGETS.join(", ")}; package sources ${DEFAULT_PACKAGE_SOURCES.join(", ")}; vulnerabilities.failOn high`,
  ];
}

/**
 * The expiry a migrated v1alpha4 key set's bootstrap root gets. A fixed
 * value keeps migration deterministic; the owner reviews it with the role
 * split.
 */
export const MIGRATED_BOOTSTRAP_EXPIRES = "2027-10-01T00:00:00Z";

/**
 * v1alpha4 -> v1alpha5: `updates.trust.keys` becomes a bootstrap root that
 * keeps the legacy keys as a compatibility trust set: every key is in both
 * the root and the channel role, threshold 1, so trust is exactly as strong
 * as before and no key is invented. No keys migrate to no bootstrap
 * (updates stay disabled).
 */
export function migrateToV1alpha5(
  document: YamlDocument,
  mode: DeploymentMode,
): string[] {
  const changes = ["schema: piship/v1alpha4 -> piship/v1alpha5"];
  document.set("schema", PISHIP_SCHEMA_V1ALPHA5);
  const legacy = document.getIn(["updates", "trust", "keys"], true);
  const json = document.toJS() as {
    updates?: { source?: unknown; trust?: { keys?: { id: string }[] } };
  };
  const ids = (json.updates?.trust?.keys ?? []).map((key) => key.id);
  if (ids.length === 0) {
    // v1alpha4 trust holds only keys, so nothing else is dropped.
    if (document.hasIn(["updates", "trust"]))
      document.deleteIn(["updates", "trust"]);
    changes.push(
      "updates.trust: no trusted update keys, so no bootstrap root; updates stay disabled (no key is invented)",
    );
    if (json.updates?.source !== undefined)
      changes.push(
        "updates.source is kept, but update fails closed and piship release refuses the distribution until updates.trust.bootstrap is configured",
      );
    return changes;
  }
  const role = () => {
    const node = document.createNode({ keyIds: ids, threshold: 1 });
    const keyIds = node.get("keyIds", true);
    if (isCollection(keyIds)) keyIds.flow = true;
    return node;
  };
  const bootstrap = document.createNode({
    version: 1,
    expires: MIGRATED_BOOTSTRAP_EXPIRES,
    keys: legacy,
    roles: { root: role(), channel: role() },
  });
  document.deleteIn(["updates", "trust", "keys"]);
  document.setIn(["updates", "trust", "bootstrap"], bootstrap);
  changes.push(
    `updates.trust.keys -> updates.trust.bootstrap: version 1, expires ${MIGRATED_BOOTSTRAP_EXPIRES}; the legacy keys (${ids.join(", ")}) are kept as a compatibility trust set in both the root and the channel role, threshold 1. No key is added and trust is no stronger than before`,
    mode === "managed"
      ? "Warning: the root and channel roles share the legacy keys. Managed rollout requires an explicit root / channel split: add an offline root key to updates.trust.bootstrap.roles.root and keep the release key in roles.channel; piship validate warns and piship release refuses this distribution until the roles are split"
      : "Review updates.trust.bootstrap: the root and channel roles share the legacy keys; an offline root key separate from the channel release key is recommended",
  );
  return changes;
}
