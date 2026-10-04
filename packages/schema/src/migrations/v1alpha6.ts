// piship/v1alpha5 -> piship/v1alpha6. Deterministic and never broadening:
// every value it writes keeps the v0.8 decision, and the one default that
// changes (cache warming) is reported as an effective change.
import { isMap, isSeq } from "yaml";
import { defaultMcpServerClass } from "../governance.js";
import { PISHIP_SCHEMA_V1ALPHA6 } from "../versions.js";
import type {
  MigrationContext,
  MigrationStepResult,
  YamlDocument,
} from "./types.js";

const RULE_SECTIONS = ["enforced", "defaults"] as const;

/** `model.use` rules become `model.select` rules; the decision is the same. */
function renameModelUse(document: YamlDocument, changes: string[]): void {
  for (const section of RULE_SECTIONS) {
    const rules = document.getIn(["policy", section], true);
    if (!isSeq(rules)) continue;
    rules.items.forEach((rule, index) => {
      if (!isMap(rule) || rule.get("action") !== "model.use") return;
      rule.set("action", "model.select");
      changes.push(
        `policy.${section}[${index}].action: model.use -> model.select (the same rule; model.use stays accepted as an alias)`,
      );
    });
  }
}

/**
 * The exposure map that keeps a v1alpha5 `tools.allow` / `tools.deny`
 * filter: denied tools are hidden, and with an allowlist every other tool is
 * hidden too.
 */
function exposureMap(
  allow: readonly string[],
  deny: readonly string[],
): Record<string, string> {
  const map: Record<string, string> = {};
  for (const name of allow) map[name] = "direct";
  for (const name of deny) map[name] = "hidden";
  if (allow.length) map["*"] = "hidden";
  return map;
}

function migrateServers(
  document: YamlDocument,
  context: MigrationContext,
  changes: string[],
  effective: string[],
): void {
  const governance = context.parse().governance;
  const servers = governance?.mcp.servers ?? [];
  const trust = governance?.policy.resourceTrust;
  const cls = defaultMcpServerClass(context.mode);
  for (const server of servers) {
    const path = ["mcp", "servers", server.id];
    const at = `mcp.servers.${server.id}`;
    document.setIn([...path, "class"], cls);
    changes.push(
      `${at}.class: ${cls} (${context.mode} distribution servers); the server is now governed by policy.resourceTrust.${cls}`,
    );
    if (trust && trust[cls] !== "allow")
      effective.push(
        `${at}.class: ${cls} is denied by policy.resourceTrust.${cls}, so ${server.id} would no longer start; allow the class or remove the server before migrating`,
      );
    document.setIn([...path, "exposure"], "direct");
    changes.push(`${at}.exposure: direct (v0.8 behavior)`);
    const { allow, deny } = server.tools;
    if (allow.length || deny.length) {
      document.setIn(
        [...path, "tools"],
        document.createNode(exposureMap(allow, deny)),
      );
      changes.push(
        `${at}.tools: allow/deny -> an exposure map (${[
          ...allow.map((name) => `${name}: direct`),
          ...deny.map((name) => `${name}: hidden`),
          ...(allow.length ? ["*: hidden"] : []),
        ].join(", ")}); the same tools stay visible`,
      );
    } else if (document.hasIn([...path, "tools"])) {
      document.deleteIn([...path, "tools"]);
      changes.push(
        `${at}.tools: empty filter removed (every tool stays visible)`,
      );
    }
  }
}

export function migrateToV1alpha6(
  document: YamlDocument,
  context: MigrationContext,
): MigrationStepResult {
  const changes = ["schema: piship/v1alpha5 -> piship/v1alpha6"];
  const effective: string[] = [];
  renameModelUse(document, changes);
  migrateServers(document, context, changes, effective);
  const warming =
    "runtime.cacheWarming: absent, which is off in piship/v1alpha6; v0.8 sessions warmed the prompt cache (Pi's default, streaming). Set runtime.cacheWarming.mode: streaming to keep warming";
  changes.push(warming);
  effective.push(warming);
  changes.push("data: absent, so no retention sweep runs (as in v0.8)");
  document.set("schema", PISHIP_SCHEMA_V1ALPHA6);
  return { changes, effective };
}
