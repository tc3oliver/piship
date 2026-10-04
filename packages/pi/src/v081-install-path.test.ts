// The install path from v0.8.1: a distribution still on a piship/v1alpha5
// manifest, launched by v0.9 over the state a v0.8.1 runtime left, and the
// rollback contract back to v0.8.1. v0.9 reads that state as it is and
// rewrites none of it, and keeps every schema id v0.8.1 reads, so v0.8.1
// still launches over the state v0.9 leaves (including audit logs that hold
// the event types v0.9 added).
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AUDIT_BATCH_SCHEMA,
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_TYPES,
  type ManagedFetch,
} from "@piship/contracts";
import {
  LOCK_SCHEMA_V1ALPHA5,
  resolveLock,
  STATE_SCHEMAS,
  sweepDistributionData,
} from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { GovernanceSession } from "./governance-session.js";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** What v0.8.1 (d069104) reads: its STATE_SCHEMAS. */
const V081_STATE_SCHEMAS = {
  state: ["piship-state/v1"],
  identity: ["piship-identity-metadata/v1"],
  credential: ["piship-credential-metadata/v1"],
  preferences: ["piship-preferences/v1"],
  metrics: ["piship-metrics/v1"],
  audit: ["piship-audit/v1"],
  sandboxCredential: ["piship-sandbox-credential-metadata/v1"],
  credentialIssuance: ["piship-credential-issuance/v1"],
};

/** v0.8.1's AUDIT_EVENT_TYPES. */
const V081_AUDIT_EVENT_TYPES = [
  "session.start",
  "session.end",
  "identity.login",
  "identity.refresh",
  "identity.logout",
  "credential.acquire",
  "credential.refresh",
  "credential.revoke",
  "model.request",
  "model.denied",
  "resource.load",
  "resource.denied",
  "provider.load",
  "provider.denied",
  "tool.request",
  "tool.allowed",
  "tool.denied",
  "mcp.server.start",
  "mcp.call",
  "mcp.denied",
  "policy.loaded",
  "policy.violation",
  "policy.auto_enabled",
  "policy.auto_disabled",
  "policy.auto_approved",
  "runtime.update",
  "runtime.rollback",
];

/** A v0.8.1-era personal manifest, still on piship/v1alpha5. */
const V1ALPHA5 = `schema: piship/v1alpha5
app: { id: acmepi, name: AcmePi, command: acmepi, version: 1.0.0 }
runtime: { pi: "1.0.2" }
deployment: { mode: personal }
identity: { mode: none }
credential: { provider: none }
inference:
  provider: openai-compatible
  baseUrl: https://gateway.acme.example/v1
models:
  default: acme/coder
  allowed: [acme/coder]
  catalog:
    acme/coder: { name: Acme Coder, contextWindow: 128000, maxOutputTokens: 8192 }
policy:
  default: ask
  defaults:
    - { id: models, action: model.use, resource: "acme/**", effect: allow }
audit:
  enabled: true
  sinks:
    - { id: local, type: file, required: true }
updates: { channel: stable, channels: [stable] }
`;

/** A user rule as v0.8.1 writes it, under the action name it knew. */
const V081_USER_RULES = `${JSON.stringify(
  [
    {
      id: "user.no-coder",
      action: "model.use",
      resource: "acme/coder",
      effect: "deny",
    },
  ],
  null,
  2,
)}\n`;

const V081_AUDIT_LINE = `${JSON.stringify({
  schema: "piship-audit/v1",
  event: "session.start",
  time: "2026-10-03T10:00:00.000Z",
  user: null,
  session: "s-081",
  distribution: "acmepi",
})}\n`;

function snapshot(dir: string): Record<string, string> {
  const files: Record<string, string> = {};
  const visit = (path: string, prefix: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) visit(child, `${prefix}${entry.name}/`);
      else files[`${prefix}${entry.name}`] = readFileSync(child, "utf8");
    }
  };
  visit(dir, "");
  return files;
}

function v081Distribution() {
  const root = mkdtempSync(join(tmpdir(), "piship-v081-path-"));
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const state = join(root, "state");
  for (const path of [
    distribution,
    workspace,
    join(state, "config"),
    join(state, "logs"),
  ])
    mkdirSync(path, { recursive: true });
  writeFileSync(join(distribution, "piship.yaml"), V1ALPHA5);
  writeFileSync(join(state, "config", "policy.json"), V081_USER_RULES);
  writeFileSync(join(state, "logs", "audit.jsonl.1"), V081_AUDIT_LINE);
  return { root, distribution, workspace, state };
}

describe("v0.8.1 state and a v1alpha5 manifest under v0.9", () => {
  it("locks the v1alpha5 manifest without v1alpha6 sections", () => {
    const { distribution } = v081Distribution();
    const lock = resolveLock(join(distribution, "piship.yaml"));
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA5);
    expect(lock.manifest.schema).toBe("piship/v1alpha5");
    for (const field of [
      "runtimeTools",
      "tools",
      "enforcement",
      "data",
      "sessionExportStatus",
      "virtualModels",
      "packages",
      "cacheWarming",
    ])
      expect(lock).not.toHaveProperty(field);
  });

  it("launches over v0.8.1 state, reads model.use as model.select, and rewrites nothing", async () => {
    const { distribution, workspace, state, root } = v081Distribution();
    const lock = resolveLock(join(distribution, "piship.yaml"));
    const configBefore = snapshot(join(state, "config"));
    const rotatedBefore = readFileSync(
      join(state, "logs", "audit.jsonl.1"),
      "utf8",
    );
    // No `data` section: no retention sweep runs, as on v0.8.1.
    expect(
      await sweepDistributionData(
        { metadata: lock, stateDir: state } as never,
        "launch",
      ),
    ).toBeUndefined();
    const session = await GovernanceSession.open({
      lock: lock as Parameters<typeof GovernanceSession.open>[0]["lock"],
      distributionDir: distribution,
      stateDir: state,
      cwd: workspace,
      piVersion: "1.0.2",
      interactive: false,
      fetch: (() => {
        throw new Error("no network in unit tests");
      }) as unknown as ManagedFetch,
      resolveTemplate: (_key, template) => template,
      homeDir: join(root, "home"),
    });
    sessions.push(session);
    // The v0.8.1 user rule still applies, under the renamed action.
    expect(
      session.engine.evaluate({
        action: "model.select",
        resource: "acme/coder",
      }),
    ).toMatchObject({ effect: "deny", ruleId: "user.no-coder" });
    await session.close();
    sessions.splice(sessions.indexOf(session), 1);
    // State files are read as they are; a rollback to v0.8.1 reads them.
    expect(snapshot(join(state, "config"))).toEqual(configBefore);
    expect(readFileSync(join(state, "logs", "audit.jsonl.1"), "utf8")).toBe(
      rotatedBefore,
    );
    // What v0.9 appended keeps the event schema v0.8.1 reads.
    const live = readFileSync(join(state, "logs", "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { schema: string });
    expect(live.length).toBeGreaterThan(0);
    for (const event of live) expect(event.schema).toBe(AUDIT_EVENT_SCHEMA);
  });
});

describe("rollback to v0.8.1", () => {
  it("keeps every state schema id v0.8.1 reads", () => {
    expect(STATE_SCHEMAS).toEqual(V081_STATE_SCHEMAS);
  });

  it("keeps the audit schema ids, and only adds event types", () => {
    // v0.8.1's doctor reads the local log by `piship-audit/v1` and skips an
    // event type it does not know; collectors get `piship-audit-batch/v1`.
    expect(AUDIT_EVENT_SCHEMA).toBe("piship-audit/v1");
    expect(AUDIT_BATCH_SCHEMA).toBe("piship-audit-batch/v1");
    expect(AUDIT_EVENT_TYPES).toEqual(
      expect.arrayContaining(V081_AUDIT_EVENT_TYPES),
    );
    const added = AUDIT_EVENT_TYPES.filter(
      (type) => !V081_AUDIT_EVENT_TYPES.includes(type),
    );
    expect(added).toEqual(
      expect.arrayContaining([
        "model.dispatch",
        "session.export",
        "runtime.mutation.reverted",
        "data.swept",
      ]),
    );
  });
});
