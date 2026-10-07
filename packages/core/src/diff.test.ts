import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIFF_TESTS, diffLocks, formatDiff } from "./diff/index.js";
import { PISHIP_VERSION } from "./compatibility.js";
import type { DistributionLock } from "./index.js";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const cli = join(repo, "packages", "cli", "dist", "bin.js");
const roots: string[] = [];

// The personal example's resources declared with the v0.1 personal alpha
// schema, so a v1alpha1 lock can be compared with a current one.
const V1ALPHA1_PERSONAL = `schema: piship/v1alpha1
app:
  id: mypi
  name: MyPi
  command: mypi
  version: 1.0.0
  theme: mypi
runtime:
  pi: "1.0.3"
deployment:
  mode: personal
resources:
  instructions:
    - ./resources/AGENTS.md
  skills:
    - ./resources/skills
  extensions:
    - ./resources/extensions/demo
  prompts:
    - ./resources/prompts
  themes:
    - ./resources/themes/mypi.json
`;

// The demo company's manifest as it was before its migration to
// piship/v1alpha6 and piship/v1, so these comparisons run on a piship-lock/v1alpha5 lock and
// the v1alpha6 fields are added to it below.
const V1ALPHA5_DEMO = readFileSync(
  join(repo, "examples", "demo-company", "piship.yaml"),
  "utf8",
)
  .replace("schema: piship/v1", "schema: piship/v1alpha5")
  .replace("action: model.select", "action: model.use")
  .replace(
    `        search: direct
        get_document: direct
        delete_document: direct
        "*": hidden
      class: company
      exposure: direct
`,
    "        allow: [search, get_document, delete_document]\n",
  );

/**
 * Lock a temporary copy of an example with the built CLI, optionally with a
 * replacement manifest.
 */
function lockExample(name: string, manifest?: string): DistributionLock {
  const dir = mkdtempSync(join(tmpdir(), "piship-diff-"));
  roots.push(dir);
  cpSync(join(repo, "examples", name), dir, { recursive: true });
  if (manifest) writeFileSync(join(dir, "piship.yaml"), manifest);
  const result = spawnSync(process.execPath, [cli, "lock", "piship.yaml"], {
    cwd: dir,
    env: process.env,
    encoding: "utf8",
  });
  if (result.status !== 0)
    throw new Error(`piship lock failed: ${result.stderr}${result.stdout}`);
  return JSON.parse(readFileSync(join(dir, "piship.lock"), "utf8"));
}

// Mutable deep copy for building "after" fixtures.
// biome-ignore lint/suspicious/noExplicitAny: fixtures mutate arbitrary lock fields
type Mutable = any;
let base: DistributionLock;
let personal: DistributionLock;
const clone = (lock: DistributionLock): Mutable => structuredClone(lock);

beforeAll(() => {
  base = lockExample("demo-company", V1ALPHA5_DEMO);
  personal = lockExample("personal", V1ALPHA1_PERSONAL);
});
afterAll(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("diffLocks", () => {
  it("reports nothing for identical locks", () => {
    expect(base.schema).toBe("piship-lock/v1alpha5");
    const report = diffLocks(base, clone(base));
    expect(report.risk).toBe("none");
    expect(report.changes).toEqual([]);
    expect(report.requiredTests).toEqual([]);
    expect(formatDiff(report)).toBe(
      `acmecode 1.0.0 -> 1.0.0 (risk: none)\nPi 1.0.3, PiShip ${PISHIP_VERSION}\nNo release-impact changes.\n`,
    );
  });

  it("flags a Pi version bump as high and requires compatibility tests", () => {
    const after = clone(base);
    after.runtime.version = "0.88.0";
    const report = diffLocks(base, after);
    expect(report.risk).toBe("high");
    expect(report.changes).toEqual([
      expect.objectContaining({
        area: "pi",
        kind: "changed",
        before: "1.0.3",
        after: "0.88.0",
        risk: "high",
      }),
    ]);
    expect(report.requiredTests).toEqual(
      expect.arrayContaining([
        DIFF_TESTS.check,
        DIFF_TESTS.compatibility,
        DIFF_TESTS.installed,
      ]),
    );
  });

  it("flags package content changed without a version change", () => {
    const after = clone(base);
    const pkg = after.runtime.packages[1];
    pkg.integrity = `sha512-${Buffer.alloc(64, 7).toString("base64")}`;
    const report = diffLocks(base, after);
    expect(report.changes).toHaveLength(1);
    expect(report.changes[0]).toMatchObject({
      area: "packages",
      item: `${pkg.path} integrity`,
      risk: "high",
      after: "sha512-070707070707",
    });
    expect(report.changes[0]?.reason).toMatch(/without a version change/);
  });

  it("flags v1alpha4 package origin and install-script changes", () => {
    const before = clone(base);
    before.runtime.packages[1].resolved =
      "https://registry.npmjs.org/x/-/x-1.0.0.tgz";
    const after = clone(before);
    after.runtime.packages[1].resolved =
      "https://user:secret@mirror.example.com/x/-/x-1.0.0.tgz";
    after.runtime.packages[1].installScript = true;
    const report = diffLocks(before, after);
    expect(report.changes.map((change) => change.risk)).toEqual([
      "high",
      "high",
    ]);
    expect(report.changes[1]).toMatchObject({
      before: "https://registry.npmjs.org",
      after: "https://mirror.example.com",
    });
    expect(JSON.stringify(report)).not.toContain("secret");
  });

  it("flags a new extension resource as executable code", () => {
    const after = clone(base);
    after.resources.push({
      kind: "extensions",
      path: "resources/extensions/new/index.ts",
      sha256: "a".repeat(64),
      class: "company",
    });
    const report = diffLocks(base, after);
    expect(report.changes).toEqual([
      {
        area: "extensions",
        kind: "added",
        item: "extensions resources/extensions/new/index.ts",
        after: "aaaaaaaaaaaa",
        risk: "high",
        reason: "Adds executable code (extensions).",
      },
    ]);
    expect(report.requiredTests).toContain(DIFF_TESTS.installed);
  });

  it("flags a trust class widening as high", () => {
    const after = clone(base);
    const resource = after.resources.find(
      (item: { kind: string }) => item.kind === "instructions",
    );
    resource.class = "user";
    const report = diffLocks(base, after);
    expect(report.changes).toEqual([
      expect.objectContaining({
        area: "resources",
        before: "company",
        after: "user",
        risk: "high",
      }),
    ]);
  });

  it("classifies policy relaxation as high and tightening as medium", () => {
    const relaxed = clone(base);
    const rule = (lock: Mutable) =>
      lock.governance.manifest.policy.defaults.find(
        (item: { id: string }) => item.id === "acme.shell",
      );
    rule(relaxed).effect = "allow";
    const relax = diffLocks(base, relaxed);
    expect(relax.risk).toBe("high");
    expect(relax.changes).toEqual([
      {
        area: "policy",
        kind: "changed",
        item: "policy rule acme.shell",
        before: "ask",
        after: "allow",
        risk: "high",
        reason: "Relaxes policy.",
      },
    ]);
    expect(relax.requiredTests).toContain(DIFF_TESTS.governance);

    const tightened = clone(base);
    rule(tightened).effect = "deny";
    expect(diffLocks(base, tightened).risk).toBe("medium");

    const removed = clone(base);
    removed.governance.manifest.policy.enforced.shift();
    expect(diffLocks(base, removed).changes[0]).toMatchObject({
      kind: "removed",
      item: "policy rule acme.secrets.read",
      risk: "high",
    });

    const defaultLoosened = clone(base);
    defaultLoosened.governance.manifest.policy.default = "allow";
    defaultLoosened.governance.manifest.policy.projectTrust.unknown.dimensions.skills =
      "allow";
    expect(
      diffLocks(base, defaultLoosened).changes.map((change) => change.risk),
    ).toEqual(["high", "high"]);
  });

  it("reads an undeclared Claude Code dimension as its mode's default", () => {
    // The managed default of claudeHooks is deny and of claudeRules
    // company-approved: declaring either changes nothing.
    const declared = clone(base);
    Object.assign(
      declared.governance.manifest.policy.projectTrust.company.dimensions,
      {
        claudeHooks: "deny",
        claudeRules: "company-approved",
      },
    );
    expect(diffLocks(base, declared).changes).toEqual([]);

    // Admitting hooks relaxes policy, whether or not the manifest declared the
    // dimension before.
    const hooks = clone(base);
    Object.assign(
      hooks.governance.manifest.policy.projectTrust.company.dimensions,
      {
        claudeHooks: "allow",
      },
    );
    expect(diffLocks(base, hooks).changes).toEqual([
      expect.objectContaining({
        area: "policy",
        item: "policy projectTrust.company.claudeHooks",
        before: "deny",
        after: "allow",
        risk: "high",
      }),
    ]);
    expect(diffLocks(declared, hooks).changes).toHaveLength(1);

    // Removing a declared approval tightens it.
    const closed = clone(hooks);
    Object.assign(
      closed.governance.manifest.policy.projectTrust.company.dimensions,
      {
        claudeHooks: "deny",
      },
    );
    expect(diffLocks(hooks, closed).risk).toBe("medium");
  });

  it("flags a new MCP server as high and a narrowed tool list as medium", () => {
    const added = clone(base);
    const docs = added.governance.manifest.mcp.servers[0];
    added.governance.manifest.mcp.servers.push({
      ...structuredClone(docs),
      id: "web",
      transport: "streamable-http",
      module: undefined,
      url: ["$", "{ACME_WEB_MCP_URL}"].join(""),
    });
    const report = diffLocks(base, added);
    expect(report.changes).toEqual([
      expect.objectContaining({
        area: "mcp",
        kind: "added",
        item: "mcp server web",
        risk: "high",
      }),
    ]);

    const narrowed = clone(base);
    narrowed.governance.manifest.mcp.servers[0].tools.allow = ["search"];
    const narrow = diffLocks(base, narrowed);
    expect(narrow.risk).toBe("medium");
    expect(narrow.changes.map((change) => change.item)).toEqual([
      "mcp server docs tools.allow delete_document",
      "mcp server docs tools.allow get_document",
    ]);
  });

  it("flags plain HTTP as high and an identity header as medium", () => {
    const https = clone(base);
    https.governance.manifest.mcp.servers.push({
      ...structuredClone(https.governance.manifest.mcp.servers[0]),
      id: "tickets",
      transport: "streamable-http",
      module: undefined,
      url: "https://mcp.corp.internal/mcp",
      httpTransport: "https",
    });
    const plain = clone(https);
    const tickets = plain.governance.manifest.mcp.servers.at(-1);
    Object.assign(tickets, {
      httpTransport: "http-allowed",
      headers: { "X-Company-User": { identityClaim: "preferred_username" } },
    });
    const report = diffLocks(https, plain);
    expect(report.risk).toBe("high");
    expect(report.changes).toEqual([
      expect.objectContaining({
        area: "mcp",
        kind: "added",
        item: "mcp server tickets headers X-Company-User: preferred_username",
        risk: "medium",
      }),
      expect.objectContaining({
        area: "mcp",
        kind: "changed",
        item: "mcp server tickets httpTransport",
        before: "https",
        after: "http-allowed",
        risk: "high",
      }),
    ]);
    expect(
      diffLocks(plain, https).changes.map((change) => change.risk),
    ).toEqual(["low", "low"]);
  });

  it("treats an absent httpTransport and http-allowed as the same default", () => {
    const absent = clone(base);
    absent.governance.manifest.mcp.servers.push({
      ...structuredClone(absent.governance.manifest.mcp.servers[0]),
      id: "tickets",
      transport: "streamable-http",
      module: undefined,
      url: "http://10.20.30.40/mcp",
    });
    const explicit = clone(absent);
    explicit.governance.manifest.mcp.servers.at(-1).httpTransport =
      "http-allowed";
    expect(diffLocks(absent, explicit).changes).toEqual([]);
    expect(diffLocks(explicit, absent).changes).toEqual([]);
    // Only an explicit https differs, and it is the tighter side.
    const strict = clone(absent);
    strict.governance.manifest.mcp.servers.at(-1).httpTransport = "https";
    expect(
      diffLocks(absent, strict).changes.map(({ item, risk }) => ({
        item,
        risk,
      })),
    ).toEqual([{ item: "mcp server tickets httpTransport", risk: "low" }]);
    expect(
      diffLocks(strict, absent).changes.map(({ item, risk }) => ({
        item,
        risk,
      })),
    ).toEqual([{ item: "mcp server tickets httpTransport", risk: "high" }]);
  });

  it("flags plain HTTP on the gateway, broker, identity, audit sinks, and sandbox as high", () => {
    const https = clone(base);
    https.governance.manifest.audit.sinks.push({
      id: "collector",
      type: "http",
      url: "https://audit.corp.internal/events",
      required: false,
      httpTransport: "https",
    });
    https.access.inference.httpTransport = "https";
    https.access.credential.broker.httpTransport = "https";
    https.access.identity.oidc.httpTransport = "https";
    https.governance.manifest.sandbox.endpoint =
      "https://sandbox.corp.internal";
    https.governance.manifest.sandbox.httpTransport = "https";
    const plain = clone(https);
    plain.access.inference.httpTransport = "http-allowed";
    plain.access.credential.broker.httpTransport = "http-allowed";
    plain.access.identity.oidc.httpTransport = "http-allowed";
    plain.governance.manifest.audit.sinks.at(-1).httpTransport = "http-allowed";
    plain.governance.manifest.sandbox.httpTransport = "http-allowed";
    plain.governance.manifest.sandbox.httpTransport = "http-allowed";
    const report = diffLocks(https, plain);
    expect(report.risk).toBe("high");
    expect(
      report.changes.map(({ item, risk, after }) => ({ item, risk, after })),
    ).toEqual([
      { item: "sandbox httpTransport", risk: "high", after: "http-allowed" },
      {
        item: "audit sink collector httpTransport",
        risk: "high",
        after: "http-allowed",
      },
      {
        item: "credential broker httpTransport",
        risk: "high",
        after: "http-allowed",
      },
      {
        item: "identity httpTransport",
        risk: "high",
        after: "http-allowed",
      },
      {
        item: "inference httpTransport",
        risk: "high",
        after: "http-allowed",
      },
    ]);
    expect(
      diffLocks(plain, https).changes.map((change) => change.risk),
    ).toEqual(["low", "low", "low", "low", "low"]);
  });

  it("names plain HTTP and identity headers of an added server", () => {
    const added = clone(base);
    added.governance.manifest.mcp.servers.push({
      ...structuredClone(added.governance.manifest.mcp.servers[0]),
      id: "tickets",
      transport: "streamable-http",
      module: undefined,
      url: "http://10.20.30.40/mcp",
      httpTransport: "http-allowed",
      headers: { "X-Company-User": { identityClaim: "preferred_username" } },
    });
    const report = diffLocks(base, added);
    expect(
      report.changes.map(({ item, risk, after }) => ({ item, risk, after })),
    ).toEqual(
      expect.arrayContaining([
        {
          item: "mcp server tickets",
          risk: "high",
          after: "streamable-http",
        },
        {
          item: "mcp server tickets httpTransport",
          risk: "high",
          after: "http-allowed",
        },
        {
          item: "mcp server tickets headers X-Company-User: preferred_username",
          risk: "medium",
          after: "X-Company-User: preferred_username",
        },
      ]),
    );
    expect(report.changes).toHaveLength(3);
  });

  it("flags a sandbox that no longer fails closed", () => {
    const after = clone(base);
    after.governance.manifest.sandbox.required = false;
    const report = diffLocks(base, after);
    expect(report.changes).toEqual([
      expect.objectContaining({
        area: "sandbox",
        item: "sandbox required",
        before: "true",
        after: "false",
        risk: "high",
      }),
    ]);
    expect(report.requiredTests).toEqual(
      expect.arrayContaining([DIFF_TESTS.sandbox, DIFF_TESTS.governance]),
    );
  });

  it("reports a sandbox backend switch and its user", () => {
    const after = clone(base);
    Object.assign(after.governance.manifest.sandbox, {
      provider: "e2b-compatible",
      endpoint: "https://cube.acme.example",
      user: "root",
    });
    const report = diffLocks(base, after);
    expect(report.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          item: "sandbox provider",
          before: "native",
          after: "e2b-compatible",
          risk: "high",
        }),
        expect.objectContaining({
          item: "sandbox user",
          after: "root",
          risk: "medium",
        }),
      ]),
    );
  });

  it("classifies a model allowlist addition as medium", () => {
    const after = clone(base);
    after.access.models.allowed.push("acme/large");
    const report = diffLocks(base, after);
    expect(report.risk).toBe("medium");
    expect(report.changes).toEqual([
      {
        area: "models",
        kind: "added",
        item: "model acme/large",
        after: "acme/large",
        risk: "medium",
        reason: "Allows an additional model.",
      },
    ]);
    expect(report.requiredTests).toEqual([
      DIFF_TESTS.managed,
      DIFF_TESTS.check,
    ]);
  });

  it("flags update trust key changes and never prints key material", () => {
    const keyA = `MCowBQYDK2VwAyEA${Buffer.alloc(32, 1).toString("base64")}`;
    const keyB = `MCowBQYDK2VwAyEA${Buffer.alloc(32, 2).toString("base64")}`;
    const updates = (publicKey: string) => ({
      channel: "stable",
      channels: ["stable"],
      rollback: true,
      trust: { keys: [{ id: "acme-release-2026", publicKey }] },
    });
    const before = { ...clone(base), updates: updates(keyA) };
    const after = { ...clone(base), updates: updates(keyB) };
    after.updates.channels.push("dev");
    const report = diffLocks(before, after);
    expect(report.changes).toEqual([
      expect.objectContaining({
        area: "updates",
        item: "update channels dev",
        risk: "medium",
      }),
      expect.objectContaining({
        area: "updates",
        kind: "changed",
        item: "update trust key acme-release-2026",
        risk: "high",
        reason: "Changes who can publish updates.",
      }),
    ]);
    expect(report.changes[1]?.after).toMatch(/^sha256:[0-9a-f]{12}$/);
    expect(JSON.stringify(report)).not.toContain(keyB);
    expect(report.requiredTests).toContain(DIFF_TESTS.release);
  });

  it("flags v1alpha5 bootstrap root changes as changes to who can publish", () => {
    const keyA = `MCowBQYDK2VwAyEA${Buffer.alloc(32, 1).toString("base64")}`;
    const keyB = `MCowBQYDK2VwAyEA${Buffer.alloc(32, 2).toString("base64")}`;
    const updates = (channel: string[], version: number) => ({
      channel: "stable",
      channels: ["stable"],
      rollback: true,
      trust: {
        bootstrap: {
          version,
          expires: "2027-10-01T00:00:00Z",
          keys: [
            { id: "acme-root", publicKey: keyA },
            { id: "acme-channel", publicKey: keyB },
          ],
          roles: {
            root: { keyIds: ["acme-root"], threshold: 1 },
            channel: { keyIds: channel, threshold: 1 },
          },
        },
      },
    });
    const report = diffLocks(
      { ...clone(base), updates: updates(["acme-channel"], 1) },
      { ...clone(base), updates: updates(["acme-channel", "acme-root"], 2) },
    );
    expect(report.changes).toEqual([
      expect.objectContaining({
        item: "update bootstrap root version",
        kind: "changed",
        risk: "high",
      }),
      expect.objectContaining({
        item: "update channel role key acme-root",
        kind: "added",
        risk: "high",
      }),
    ]);
    expect(JSON.stringify(report)).not.toContain(keyA);
  });

  it("formats a report deterministically", () => {
    const after = clone(base);
    after.app.version = "1.1.0";
    after.runtime.pishipVersion = "0.2.0";
    after.access.models.default = "acme/review";
    const report = diffLocks(base, after);
    expect(formatDiff(report)).toBe(
      [
        "acmecode 1.0.0 -> 1.1.0 (risk: medium)",
        `Pi 1.0.3, PiShip ${PISHIP_VERSION} -> 0.2.0`,
        "Changes:",
        "  [low] distribution: changed version (1.0.0 -> 1.1.0): Release version change.",
        `  [medium] piship: changed PiShip version (${PISHIP_VERSION} -> 0.2.0): PiShip runtime changed; launch and governance code differ.`,
        "  [low] models: changed default model (acme/coder -> acme/review): Default model changed.",
        "Required tests:",
        `  - ${DIFF_TESTS.compatibility}`,
        `  - ${DIFF_TESTS.installed}`,
        `  - ${DIFF_TESTS.managed}`,
        `  - ${DIFF_TESTS.check}`,
        "",
      ].join("\n"),
    );
    expect(formatDiff(diffLocks(base, after))).toBe(formatDiff(report));
  });

  it("compares a v1alpha1 lock with a v1alpha3 lock", () => {
    expect(personal.schema).toBe("piship-lock/v1alpha1");
    const report = diffLocks(personal, base);
    expect(report.risk).toBe("high");
    const items = report.changes.map(
      (change) => `${change.area} ${change.item}`,
    );
    expect(items).toEqual(
      expect.arrayContaining([
        "distribution id",
        "distribution deployment mode",
        "schema lock schema",
        "policy governance",
        "access access",
      ]),
    );
    expect(() => formatDiff(diffLocks(base, personal))).not.toThrow();
  });

  it("does not report the model.use -> model.select rename", () => {
    const before = clone(base);
    const after = clone(base);
    const rule = {
      id: "acme.models",
      action: "model.use",
      resource: "acme/**",
      effect: "allow",
    };
    before.governance.manifest.policy.defaults.push(rule);
    after.governance.manifest.policy.defaults.push({
      ...rule,
      action: "model.select",
    });
    expect(diffLocks(before, after).changes).toEqual([]);
  });

  describe("v1alpha6 lock fields", () => {
    const v6 = (): Mutable => {
      const lock = clone(base);
      lock.runtimeTools = { codemode: "off", toolSearch: "off", exposure: [] };
      lock.tools = [
        { tool: "bash", origin: "piship", exposure: "direct" },
        { tool: "docs:delete_*", origin: "mcp", exposure: "hidden" },
      ];
      lock.enforcement = {
        pi: "1.0.0",
        seams: { "tool.execute": "hook", "web.request": "none" },
        digest: `sha256-${"a".repeat(64)}`,
      };
      lock.data = {
        contract: "piship-data/v1",
        declared: {
          retention: {
            sessions: { retentionSeconds: 2_592_000 },
            audit: { retentionSeconds: 15_552_000 },
          },
          purge: { onLogout: ["cache", "temp"], onUninstall: "none" },
          export: { public: "deny" },
        },
      };
      lock.sessionExportStatus = {
        public: "unsupported",
        local: "unsupported",
        support: "enforced",
      };
      lock.virtualModels = [
        { id: "acme/auto", router: "acme-router", routes: ["acme/coder"] },
      ];
      return lock;
    };
    const find = (report: ReturnType<typeof diffLocks>, item: string) =>
      report.changes.find((change) => change.item === item);

    it("reports nothing for identical v1alpha6 locks", () => {
      expect(diffLocks(v6(), v6()).changes).toEqual([]);
    });

    it("treats the fields of an older lock as absent", () => {
      const report = diffLocks(base, v6());
      expect(find(report, "seam evidence")).toMatchObject({
        area: "enforcement",
        kind: "added",
        risk: "low",
      });
      expect(find(report, "virtual model acme/auto")).toMatchObject({
        risk: "high",
        after: "acme/coder",
      });
      expect(() => formatDiff(report)).not.toThrow();
    });

    it("flags widened exposure and Codemode as high", () => {
      const after = v6();
      after.runtimeTools.codemode = "on";
      after.runtimeTools.toolSearch = "on";
      after.runtimeTools.exposure = [{ pattern: "bash", exposure: "deferred" }];
      after.tools[1].exposure = "direct";
      after.tools[0].exposure = "deferred";
      const report = diffLocks(v6(), after);
      expect(report.risk).toBe("high");
      expect(find(report, "Codemode")).toMatchObject({
        area: "tools",
        before: "off",
        after: "on",
        risk: "high",
      });
      expect(find(report, "tool search")?.risk).toBe("medium");
      expect(find(report, "exposure rule bash")?.risk).toBe("medium");
      expect(find(report, "tool mcp docs:delete_*")).toMatchObject({
        before: "hidden",
        after: "direct",
        risk: "high",
        reason: "Exposure widened: the model can see or reach more.",
      });
      expect(find(report, "tool piship bash")?.risk).toBe("medium");
      expect(report.requiredTests).toContain(DIFF_TESTS.governance);
    });

    it("flags any enforcement downgrade as high", () => {
      const after = v6();
      after.enforcement.pi = "1.0.3";
      after.enforcement.seams["tool.execute"] = "none";
      after.sessionExportStatus.support = "unsupported";
      const report = diffLocks(v6(), after);
      expect(find(report, "seam table Pi")?.risk).toBe("medium");
      expect(find(report, "seam tool.execute")).toMatchObject({
        area: "enforcement",
        before: "hook",
        after: "none",
        risk: "high",
      });
      expect(find(report, "session export support")?.risk).toBe("high");
      // A status the lock no longer records is a downgrade too.
      const dropped = v6();
      delete (dropped.sessionExportStatus as Record<string, string>).support;
      expect(
        find(diffLocks(v6(), dropped), "session export support"),
      ).toMatchObject({ kind: "removed", risk: "high" });
      expect(
        find(diffLocks(dropped, v6()), "session export support")?.risk,
      ).toBe("low");
      expect(report.requiredTests).toContain(DIFF_TESTS.compatibility);
      const upgraded = diffLocks(after, v6());
      expect(find(upgraded, "seam tool.execute")?.risk).toBe("medium");
      // Only the digest moved: the per-resource evidence changed.
      const digest = v6();
      digest.enforcement.digest = `sha256-${"b".repeat(64)}`;
      expect(diffLocks(v6(), digest).changes).toMatchObject([
        { item: "seam digest", risk: "medium" },
      ]);
    });

    it("flags allowed export and shorter audit retention as high", () => {
      const after = v6();
      after.data.declared.export.public = "allow";
      after.data.declared.retention.audit.retentionSeconds = 86_400;
      after.data.declared.retention.sessions.retentionSeconds = 86_400;
      after.data.declared.purge.onLogout = ["temp"];
      const report = diffLocks(v6(), after);
      expect(find(report, "export public")).toMatchObject({
        area: "data",
        risk: "high",
        reason: "Session export allowed.",
      });
      expect(find(report, "retention audit")?.risk).toBe("high");
      expect(find(report, "retention sessions")?.risk).toBe("medium");
      expect(find(report, "purge on logout cache")).toMatchObject({
        kind: "removed",
        risk: "medium",
      });
    });

    it("records the uninstall purge without claiming uninstall applies it", () => {
      const after = v6();
      after.data.declared.purge.onUninstall = "all";
      const report = diffLocks(v6(), after);
      expect(find(report, "purge on uninstall")).toMatchObject({
        area: "data",
        before: "none",
        after: "all",
        risk: "low",
        reason:
          "Uninstall purge recorded: all (not applied: uninstall keeps state).",
      });
      const back = diffLocks(after, v6());
      expect(find(back, "purge on uninstall")).toMatchObject({
        before: "all",
        after: "none",
        risk: "low",
        reason:
          "Uninstall purge recorded: none (uninstall keeps state, as before).",
      });
    });

    it("flags a new Pi package or a changed resolution as high", () => {
      const pkg = {
        id: "pi-platform",
        source: "npm",
        class: "company",
        url: "https://registry.npmjs.org/",
        version: "1.0.0",
        integrity: `sha512-${"A".repeat(86)}==`,
        tree: `sha256-${"c".repeat(64)}`,
        files: 4,
        resources: [],
      };
      const before = v6();
      const after = v6();
      after.packages = [pkg];
      expect(
        find(diffLocks(before, after), "Pi package pi-platform"),
      ).toMatchObject({
        area: "packages",
        kind: "added",
        after: "npm 1.0.0",
        risk: "high",
      });
      before.packages = [pkg];
      after.packages = [
        {
          ...pkg,
          version: "1.0.1",
          tree: `sha256-${"d".repeat(64)}`,
          class: "user",
        },
      ];
      const changed = diffLocks(before, after);
      for (const item of ["version", "tree", "class"])
        expect(find(changed, `Pi package pi-platform ${item}`)?.risk).toBe(
          "high",
        );
      expect(changed.requiredTests).toContain(DIFF_TESTS.compatibility);
    });

    it("reports what a package is given: its environment and its configuration files", () => {
      const pkg = {
        id: "pi-bg",
        source: "npm",
        class: "user",
        url: "https://registry.npmjs.org/",
        version: "1.0.0",
        integrity: `sha512-${"A".repeat(86)}==`,
        tree: `sha256-${"c".repeat(64)}`,
        files: 4,
        resources: [],
      };
      const file = (sha: string, mode = "seed") => ({
        path: "extensions/pi-bg/config.json",
        mode,
        sha256: `sha256-${sha.repeat(64)}`,
      });
      const before = v6();
      before.packages = [
        {
          ...pkg,
          environment: { PI_BG_FEATURES: "process", PI_BG_OLD_FLAG: "1" },
          agentFiles: [file("a")],
        },
      ];
      const after = v6();
      after.packages = [
        {
          ...pkg,
          environment: {
            PI_BG_FEATURES: "process,delegate",
            PI_BG_NEW_FLAG: "1",
            PI_BG_HOME: { statePath: "bg" },
          },
          agentFiles: [file("b", "enforce")],
        },
      ];
      const report = diffLocks(before, after);
      expect(
        find(report, "Pi package pi-bg environment PI_BG_FEATURES"),
      ).toMatchObject({
        area: "packages",
        kind: "changed",
        before: "process",
        after: "process,delegate",
        risk: "medium",
      });
      expect(
        find(report, "Pi package pi-bg environment PI_BG_NEW_FLAG"),
      ).toMatchObject({
        kind: "added",
        risk: "medium",
      });
      expect(
        find(report, "Pi package pi-bg environment PI_BG_HOME")?.after,
      ).toBe('{"statePath":"bg"}');
      expect(
        find(report, "Pi package pi-bg environment PI_BG_OLD_FLAG"),
      ).toMatchObject({
        kind: "removed",
        risk: "low",
      });
      expect(
        find(
          report,
          "Pi package pi-bg file extensions/pi-bg/config.json content",
        )?.risk,
      ).toBe("high");
      expect(
        find(report, "Pi package pi-bg file extensions/pi-bg/config.json mode"),
      ).toMatchObject({ before: "seed", after: "enforce", risk: "medium" });
      // A configuration file that appears is high; one that goes is low.
      const bare = v6();
      bare.packages = [pkg];
      expect(
        find(
          diffLocks(bare, before),
          "Pi package pi-bg file extensions/pi-bg/config.json",
        )?.risk,
      ).toBe("high");
      expect(
        find(
          diffLocks(before, bare),
          "Pi package pi-bg file extensions/pi-bg/config.json",
        )?.risk,
      ).toBe("low");
    });

    it("reports cache warming, absent as off", () => {
      const after = v6();
      after.cacheWarming = { mode: "streaming", userOverride: true };
      const report = diffLocks(v6(), after);
      expect(find(report, "cache warming")).toMatchObject({
        area: "models",
        before: "off",
        after: "streaming",
        risk: "medium",
      });
      expect(find(report, "cache warming userOverride")?.risk).toBe("medium");
      const off = v6();
      off.cacheWarming = { mode: "off", userOverride: false };
      expect(diffLocks(v6(), off).changes).toEqual([]);
    });

    it("flags a new physical route as high", () => {
      const after = v6();
      after.virtualModels[0].routes.push("anthropic/claude-opus-x");
      after.virtualModels[0].router = "acme-router-2";
      const report = diffLocks(v6(), after);
      expect(
        find(report, "virtual model acme/auto route anthropic/claude-opus-x"),
      ).toMatchObject({ area: "models", kind: "added", risk: "high" });
      expect(find(report, "virtual model acme/auto router")?.risk).toBe(
        "medium",
      );
    });
  });
});
