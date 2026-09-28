import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIFF_TESTS, diffLocks, formatDiff } from "./diff.js";
import type { DistributionLock } from "./index.js";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const cli = join(repo, "packages", "cli", "dist", "bin.js");
const roots: string[] = [];

/** Lock a temporary copy of an example with the built CLI. */
function lockExample(name: string): DistributionLock {
  const dir = mkdtempSync(join(tmpdir(), "piship-diff-"));
  roots.push(dir);
  cpSync(join(repo, "examples", name), dir, { recursive: true });
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
  base = lockExample("demo-company");
  personal = lockExample("personal");
});
afterAll(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("diffLocks", () => {
  it("reports nothing for identical locks", () => {
    expect(base.schema).toBe("piship-lock/v1alpha4");
    const report = diffLocks(base, clone(base));
    expect(report.risk).toBe("none");
    expect(report.changes).toEqual([]);
    expect(report.requiredTests).toEqual([]);
    expect(formatDiff(report)).toBe(
      "acmecode 1.0.0 -> 1.0.0 (risk: none)\nPi 0.87.1, PiShip 0.1.0\nNo release-impact changes.\n",
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
        before: "0.87.1",
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

  it("formats a report deterministically", () => {
    const after = clone(base);
    after.app.version = "1.1.0";
    after.runtime.pishipVersion = "0.2.0";
    after.access.models.default = "acme/review";
    const report = diffLocks(base, after);
    expect(formatDiff(report)).toBe(
      [
        "acmecode 1.0.0 -> 1.1.0 (risk: medium)",
        "Pi 0.87.1, PiShip 0.1.0 -> 0.2.0",
        "Changes:",
        "  [low] distribution: changed version (1.0.0 -> 1.1.0): Release version change.",
        "  [medium] piship: changed PiShip version (0.1.0 -> 0.2.0): PiShip runtime changed; launch and governance code differ.",
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
});
