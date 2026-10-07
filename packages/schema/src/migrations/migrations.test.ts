import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  LATEST_SCHEMA,
  MANIFEST_MIGRATIONS,
  type Manifest,
  checkManifestMigration,
  manifestMigration,
  migrateManifestSource,
  migrationPath,
  PISHIP_SCHEMA_V1,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
  releaseOptions,
  SUPPORTED_SCHEMAS,
} from "../index.js";

const fixture = (name: string) =>
  new URL(`./fixtures/${name}`, import.meta.url);
/** Fixture text with LF endings, whatever the checkout converted them to. */
const read = (name: string) =>
  readFileSync(fixture(name), "utf8").replace(/\r\n/g, "\n");
const stepName = (from: string, to: string) =>
  `${from.split("/")[1]}-${to.split("/")[1]}`;
const parse = (source: string): Manifest =>
  parseManifest(parseYaml(source) as unknown);

describe("manifest migration registry", () => {
  it("has exactly one step for each consecutive pair of schemas", () => {
    expect(MANIFEST_MIGRATIONS.map((step) => [step.from, step.to])).toEqual(
      SUPPORTED_SCHEMAS.slice(0, -1).map((from, index) => [
        from,
        SUPPORTED_SCHEMAS[index + 1],
      ]),
    );
    expect(MANIFEST_MIGRATIONS.at(-1)?.to).toBe(LATEST_SCHEMA);
  });

  it("chains the steps between two schemas in order", () => {
    expect(
      migrationPath("piship/v1alpha3", PISHIP_SCHEMA_V1).map((step) => step.to),
    ).toEqual([
      "piship/v1alpha4",
      PISHIP_SCHEMA_V1ALPHA5,
      PISHIP_SCHEMA_V1ALPHA6,
      PISHIP_SCHEMA_V1,
    ]);
    expect(migrationPath(PISHIP_SCHEMA_V1, PISHIP_SCHEMA_V1)).toEqual([]);
    expect(
      manifestMigration(PISHIP_SCHEMA_V1ALPHA5, PISHIP_SCHEMA_V1ALPHA6)?.to,
    ).toBe(PISHIP_SCHEMA_V1ALPHA6);
    expect(
      manifestMigration(PISHIP_SCHEMA_V1ALPHA6, PISHIP_SCHEMA_V1)?.to,
    ).toBe(PISHIP_SCHEMA_V1);
    expect(
      manifestMigration("piship/v1alpha1", PISHIP_SCHEMA_V1),
    ).toBeUndefined();
  });

  for (const step of MANIFEST_MIGRATIONS) {
    const name = stepName(step.from, step.to);
    describe(`${step.from} -> ${step.to}`, () => {
      it("has an input and an expected fixture", () => {
        expect(existsSync(fixture(`${name}.input.yaml`))).toBe(true);
        expect(existsSync(fixture(`${name}.expected.yaml`))).toBe(true);
      });

      it("migrates the fixture exactly, keeping comments", () => {
        const input = read(`${name}.input.yaml`);
        expect(parse(input).schema).toBe(step.from);
        const plan = migrateManifestSource(input, step.to);
        expect(plan.from).toBe(step.from);
        expect(plan.to).toBe(step.to);
        expect(plan.source).toBe(read(`${name}.expected.yaml`));
        expect(parse(plan.source).schema).toBe(step.to);
        expect(plan.changes[0]).toBe(`schema: ${step.from} -> ${step.to}`);
        // Every effective change is also printed as a change.
        for (const line of plan.effective) expect(plan.changes).toContain(line);
      });

      it("is deterministic and idempotent", () => {
        const input = read(`${name}.input.yaml`);
        const plan = migrateManifestSource(input, step.to);
        expect(migrateManifestSource(input, step.to)).toEqual(plan);
        expect(migrateManifestSource(plan.source, step.to)).toEqual({
          from: step.to,
          to: step.to,
          changes: [],
          effective: [],
          review: [],
          source: plan.source,
        });
      });
    });
  }
});

describe("piship/v1alpha5 -> piship/v1alpha6", () => {
  const input = read("v1alpha5-v1alpha6.input.yaml");

  it("keeps every decision except the cache warming default", () => {
    const before = parse(input);
    const plan = migrateManifestSource(input, PISHIP_SCHEMA_V1ALPHA6);
    const after = parse(plan.source);
    expect(plan.to).toBe(PISHIP_SCHEMA_V1ALPHA6);
    // model.use is read as model.select in both schemas.
    expect(after.governance?.policy).toEqual({
      ...before.governance?.policy,
      acknowledgeUnenforced: [],
    });
    expect(after.governance?.policy.defaults[0]?.action).toBe("model.select");
    // The v1alpha5 filter becomes the exposure map: allowed tools direct,
    // denied tools hidden, and with an allowlist every other tool hidden.
    const exposures = Object.fromEntries(
      (after.governance?.mcp.servers ?? []).map((server) => [
        server.id,
        server.toolExposure,
      ]),
    );
    expect(exposures).toEqual({
      docs: [
        { pattern: "search", exposure: "direct" },
        { pattern: "get_document", exposure: "direct" },
        { pattern: "delete_document", exposure: "hidden" },
        { pattern: "*", exposure: "hidden" },
      ],
      issues: [{ pattern: "close_issue", exposure: "hidden" }],
      notes: [],
    });
    for (const server of after.governance?.mcp.servers ?? []) {
      expect(server.class).toBe("company");
      expect(server.exposure).toBe("direct");
    }
    // Absent cacheWarming is off now, and an absent release.bundle is on.
    expect(after.runtime.cacheWarming).toEqual({
      mode: "off",
      userOverride: false,
    });
    expect(plan.effective).toEqual([
      expect.stringContaining("runtime.cacheWarming"),
      expect.stringContaining("release.bundle and release.strip"),
    ]);
    // Absent data stays absent: no retention sweep.
    expect(after.data).toBeUndefined();
    expect(plan.changes).toContain(
      "data: absent, so no retention sweep runs (as in v0.8)",
    );
  });

  it("reports an MCP server that its new trust class would stop", () => {
    const narrowed = input.replace(
      "policy:\n",
      "policy:\n  resourceTrust: { company: deny }\n",
    );
    const plan = migrateManifestSource(narrowed, PISHIP_SCHEMA_V1ALPHA6);
    expect(plan.effective).toHaveLength(5);
    for (const id of ["docs", "issues", "notes"])
      expect(plan.effective).toContainEqual(
        expect.stringContaining(
          `mcp.servers.${id}.class: company is denied by policy.resourceTrust.company`,
        ),
      );
  });

  it("gives personal servers the user class", () => {
    const personal = [
      "schema: piship/v1alpha5",
      "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
      'runtime: { pi: "1.0.0" }',
      "deployment: { mode: personal }",
      "mcp:",
      "  servers:",
      "    docs: { transport: stdio, module: ./mcp/docs.mjs, tools: {} }",
      "updates: { channel: stable, channels: [stable] }",
      "",
    ].join("\n");
    const plan = migrateManifestSource(personal, PISHIP_SCHEMA_V1ALPHA6);
    const server = parse(plan.source).governance?.mcp.servers[0];
    expect(server?.class).toBe("user");
    expect(server?.tools).toEqual({ allow: [], deny: [] });
    expect(plan.changes).toContain(
      "mcp.servers.docs.tools: empty filter removed (every tool stays visible)",
    );
  });

  describe("MCP tool filters keep deny-wins", () => {
    const manifest = (tools: string) =>
      [
        "schema: piship/v1alpha5",
        "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
        'runtime: { pi: "1.0.0" }',
        "deployment: { mode: personal }",
        "mcp:",
        "  servers:",
        `    docs: { transport: stdio, module: ./mcp/docs.mjs, tools: ${tools} }`,
        "updates: { channel: stable, channels: [stable] }",
        "",
      ].join("\n");

    it("migrates a plain allow/deny filter to exact names, with no effective change", () => {
      const plan = migrateManifestSource(
        manifest("{ allow: [search, get_issue], deny: [delete_issue] }"),
        PISHIP_SCHEMA_V1ALPHA6,
      );
      expect(
        parse(plan.source).governance?.mcp.servers[0]?.toolExposure,
      ).toEqual([
        { pattern: "search", exposure: "direct" },
        { pattern: "get_issue", exposure: "direct" },
        { pattern: "delete_issue", exposure: "hidden" },
        { pattern: "*", exposure: "hidden" },
      ]);
      expect(plan.effective).toEqual([
        expect.stringContaining("runtime.cacheWarming"),
        expect.stringContaining("release.bundle and release.strip"),
      ]);
    });

    // A glob allow more specific than a deny glob, or two equally specific
    // ones, would resolve differently under most-specific-wins (or tie).
    // v1alpha5 never accepted globs in tool filters, so neither can reach
    // the migration.
    for (const [name, tools] of [
      [
        "allow more specific than deny",
        '{ allow: ["get_issue*"], deny: ["get_*"] }',
      ],
      ["equal-specificity tie", '{ allow: ["get_*"], deny: ["*_all"] }'],
    ] as const)
      it(`refuses a v1alpha5 filter with globs (${name})`, () => {
        expect(() =>
          migrateManifestSource(manifest(tools), PISHIP_SCHEMA_V1ALPHA6),
        ).toThrow(/Tool names use letters, digits, and _ \. -/);
      });
  });

  it("never rewrites a manifest that is already piship/v1alpha6", () => {
    const migrated = migrateManifestSource(
      input,
      PISHIP_SCHEMA_V1ALPHA6,
    ).source;
    expect(
      migrateManifestSource(migrated, PISHIP_SCHEMA_V1ALPHA6).changes,
    ).toEqual([]);
  });
});

describe("piship/v1alpha6 -> piship/v1", () => {
  const input = read("v1alpha6-v1.input.yaml");

  it("changes the schema id and nothing else", () => {
    const plan = migrateManifestSource(input);
    expect(plan.to).toBe(PISHIP_SCHEMA_V1);
    expect(plan.effective).toEqual([]);
    expect(plan.review).toEqual([]);
    const before = parse(input);
    const after = parse(plan.source);
    expect({ ...after, schema: before.schema }).toEqual(before);
    expect(plan.source).toBe(
      input.replace("schema: piship/v1alpha6", "schema: piship/v1"),
    );
  });

  it("keeps the v1alpha6 defaults: release.bundle and release.strip stay on", () => {
    const bare = [
      "schema: piship/v1alpha6",
      "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
      'runtime: { pi: "1.0.3" }',
      "deployment: { mode: personal }",
      "updates: { channel: stable, channels: [stable] }",
      "",
    ].join("\n");
    const before = parse(bare);
    const after = parse(migrateManifestSource(bare).source);
    for (const manifest of [before, after])
      expect(
        releaseOptions(manifest.schema, manifest.lifecycle?.release),
      ).toEqual({ bundle: true, strip: true });
  });

  it("chains from v1alpha5 and flags the placeholder an earlier step wrote", () => {
    const plan = migrateManifestSource(read("v1alpha4-v1alpha5.expected.yaml"));
    expect(plan.to).toBe(PISHIP_SCHEMA_V1);
    expect(plan.review).toEqual([
      expect.stringContaining("updates.trust.bootstrap.expires"),
    ]);
    expect(plan.source).toContain("expires: 2027-10-01T00:00:00Z");
  });

  it("never rewrites a manifest that is already piship/v1", () => {
    const migrated = migrateManifestSource(input).source;
    expect(migrateManifestSource(migrated).changes).toEqual([]);
  });
});

describe("migration verdicts", () => {
  const verdict = (name: string) =>
    checkManifestMigration(read(`verdicts/${name}.yaml`));

  it("migratable: nothing changes a decision and nothing needs an owner", () => {
    const check = verdict("migratable");
    expect(check).toMatchObject({
      verdict: "migratable",
      from: "piship/v1alpha6",
      to: PISHIP_SCHEMA_V1,
      review: [],
    });
    expect(check.changes[0]).toBe("schema: piship/v1alpha6 -> piship/v1");
  });

  it("requires review: an earlier migration's placeholder is not silently accepted", () => {
    const check = verdict("requires-review");
    expect(check.verdict).toBe("requires review");
    expect(check.review).toEqual([
      expect.stringContaining("updates.trust.bootstrap.expires"),
    ]);
    // The placeholder is reported, never rewritten.
    expect(
      migrateManifestSource(read("verdicts/requires-review.yaml")).source,
    ).toContain("expires: 2027-10-01T00:00:00Z");
  });

  it("requires review: a managed bootstrap whose roles share a key", () => {
    const check = verdict("requires-review-shared-roles");
    expect(check.verdict).toBe("requires review");
    expect(check.review.join("\n")).toContain("share release-2026");
  });

  it("requires review: older schemas report their effective changes", () => {
    const check = checkManifestMigration(read("v1alpha5-v1alpha6.input.yaml"));
    expect(check.verdict).toBe("requires review");
    expect(check.review).toEqual(
      expect.arrayContaining([
        expect.stringContaining("runtime.cacheWarming"),
        expect.stringContaining("release.bundle and release.strip"),
      ]),
    );
  });

  for (const [name, reason] of [
    ["cannot-migrate-invalid", /runtime\.pi/],
    [
      "cannot-migrate-future-schema",
      /Unsupported schema piship\/v2; the current schema is piship\/v1/,
    ],
    ["cannot-migrate-tool-glob", /Tool names use letters/],
  ] as const)
    it(`cannot migrate: ${name}`, () => {
      const check = verdict(name);
      expect(check.verdict).toBe("cannot migrate");
      expect(check.reason).toMatch(reason);
      expect(check.changes).toEqual([]);
    });

  it("cannot migrate: a document that is not YAML", () => {
    expect(checkManifestMigration("schema: [").verdict).toBe("cannot migrate");
  });

  it("never touches the text it checks", () => {
    const source = read("verdicts/requires-review.yaml");
    const copy = `${source}`;
    checkManifestMigration(source);
    expect(source).toBe(copy);
  });
});
