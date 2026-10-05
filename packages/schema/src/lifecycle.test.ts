import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  DEFAULT_PACKAGE_SOURCES,
  DEFAULT_RELEASE_TARGETS,
  LATEST_SCHEMA,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  RELEASE_CHANNELS,
  RELEASE_TARGETS,
  SUPPORTED_SCHEMAS,
  migrateManifestSource,
  parseManifest,
  parseManifestHeader,
} from "./index.js";

type Json = Record<string, unknown>;

function ed25519Key(): string {
  return generateKeyPairSync("ed25519")
    .publicKey.export({ type: "spki", format: "der" })
    .toString("base64");
}
const KEY_A = ed25519Key();
const KEY_B = ed25519Key();

function personal(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA4,
    app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
    runtime: { pi: "1.0.3" },
    deployment: { mode: "personal" },
    updates: {},
    ...extra,
  };
}
function lifecycle(input: Json) {
  const manifest = parseManifest(input);
  if (!manifest.lifecycle) throw new Error("lifecycle missing");
  return manifest.lifecycle;
}
function rejects(input: Json, field: string, message?: string): void {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).kind).toBe("invalid field");
  expect((error as ManifestError).field).toBe(field);
  if (message) expect((error as ManifestError).message).toContain(message);
}
function updates(value: Json): Json {
  return personal({ updates: value });
}
function release(value: Json): Json {
  return personal({ release: value });
}

describe("piship/v1alpha4 schema", () => {
  it("is supported, latest, and reported by the header", () => {
    expect(SUPPORTED_SCHEMAS).toEqual([
      "piship/v1alpha1",
      "piship/v1alpha2",
      "piship/v1alpha3",
      "piship/v1alpha4",
      "piship/v1alpha5",
      "piship/v1alpha6",
    ]);
    expect(LATEST_SCHEMA).toBe("piship/v1alpha6");
    expect(parseManifestHeader(personal())).toEqual({
      schema: PISHIP_SCHEMA_V1ALPHA4,
    });
  });
  it("exports channel and target constants", () => {
    expect(RELEASE_CHANNELS).toEqual(["stable", "candidate", "dev"]);
    expect(RELEASE_TARGETS).toEqual([
      "linux-x64",
      "linux-arm64",
      "darwin-arm64",
      "darwin-x64",
      "win32-x64",
    ]);
    expect(DEFAULT_RELEASE_TARGETS).toEqual([
      "linux-x64",
      "darwin-arm64",
      "win32-x64",
    ]);
    expect(DEFAULT_PACKAGE_SOURCES).toEqual(["https://registry.npmjs.org"]);
  });
  it("applies defaults to a minimal updates section and omitted release", () => {
    const manifest = parseManifest(personal());
    expect(manifest.schema).toBe(PISHIP_SCHEMA_V1ALPHA4);
    expect(manifest.governance).toBeDefined();
    expect(manifest.access).toBeDefined();
    expect(manifest.lifecycle).toEqual({
      updates: {
        channel: "stable",
        channels: ["stable"],
        rollback: true,
        trust: { keys: [] },
      },
      release: {
        targets: ["linux-x64", "darwin-arm64", "win32-x64"],
        sources: ["https://registry.npmjs.org"],
        vulnerabilities: { failOn: "high", allow: [] },
      },
    });
    expect(manifest.lifecycle?.updates).not.toHaveProperty("source");
  });
  it("defaults channels to the chosen default channel", () => {
    expect(
      lifecycle(updates({ channel: "candidate" })).updates.channels,
    ).toEqual(["candidate"]);
  });
  it("accepts full updates and release sections", () => {
    const parsed = lifecycle(
      personal({
        variables: ["ACME_UPDATE_SOURCE"],
        updates: {
          channel: "stable",
          channels: ["stable", "candidate", "dev"],
          source: `\${ACME_UPDATE_SOURCE}`,
          rollback: false,
          trust: {
            keys: [
              { id: "acme-release-2026", publicKey: KEY_A },
              { id: "acme.backup.1", publicKey: KEY_B },
            ],
          },
        },
        release: {
          targets: ["linux-arm64", "darwin-x64"],
          sources: [
            "https://registry.npmjs.org/",
            "https://npm.acme.example:8443",
          ],
          vulnerabilities: {
            failOn: "moderate",
            allow: [
              {
                id: "GHSA-abcd-efgh-ijkl",
                reason: "not reachable from the packaged runtime",
                expires: "2026-12-31",
              },
              {
                id: "CVE-2026:1234.a_b",
                reason: "dev only",
                expires: "2028-02-29",
              },
            ],
          },
        },
      }),
    );
    expect(parsed).toEqual({
      updates: {
        channel: "stable",
        channels: ["stable", "candidate", "dev"],
        source: `\${ACME_UPDATE_SOURCE}`,
        rollback: false,
        trust: {
          keys: [
            { id: "acme-release-2026", publicKey: KEY_A },
            { id: "acme.backup.1", publicKey: KEY_B },
          ],
        },
      },
      release: {
        targets: ["linux-arm64", "darwin-x64"],
        sources: [
          "https://registry.npmjs.org",
          "https://npm.acme.example:8443",
        ],
        vulnerabilities: {
          failOn: "moderate",
          allow: [
            {
              id: "GHSA-abcd-efgh-ijkl",
              reason: "not reachable from the packaged runtime",
              expires: "2026-12-31",
            },
            {
              id: "CVE-2026:1234.a_b",
              reason: "dev only",
              expires: "2028-02-29",
            },
          ],
        },
      },
    });
  });
  it.each([
    "https://updates.acme.example/channels",
    "http://127.0.0.1:8080/updates",
    "http://localhost/updates",
    "http://[::1]:9000/",
  ])("accepts update source %s", (source) => {
    expect(lifecycle(updates({ source })).updates.source).toBe(source);
  });
  it("accepts a YAML document with an unquoted expiry date", () => {
    const source = [
      "schema: piship/v1alpha4",
      "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
      'runtime: { pi: "1.0.3" }',
      "deployment: { mode: personal }",
      "updates: {}",
      "release:",
      "  vulnerabilities:",
      "    allow:",
      "      - { id: GHSA-1, reason: reviewed, expires: 2026-12-31 }",
      "",
    ].join("\n");
    expect(
      lifecycle(parseYaml(source) as Json).release.vulnerabilities.allow[0]
        ?.expires,
    ).toBe("2026-12-31");
  });
});

describe("v1alpha4 section gating", () => {
  it("requires updates on v1alpha4", () => {
    const input = personal();
    delete input.updates;
    rejects(input, "updates", "requires an updates section");
  });
  it.each([
    [PISHIP_SCHEMA_V1ALPHA3, "updates"],
    [PISHIP_SCHEMA_V1ALPHA3, "release"],
    [PISHIP_SCHEMA_V1ALPHA2, "updates"],
    [PISHIP_SCHEMA_V1ALPHA2, "release"],
    ["piship/v1alpha1", "updates"],
    ["piship/v1alpha1", "release"],
  ])("%s rejects the %s section", (schema, key) => {
    rejects(
      {
        schema,
        app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
        runtime: { pi: "1.0.3" },
        deployment: { mode: "personal" },
        [key]: {},
      },
      `manifest.${key}`,
      "Unknown field",
    );
  });
  it("omits lifecycle for earlier schemas", () => {
    const input = personal({ schema: PISHIP_SCHEMA_V1ALPHA3 });
    delete input.updates;
    expect(parseManifest(input).lifecycle).toBeUndefined();
  });
  it("still applies v1alpha3 validation", () => {
    rejects(personal({ policy: { default: "maybe" } }), "policy.default");
    rejects(personal({ tools: {} }), "manifest.tools", "Unknown field");
  });
  it("lists v1alpha4 among the schemas that accept managed mode", () => {
    const input = personal({
      schema: "piship/v1alpha1",
      deployment: { mode: "managed" },
    });
    delete input.updates;
    rejects(input, "deployment.mode", "piship/v1alpha4");
  });
});

describe("v1alpha4 updates validation", () => {
  it.each<[Json, string, string]>([
    [{ extra: true }, "updates.extra", "Unknown field"],
    [{ token: "x" }, "updates.token", "Secrets are never declared"],
    [{ channel: "beta" }, "updates.channel", "stable, candidate, dev"],
    [{ channels: ["nightly"] }, "updates.channels[0]", "stable, candidate"],
    [{ channels: "stable" }, "updates.channels", "Expected a list"],
    [
      { channels: ["stable", "stable"] },
      "updates.channels",
      "Duplicate entries",
    ],
    [
      { channel: "dev", channels: ["stable", "candidate"] },
      "updates.channels",
      "default channel dev",
    ],
    [{ channels: [] }, "updates.channels", "default channel stable"],
    [{ rollback: "yes" }, "updates.rollback", "true or false"],
    [{ trust: { extra: [] } }, "updates.trust.extra", "Unknown field"],
    [{ trust: { keys: {} } }, "updates.trust.keys", "Expected a list"],
    [
      { trust: { keys: [{ id: "a", publicKey: KEY_A, name: "x" }] } },
      "updates.trust.keys[0].name",
      "Unknown field",
    ],
    [
      { trust: { keys: [{ id: "Acme", publicKey: KEY_A }] } },
      "updates.trust.keys[0].id",
      "lowercase",
    ],
    [
      { trust: { keys: [{ id: "-acme", publicKey: KEY_A }] } },
      "updates.trust.keys[0].id",
      "lowercase",
    ],
    [
      { trust: { keys: [{ id: "a".repeat(65), publicKey: KEY_A }] } },
      "updates.trust.keys[0].id",
      "at most 64",
    ],
    [
      {
        trust: {
          keys: [
            { id: "acme", publicKey: KEY_A },
            { id: "acme", publicKey: KEY_B },
          ],
        },
      },
      "updates.trust.keys[1].id",
      "Duplicate key id acme",
    ],
    [
      { trust: { keys: [{ id: "acme" }] } },
      "updates.trust.keys[0].publicKey",
      "non-empty string",
    ],
    [
      { trust: { keys: [{ id: "acme", publicKey: "not base64!" }] } },
      "updates.trust.keys[0].publicKey",
      "Ed25519",
    ],
    [
      {
        trust: {
          keys: [
            {
              id: "acme",
              publicKey: Buffer.alloc(44, 1).toString("base64"),
            },
          ],
        },
      },
      "updates.trust.keys[0].publicKey",
      "Ed25519",
    ],
    [
      {
        trust: {
          keys: [
            {
              id: "acme",
              publicKey: Buffer.from(KEY_A, "base64")
                .subarray(0, 43)
                .toString("base64"),
            },
          ],
        },
      },
      "updates.trust.keys[0].publicKey",
      "44 bytes",
    ],
    [
      {
        trust: {
          keys: [
            {
              id: "acme",
              publicKey: Buffer.concat([
                Buffer.from(KEY_A, "base64"),
                Buffer.alloc(1),
              ]).toString("base64"),
            },
          ],
        },
      },
      "updates.trust.keys[0].publicKey",
      "Ed25519",
    ],
    [
      {
        trust: {
          keys: [
            {
              id: "acme",
              publicKey: generateKeyPairSync("ec", { namedCurve: "P-256" })
                .publicKey.export({ type: "spki", format: "der" })
                .toString("base64"),
            },
          ],
        },
      },
      "updates.trust.keys[0].publicKey",
      "Ed25519",
    ],
    [{ source: "http://updates.acme.example/" }, "updates.source", "https"],
    [{ source: "http://127.0.0.2/" }, "updates.source", "https"],
    [{ source: "ftp://updates.acme.example/" }, "updates.source", "https"],
    [
      { source: "updates.acme.example" },
      "updates.source",
      `an https URL, an http URL on 127.0.0.1, localhost, or [::1], or a \${NAME} runtime reference`,
    ],
    [
      { source: "https://user:pw@updates.acme.example/" },
      "updates.source",
      "credentials",
    ],
    [
      { source: "https://updates.acme.example/?channel=x" },
      "updates.source",
      "query",
    ],
    [{ source: "" }, "updates.source", "non-empty string"],
    [
      { source: `\${ACME_UPDATE_SOURCE}` },
      "updates.source",
      "ACME_UPDATE_SOURCE is not declared",
    ],
    [{ source: `\${ACME_TOKEN}` }, "updates.source", "secret material"],
    [{ source: `\${lower}` }, "updates.source", "uppercase"],
    [{ source: "$ACME" }, "updates.source", "Malformed runtime reference"],
  ])("rejects updates %j at %s", (value, field, message) => {
    rejects(updates(value), field, message);
  });
  it("counts the update source as a variable reference", () => {
    expect(
      lifecycle(
        personal({
          variables: ["ACME_UPDATE_SOURCE"],
          updates: { source: `\${ACME_UPDATE_SOURCE}` },
        }),
      ).updates.source,
    ).toBe(`\${ACME_UPDATE_SOURCE}`);
    rejects(
      personal({ variables: ["ACME_UPDATE_SOURCE"] }),
      "variables[0]",
      "ACME_UPDATE_SOURCE is declared but not referenced",
    );
  });
});

describe("v1alpha4 release validation", () => {
  const allow = (entry: Json) => ({ vulnerabilities: { allow: [entry] } });
  const entry = { id: "GHSA-1", reason: "reviewed", expires: "2026-12-31" };
  it.each<[Json, string, string]>([
    [{ extra: true }, "release.extra", "Unknown field"],
    [{ targets: [] }, "release.targets", "at least one"],
    [{ targets: "linux-x64" }, "release.targets", "Expected a list"],
    [{ targets: ["linux-x86"] }, "release.targets[0]", "linux-x64"],
    [
      { targets: ["linux-x64", "linux-x64"] },
      "release.targets",
      "Duplicate entries",
    ],
    [{ sources: [] }, "release.sources", "at least one"],
    [{ sources: ["http://registry.npmjs.org"] }, "release.sources[0]", "https"],
    [
      { sources: ["https://registry.npmjs.org/npm"] },
      "release.sources[0]",
      "without a path",
    ],
    [
      { sources: ["https://registry.npmjs.org/?a=1"] },
      "release.sources[0]",
      "without a path",
    ],
    [
      { sources: ["https://registry.npmjs.org?"] },
      "release.sources[0]",
      "without a path",
    ],
    [
      { sources: ["https://registry.npmjs.org#top"] },
      "release.sources[0]",
      "without a path",
    ],
    [
      { sources: ["https://u:p@registry.npmjs.org"] },
      "release.sources[0]",
      "credentials",
    ],
    [{ sources: ["registry.npmjs.org"] }, "release.sources[0]", "https origin"],
    [
      {
        sources: ["https://registry.npmjs.org", "https://registry.npmjs.org/"],
      },
      "release.sources",
      "Duplicate entries",
    ],
    [
      { vulnerabilities: { extra: 1 } },
      "release.vulnerabilities.extra",
      "Unknown field",
    ],
    [
      { vulnerabilities: { failOn: "severe" } },
      "release.vulnerabilities.failOn",
      "low, moderate, high, critical",
    ],
    [
      { vulnerabilities: { allow: {} } },
      "release.vulnerabilities.allow",
      "Expected a list",
    ],
    [
      allow({ ...entry, owner: "x" }),
      "release.vulnerabilities.allow[0].owner",
      "Unknown field",
    ],
    [
      allow({ ...entry, id: "" }),
      "release.vulnerabilities.allow[0].id",
      "non-empty string",
    ],
    [
      allow({ ...entry, id: "GHSA 1" }),
      "release.vulnerabilities.allow[0].id",
      "Advisory ids",
    ],
    [
      allow({ ...entry, reason: undefined }),
      "release.vulnerabilities.allow[0].reason",
      "non-empty string",
    ],
    [
      allow({ ...entry, reason: "two\nlines" }),
      "release.vulnerabilities.allow[0].reason",
      "Control characters",
    ],
    [
      allow({ ...entry, expires: undefined }),
      "release.vulnerabilities.allow[0].expires",
      "YYYY-MM-DD",
    ],
    [
      allow({ ...entry, expires: "2026-1-31" }),
      "release.vulnerabilities.allow[0].expires",
      "YYYY-MM-DD",
    ],
    [
      allow({ ...entry, expires: "2026-02-30" }),
      "release.vulnerabilities.allow[0].expires",
      "valid calendar date",
    ],
    [
      allow({ ...entry, expires: "2026-13-01" }),
      "release.vulnerabilities.allow[0].expires",
      "valid calendar date",
    ],
    [
      { vulnerabilities: { allow: [entry, { ...entry, reason: "again" }] } },
      "release.vulnerabilities.allow[1].id",
      "Duplicate advisory id GHSA-1",
    ],
  ])("rejects release %j at %s", (value, field, message) => {
    rejects(release(value), field, message);
  });
});

describe("migration to piship/v1alpha4", () => {
  const v3 = [
    "schema: piship/v1alpha3",
    "# keep comments",
    "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
    'runtime: { pi: "1.0.3" }',
    "deployment: { mode: personal }",
    "",
  ].join("\n");
  const changes = [
    "schema: piship/v1alpha3 -> piship/v1alpha4",
    "updates.channel: stable, updates.channels: [stable], updates.rollback: true",
    "Updates stay disabled until updates.trust.keys and updates.source are configured",
    "release defaults apply: targets linux-x64, darwin-arm64, win32-x64; package sources https://registry.npmjs.org; vulnerabilities.failOn high",
    "Regenerate piship.lock with piship lock, then rebuild",
  ];
  it("migrates v1alpha3 to v1alpha4", () => {
    const plan = migrateManifestSource(v3, PISHIP_SCHEMA_V1ALPHA4);
    expect(plan.from).toBe(PISHIP_SCHEMA_V1ALPHA3);
    expect(plan.to).toBe(PISHIP_SCHEMA_V1ALPHA4);
    expect(plan.changes).toEqual(changes);
    expect(plan.source).toContain("# keep comments");
    const manifest = parseManifest(parseYaml(plan.source) as Json);
    expect(manifest.schema).toBe(PISHIP_SCHEMA_V1ALPHA4);
    expect(manifest.lifecycle?.updates).toEqual({
      channel: "stable",
      channels: ["stable"],
      rollback: true,
      trust: { keys: [] },
    });
    expect(manifest.lifecycle?.release.targets).toEqual(
      DEFAULT_RELEASE_TARGETS,
    );
    expect(migrateManifestSource(plan.source, PISHIP_SCHEMA_V1ALPHA4)).toEqual({
      from: PISHIP_SCHEMA_V1ALPHA4,
      to: PISHIP_SCHEMA_V1ALPHA4,
      changes: [],
      effective: [],
      source: plan.source,
    });
  });
  it("migrates v1alpha1 to v1alpha4 in steps", () => {
    const v1 =
      'schema: piship/v1alpha1\n# keep comments\napp:\n  id: mypi\n  name: MyPi\n  command: mypi\n  version: 1.0.0\nruntime:\n  pi: "1.0.3"\ndeployment:\n  mode: personal\nresources:\n  skills:\n    - ./skills\n';
    const plan = migrateManifestSource(v1, PISHIP_SCHEMA_V1ALPHA4);
    expect(plan.from).toBe("piship/v1alpha1");
    expect(plan.to).toBe(PISHIP_SCHEMA_V1ALPHA4);
    expect(plan.changes[0]).toBe("schema: piship/v1alpha1 -> piship/v1alpha2");
    const schemaSteps = plan.changes.filter((change) =>
      change.startsWith("schema: "),
    );
    expect(schemaSteps).toEqual([
      "schema: piship/v1alpha1 -> piship/v1alpha2",
      "schema: piship/v1alpha2 -> piship/v1alpha3",
      "schema: piship/v1alpha3 -> piship/v1alpha4",
    ]);
    expect(plan.changes.slice(-5)).toEqual(changes);
    expect(plan.source).toContain("# keep comments");
    const manifest = parseManifest(parseYaml(plan.source) as Json);
    expect(manifest.schema).toBe(PISHIP_SCHEMA_V1ALPHA4);
    expect(manifest.resources.skills).toEqual(["./skills"]);
    expect(manifest.lifecycle?.updates.channel).toBe("stable");
  });
  it("stops at earlier targets and refuses downgrades", () => {
    expect(migrateManifestSource(v3, PISHIP_SCHEMA_V1ALPHA3).changes).toEqual(
      [],
    );
    const v4 = migrateManifestSource(v3, PISHIP_SCHEMA_V1ALPHA4).source;
    expect(() => migrateManifestSource(v4, PISHIP_SCHEMA_V1ALPHA3)).toThrow(
      "downgrades are not supported",
    );
  });
});
