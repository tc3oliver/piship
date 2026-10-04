import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  AccessFieldError,
  ManifestError,
  MIGRATED_BOOTSTRAP_EXPIRES,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  channelTrustKeys,
  launchWarnings,
  migrateManifestSource,
  parseManifest,
  parseUpdateRoot,
  sharedRoleKeyIds,
  updateRoleKeys,
  type UpdateRoot,
} from "./index.js";

type Json = Record<string, unknown>;

function ed25519Key(): string {
  return generateKeyPairSync("ed25519")
    .publicKey.export({ type: "spki", format: "der" })
    .toString("base64");
}
const ROOT_A = ed25519Key();
const ROOT_B = ed25519Key();
const CHANNEL = ed25519Key();

function bootstrap(extra: Json = {}): Json {
  return {
    version: 1,
    expires: "2027-10-01T00:00:00Z",
    keys: [
      { id: "root-a", publicKey: ROOT_A },
      { id: "root-b", publicKey: ROOT_B },
      { id: "channel-a", publicKey: CHANNEL },
    ],
    roles: {
      root: { keyIds: ["root-a", "root-b"], threshold: 1 },
      channel: { keyIds: ["channel-a"], threshold: 1 },
    },
    ...extra,
  };
}
function manifest(
  updates: Json,
  mode: "personal" | "managed" = "personal",
): Json {
  const base: Json = {
    schema: PISHIP_SCHEMA_V1ALPHA5,
    app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
    runtime: { pi: "1.0.2" },
    deployment: { mode: "personal" },
    updates,
  };
  if (mode === "personal") return base;
  return {
    ...base,
    deployment: { mode: "managed" },
    identity: {
      mode: "oidc",
      oidc: {
        issuer: "https://login.acme.example",
        clientId: "acmecode",
        redirectUri: "http://127.0.0.1:8765/callback",
      },
    },
    credential: {
      provider: "http-broker",
      broker: { endpoint: "https://broker.acme.example/token" },
    },
    inference: {
      provider: "openai-compatible",
      baseUrl: "https://gateway.acme.example/v1",
    },
    models: {
      default: "acme/coder",
      allowed: ["acme/coder"],
      catalog: {
        "acme/coder": {
          name: "Acme Coder",
          contextWindow: 128000,
          maxOutputTokens: 8192,
        },
      },
    },
  };
}
function withTrust(value: Json, extra: Json = {}): Json {
  return manifest({ ...extra, trust: { bootstrap: value } });
}
function rejects(input: Json, field: string, message: string): void {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).field).toBe(field);
  expect((error as ManifestError).message).toContain(message);
}
const roles = (root: Json, channel: Json) => ({ roles: { root, channel } });

describe("piship/v1alpha5 update trust bootstrap", () => {
  it("parses a bootstrap root exactly", () => {
    const parsed = parseManifest(withTrust(bootstrap()));
    expect(parsed.schema).toBe(PISHIP_SCHEMA_V1ALPHA5);
    expect(parsed.lifecycle?.updates.trust).toEqual({ bootstrap: bootstrap() });
  });
  it("is update-disabled without trust or source", () => {
    const parsed = parseManifest(manifest({}));
    expect(parsed.lifecycle?.updates.trust).toEqual({});
    expect(channelTrustKeys(parsed.lifecycle?.updates)).toEqual([]);
    expect(launchWarnings(parsed)).toEqual([]);
  });
  it("derives channel and root keys from roles", () => {
    const updates = parseManifest(withTrust(bootstrap())).lifecycle?.updates;
    expect(channelTrustKeys(updates)).toEqual([
      { id: "channel-a", publicKey: CHANNEL },
    ]);
    const root = (updates?.trust as { bootstrap: UpdateRoot } | undefined)
      ?.bootstrap as UpdateRoot;
    expect(updateRoleKeys(root, "root").map((key) => key.id)).toEqual([
      "root-a",
      "root-b",
    ]);
    expect(sharedRoleKeyIds(root)).toEqual([]);
  });
  it("keeps v1alpha4 keys as the channel trust of a v1alpha4 manifest", () => {
    const keys = [{ id: "release", publicKey: CHANNEL }];
    expect(channelTrustKeys({ ...updatesOf(keys) })).toEqual(keys);
  });
  it.each<[Json, string, string]>([
    [
      roles(
        { keyIds: ["root-a", "missing"], threshold: 1 },
        {
          keyIds: ["channel-a"],
          threshold: 1,
        },
      ),
      "updates.trust.bootstrap.roles.root.keyIds[1]",
      "Key id missing is not listed in keys",
    ],
    [
      roles(
        { keyIds: ["root-a"], threshold: 1 },
        {
          keyIds: ["nope"],
          threshold: 1,
        },
      ),
      "updates.trust.bootstrap.roles.channel.keyIds[0]",
      "not listed in keys",
    ],
    [
      roles(
        { keyIds: ["root-a", "root-b"], threshold: 3 },
        {
          keyIds: ["channel-a"],
          threshold: 1,
        },
      ),
      "updates.trust.bootstrap.roles.root.threshold",
      "Expected an integer from 1 to 2",
    ],
    [
      roles(
        { keyIds: ["root-a"], threshold: 0 },
        {
          keyIds: ["channel-a"],
          threshold: 1,
        },
      ),
      "updates.trust.bootstrap.roles.root.threshold",
      "from 1 to 1",
    ],
    [
      roles(
        { keyIds: ["root-a"], threshold: 1 },
        {
          keyIds: ["channel-a"],
          threshold: 1.5,
        },
      ),
      "updates.trust.bootstrap.roles.channel.threshold",
      "Expected an integer",
    ],
    [
      roles(
        { keyIds: ["root-a"], threshold: 1 },
        {
          keyIds: ["channel-a"],
          threshold: "1",
        },
      ),
      "updates.trust.bootstrap.roles.channel.threshold",
      "Expected an integer",
    ],
    [
      roles(
        { keyIds: [], threshold: 1 },
        {
          keyIds: ["channel-a"],
          threshold: 1,
        },
      ),
      "updates.trust.bootstrap.roles.root.keyIds",
      "at least one key id",
    ],
    [
      roles(
        { keyIds: ["root-a", "root-a"], threshold: 1 },
        {
          keyIds: ["channel-a"],
          threshold: 1,
        },
      ),
      "updates.trust.bootstrap.roles.root.keyIds",
      "Duplicate entries",
    ],
    [
      { roles: { root: { keyIds: ["root-a"], threshold: 1 } } },
      "updates.trust.bootstrap.roles.channel",
      "Expected an object",
    ],
    [
      {
        roles: {
          ...(bootstrap().roles as Json),
          admin: { keyIds: ["root-a"], threshold: 1 },
        },
      },
      "updates.trust.bootstrap.roles.admin",
      "Unknown field",
    ],
    [
      {
        keys: [
          { id: "root-a", publicKey: ROOT_A },
          { id: "root-a", publicKey: ROOT_A },
        ],
      },
      "updates.trust.bootstrap.keys[1].id",
      "Duplicate key id root-a",
    ],
    [
      {
        keys: [
          { id: "root-a", publicKey: ROOT_A },
          { id: "root-a", publicKey: ROOT_B },
        ],
      },
      "updates.trust.bootstrap.keys[1].id",
      "one id cannot name two different public keys",
    ],
    [
      {
        keys: [
          { id: "root-a", publicKey: ROOT_A },
          { id: "root-b", publicKey: ROOT_A },
          { id: "channel-a", publicKey: CHANNEL },
        ],
      },
      "updates.trust.bootstrap.keys[1].publicKey",
      "already listed as root-a",
    ],
    [{ keys: [] }, "updates.trust.bootstrap.keys", "at least one key"],
    [
      { keys: [{ id: "Root", publicKey: ROOT_A }] },
      "updates.trust.bootstrap.keys[0].id",
      "Key ids use lowercase letters",
    ],
    [
      { keys: [{ id: "root-a", publicKey: "not-a-key" }] },
      "updates.trust.bootstrap.keys[0].publicKey",
      "Ed25519 public key",
    ],
    [
      { keys: [{ id: "root-a", publicKey: ROOT_A, privateKey: "x" }] },
      "updates.trust.bootstrap.keys[0].privateKey",
      "Secrets are never declared",
    ],
    [{ version: 0 }, "updates.trust.bootstrap.version", "at least 1"],
    [{ version: "1" }, "updates.trust.bootstrap.version", "at least 1"],
    [{ expires: "2027-10-01" }, "updates.trust.bootstrap.expires", "UTC"],
    [
      { expires: "2027-02-30T00:00:00Z" },
      "updates.trust.bootstrap.expires",
      "valid UTC timestamp",
    ],
    [
      { expires: "2027-10-01T00:00:00+02:00" },
      "updates.trust.bootstrap.expires",
      "UTC timestamp",
    ],
    [{ extra: 1 }, "updates.trust.bootstrap.extra", "Unknown field"],
  ])("rejects bootstrap %j at %s", (extra, field, message) => {
    rejects(withTrust(bootstrap(extra)), field, message);
  });
  it("rejects v1alpha4 trust keys and names the replacement", () => {
    rejects(
      manifest({ trust: { keys: [] } }),
      "updates.trust.keys",
      "replaces updates.trust.keys with updates.trust.bootstrap",
    );
  });
  it("rejects a bootstrap on a v1alpha4 manifest", () => {
    rejects(
      {
        ...manifest({ trust: { bootstrap: bootstrap() } }),
        schema: PISHIP_SCHEMA_V1ALPHA4,
      },
      "updates.trust.bootstrap",
      "Unknown field",
    );
  });
  it("accepts thresholds up to the role key count", () => {
    const parsed = parseManifest(
      withTrust(
        bootstrap(
          roles(
            { keyIds: ["root-a", "root-b"], threshold: 2 },
            {
              keyIds: ["channel-a"],
              threshold: 1,
            },
          ),
        ),
      ),
    );
    const trust = parsed.lifecycle?.updates.trust as { bootstrap: UpdateRoot };
    expect(trust.bootstrap.roles.root.threshold).toBe(2);
  });
  it("warns when an update source has no bootstrap trust (fails closed)", () => {
    const parsed = parseManifest(
      manifest({ source: "https://updates.acme.example" }),
    );
    expect(channelTrustKeys(parsed.lifecycle?.updates)).toEqual([]);
    expect(launchWarnings(parsed)).toEqual([
      expect.objectContaining({
        path: "updates.trust.bootstrap",
        message: expect.stringContaining("update fails closed"),
      }),
    ]);
  });
  const shared = bootstrap(
    roles(
      { keyIds: ["root-a", "channel-a"], threshold: 1 },
      {
        keyIds: ["channel-a"],
        threshold: 1,
      },
    ),
  );
  it("warns a managed distribution whose roles share a key", () => {
    const parsed = parseManifest(
      manifest({ trust: { bootstrap: shared } }, "managed"),
    );
    expect(launchWarnings(parsed)).toContainEqual({
      path: "updates.trust.bootstrap.roles",
      message: expect.stringContaining("share channel-a"),
    });
  });
  it("does not warn a personal distribution whose roles share a key", () => {
    const parsed = parseManifest(manifest({ trust: { bootstrap: shared } }));
    expect(launchWarnings(parsed)).toEqual([]);
  });
  it("validates hosted root metadata bodies with caller-owned fields", () => {
    const hosted = {
      schema: "piship-update-root/v1",
      distribution: "acmecode",
      ...bootstrap({ version: 2 }),
    };
    expect(() => parseUpdateRoot(hosted, "root")).toThrow(AccessFieldError);
    expect(parseUpdateRoot(hosted, "root", ["schema", "distribution"])).toEqual(
      bootstrap({ version: 2 }),
    );
  });
});

function updatesOf(keys: { id: string; publicKey: string }[]) {
  return {
    channel: "stable" as const,
    channels: ["stable" as const],
    rollback: true,
    trust: { keys },
  };
}

describe("migration piship/v1alpha4 -> piship/v1alpha5", () => {
  const v4 = (trust: string, mode = "personal", extra = "") =>
    [
      "schema: piship/v1alpha4",
      "# keep comments",
      "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
      'runtime: { pi: "1.0.2" }',
      `deployment: { mode: ${mode} }`,
      extra,
      "updates:",
      "  channel: stable",
      "  rollback: true",
      trust,
      "",
    ].join("\n");
  const legacy = [
    "  trust:",
    "    keys:",
    "      # the 2026 release key",
    "      - id: release-2026",
    `        publicKey: ${ROOT_A}`,
    "      - id: release-2027",
    `        publicKey: ${ROOT_B}`,
  ].join("\n");
  it("keeps legacy keys as a compatibility trust set in both roles", () => {
    const plan = migrateManifestSource(v4(legacy), PISHIP_SCHEMA_V1ALPHA5);
    expect(plan.from).toBe(PISHIP_SCHEMA_V1ALPHA4);
    expect(plan.to).toBe(PISHIP_SCHEMA_V1ALPHA5);
    expect(plan.source).toContain("# keep comments");
    expect(plan.source).toContain("# the 2026 release key");
    const parsed = parseManifest(parseYaml(plan.source) as Json);
    const keys = [
      { id: "release-2026", publicKey: ROOT_A },
      { id: "release-2027", publicKey: ROOT_B },
    ];
    const ids = ["release-2026", "release-2027"];
    expect(parsed.lifecycle?.updates.trust).toEqual({
      bootstrap: {
        version: 1,
        expires: MIGRATED_BOOTSTRAP_EXPIRES,
        keys,
        roles: {
          root: { keyIds: ids, threshold: 1 },
          channel: { keyIds: ids, threshold: 1 },
        },
      },
    });
    // The same keys sign channels as before: trust is not strengthened.
    expect(channelTrustKeys(parsed.lifecycle?.updates)).toEqual(keys);
    expect(plan.changes[0]).toBe("schema: piship/v1alpha4 -> piship/v1alpha5");
    expect(plan.changes.join("\n")).toContain("compatibility trust set");
  });
  it("does not silently turn legacy trust into a managed root/channel split", () => {
    const header = [
      "identity:",
      "  mode: oidc",
      "  oidc:",
      "    issuer: https://login.acme.example",
      "    clientId: acmecode",
      "    redirectUri: http://127.0.0.1:8765/callback",
      "credential:",
      "  provider: http-broker",
      "  broker: { endpoint: https://broker.acme.example/token }",
      "inference:",
      "  provider: openai-compatible",
      "  baseUrl: https://gateway.acme.example/v1",
      "models:",
      "  default: acme/coder",
      "  allowed: [acme/coder]",
      "  catalog:",
      "    acme/coder: { name: Acme Coder, contextWindow: 128000, maxOutputTokens: 8192 }",
    ].join("\n");
    const plan = migrateManifestSource(
      v4(legacy, "managed", header),
      PISHIP_SCHEMA_V1ALPHA5,
    );
    expect(plan.changes.join("\n")).toContain(
      "Managed rollout requires an explicit root / channel split",
    );
    const parsed = parseManifest(parseYaml(plan.source) as Json);
    expect(launchWarnings(parsed)).toContainEqual({
      path: "updates.trust.bootstrap.roles",
      message: expect.stringContaining("share release-2026, release-2027"),
    });
  });
  it("keeps an update-disabled distribution update-disabled", () => {
    for (const trust of ["  trust:\n    keys: []", "  trust: {}", ""]) {
      const plan = migrateManifestSource(v4(trust), PISHIP_SCHEMA_V1ALPHA5);
      const parsed = parseManifest(parseYaml(plan.source) as Json);
      expect(parsed.lifecycle?.updates.trust).toEqual({});
      expect(plan.source).not.toContain("bootstrap");
      expect(plan.source).not.toContain("publicKey");
      expect(plan.changes.join("\n")).toContain("updates stay disabled");
    }
  });
  it("keeps a source without keys, which still fails closed", () => {
    const plan = migrateManifestSource(
      v4("  source: https://updates.acme.example\n  trust:\n    keys: []"),
      PISHIP_SCHEMA_V1ALPHA5,
    );
    const parsed = parseManifest(parseYaml(plan.source) as Json);
    expect(parsed.lifecycle?.updates.source).toBe(
      "https://updates.acme.example",
    );
    expect(channelTrustKeys(parsed.lifecycle?.updates)).toEqual([]);
    expect(plan.changes.join("\n")).toContain("update fails closed");
  });
  it("is deterministic and idempotent", () => {
    const first = migrateManifestSource(v4(legacy), PISHIP_SCHEMA_V1ALPHA5);
    expect(migrateManifestSource(v4(legacy), PISHIP_SCHEMA_V1ALPHA5)).toEqual(
      first,
    );
    expect(migrateManifestSource(first.source, PISHIP_SCHEMA_V1ALPHA5)).toEqual(
      {
        from: PISHIP_SCHEMA_V1ALPHA5,
        to: PISHIP_SCHEMA_V1ALPHA5,
        changes: [],
        effective: [],
        source: first.source,
      },
    );
  });
  it("migrates v1alpha3 through v1alpha4 to an update-disabled v1alpha5", () => {
    const plan = migrateManifestSource(
      [
        "schema: piship/v1alpha3",
        "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
        'runtime: { pi: "1.0.2" }',
        "deployment: { mode: personal }",
        "",
      ].join("\n"),
      PISHIP_SCHEMA_V1ALPHA5,
    );
    expect(
      plan.changes.filter((change) => change.startsWith("schema: ")),
    ).toEqual([
      "schema: piship/v1alpha3 -> piship/v1alpha4",
      "schema: piship/v1alpha4 -> piship/v1alpha5",
    ]);
    const parsed = parseManifest(parseYaml(plan.source) as Json);
    expect(parsed.lifecycle?.updates.trust).toEqual({});
  });
});
