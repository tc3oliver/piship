import { describe, expect, it } from "vitest";
import {
  PISHIP_SCHEMA_V1ALPHA2,
  migrateManifestSource,
  parseManifest,
  resolveTemplate,
} from "./index.js";

const app = {
  id: "acmecode",
  name: "AcmeCode",
  command: "acmecode",
  version: "1.0.0",
};
const catalog = {
  "acme/coder": {
    name: "Acme Coder",
    contextWindow: 128000,
    maxOutputTokens: 8192,
    tools: true,
    policyTags: ["code"],
  },
  "acme/general": {
    name: "Acme General",
    contextWindow: 64000,
    maxOutputTokens: 4096,
  },
};
const managed = {
  schema: PISHIP_SCHEMA_V1ALPHA2,
  app,
  runtime: { pi: "1.0.0" },
  deployment: { mode: "managed" },
  variables: [
    "ACME_ISSUER",
    "ACME_CLIENT_ID",
    "ACME_BROKER_URL",
    "ACME_GATEWAY_URL",
  ],
  identity: {
    mode: "oidc",
    oidc: {
      issuer: `\${ACME_ISSUER}`,
      clientId: `\${ACME_CLIENT_ID}`,
      flow: "authorization_code_pkce",
      redirectUri: "http://127.0.0.1:8765/callback",
    },
  },
  credential: {
    provider: "http-broker",
    broker: { endpoint: `\${ACME_BROKER_URL}` },
    refresh: { beforeExpiry: "10m" },
  },
  inference: { provider: "openai-compatible", baseUrl: `\${ACME_GATEWAY_URL}` },
  models: {
    default: "acme/coder",
    allowed: ["acme/coder", "acme/general"],
    catalog,
  },
};
type Json = Record<string, unknown>;
const personal = (extra: Json) => ({
  schema: PISHIP_SCHEMA_V1ALPHA2,
  app: { ...app, id: "mypi", command: "mypi" },
  runtime: { pi: "1.0.0" },
  deployment: { mode: "personal" },
  ...extra,
});
function patch(base: Json, path: string, value: unknown): Json {
  const clone = structuredClone(base);
  const keys = path.split(".");
  let target = clone as Json;
  for (const key of keys.slice(0, -1)) target = target[key] as Json;
  const last = keys.at(-1) as string;
  if (value === undefined) delete target[last];
  else target[last] = value;
  return clone;
}

describe("piship/v1alpha2 managed manifest", () => {
  it("accepts the managed profile and keeps runtime references unresolved", () => {
    const manifest = parseManifest(managed);
    expect(manifest.deployment.mode).toBe("managed");
    expect(manifest.access?.identity).toMatchObject({
      mode: "oidc",
      oidc: {
        issuer: `\${ACME_ISSUER}`,
        scopes: ["openid", "profile", "email"],
      },
    });
    expect(manifest.access?.credential).toMatchObject({
      provider: "http-broker",
      storage: { provider: "system", acknowledgePlaintext: false },
      refresh: { beforeExpirySeconds: 600 },
    });
    expect(manifest.access?.network.publicFallback).toBe("deny");
    expect(manifest.access?.config.userOverridable).toEqual([
      "model",
      "theme",
      "thinkingLevel",
    ]);
    expect(manifest.access?.models.catalog.map((item) => item.id)).toEqual([
      "acme/coder",
      "acme/general",
    ]);
  });

  it.each([
    ["identity", undefined, "Managed mode requires identity"],
    ["identity", { mode: "none" }, "Managed mode requires oidc or adapter"],
    ["identity.oidc.clientSecret", "shh", "embedded client secret"],
    ["identity.oidc.flow", "device_code", "authorization_code_pkce"],
    [
      "identity.oidc.redirectUri",
      "https://app.example/callback",
      "loopback redirect",
    ],
    ["identity.oidc.scopes", ["profile"], "openid scope"],
    ["credential.provider", "local-secret", "organization-issued credential"],
    ["credential.provider", "pi-native", "organization-issued credential"],
    ["credential.apiKey", "sk-embedded", "Secrets are never declared"],
    ["credential.storage", { provider: "file" }, "acknowledgePlaintext"],
    ["inference.provider", "pi-native", "explicit openai-compatible gateway"],
    ["inference.baseUrl", "http://gateway.example/v1", "Use https"],
    [
      "inference.baseUrl",
      "https://user:pw@gateway.example/v1",
      "must not embed credentials",
    ],
    ["models.default", undefined, "requires a default model"],
    ["models.default", "acme/other", "not in models.allowed"],
    [
      "models.allowed",
      ["acme/coder", "acme/missing"],
      "no models.catalog metadata",
    ],
    ["network", { publicFallback: "allow" }, "never falls back"],
    [
      "network",
      { tls: { rejectUnauthorized: false } },
      "TLS verification cannot be disabled",
    ],
    [
      "config",
      { enforced: { model: "acme/general" } },
      "enforced model must equal models.default",
    ],
    [
      "config",
      { enforced: { theme: "dark" }, userOverridable: ["theme"] },
      "enforced and cannot also be user-overridable",
    ],
    [
      "config",
      { userOverridable: ["inference.baseUrl"] },
      "security-sensitive",
    ],
    ["config", { defaults: { model: "acme/coder" } }, "Use models.default"],
  ])("rejects %s = %j", (path, value, message) => {
    expect(() => parseManifest(patch(managed, path, value))).toThrow(message);
  });

  it("allowlists runtime references by field and variable", () => {
    expect(() =>
      parseManifest(patch(managed, "app.name", `\${ACME_ISSUER}`)),
    ).toThrow("app.name");
    expect(() =>
      parseManifest(
        patch(managed, "identity.oidc.redirectUri", `\${ACME_ISSUER}`),
      ),
    ).toThrow("not allowed in this field");
    expect(() =>
      parseManifest(
        patch(managed, "variables", [
          "ACME_CLIENT_ID",
          "ACME_BROKER_URL",
          "ACME_GATEWAY_URL",
        ]),
      ),
    ).toThrow("ACME_ISSUER is not declared");
    expect(() =>
      parseManifest(
        patch(managed, "variables", [...managed.variables, "ACME_UNUSED"]),
      ),
    ).toThrow("declared but not referenced");
    expect(() =>
      parseManifest({
        ...patch(managed, "variables", [
          ...managed.variables.slice(1),
          "ACME_API_KEY",
        ]),
        identity: patch(
          managed.identity as Json,
          "oidc.issuer",
          `\${ACME_API_KEY}`,
        ),
      }),
    ).toThrow("looks like secret material");
    expect(() =>
      parseManifest(patch(managed, "inference.baseUrl", "$ACME_GATEWAY_URL")),
    ).toThrow("Malformed runtime reference");
  });

  it("resolves templates at runtime without recursion", () => {
    expect(
      resolveTemplate("inference.baseUrl", `\${GW}/v1`, ["GW"], {
        GW: "https://llm.example",
      }),
    ).toBe("https://llm.example/v1");
    expect(() =>
      resolveTemplate("inference.baseUrl", `\${GW}`, ["GW"], {}),
    ).toThrow("GW for inference.baseUrl is not set");
    expect(() =>
      resolveTemplate("inference.baseUrl", `\${GW}`, ["GW"], {
        GW: `\${OTHER}`,
      }),
    ).toThrow("contains a reference");
    expect(() =>
      resolveTemplate("inference.baseUrl", `\${GW}`, [], { GW: "x" }),
    ).toThrow("not declared");
  });

  it("keeps v1alpha1 managed manifests rejected with a migration hint", () => {
    expect(() =>
      parseManifest({ ...managed, schema: "piship/v1alpha1" }),
    ).toThrow("Unknown field");
    expect(() =>
      parseManifest({
        schema: "piship/v1alpha1",
        app,
        runtime: { pi: "1.0.0" },
        deployment: { mode: "managed" },
      }),
    ).toThrow("requires schema piship/v1alpha2");
  });
});

describe("model catalog metadata", () => {
  it("records structuredOutput only when declared", () => {
    const withFlag = patch(
      managed,
      "models.catalog.acme/coder",
      undefined,
    ) as Json;
    const models = (withFlag.models as Json).catalog as Json;
    models["acme/coder"] = {
      name: "Coder",
      contextWindow: 128000,
      maxOutputTokens: 8192,
      structuredOutput: true,
    };
    const catalog = parseManifest(withFlag).access?.models.catalog ?? [];
    expect(catalog.find((item) => item.id === "acme/coder")).toMatchObject({
      structuredOutput: true,
    });
    expect(
      catalog.find((item) => item.id === "acme/general"),
    ).not.toHaveProperty("structuredOutput");
    models["acme/coder"] = {
      name: "Coder",
      contextWindow: 128000,
      maxOutputTokens: 8192,
      structuredOutput: "yes",
    };
    expect(() => parseManifest(withFlag)).toThrow("true or false");
  });
});

describe("piship/v1alpha2 personal modes", () => {
  const gateway = {
    inference: {
      provider: "openai-compatible",
      baseUrl: "http://127.0.0.1:8000/v1",
    },
    models: {
      allowed: ["local/coder"],
      catalog: {
        "local/coder": {
          name: "Local",
          contextWindow: 32000,
          maxOutputTokens: 2048,
        },
      },
    },
  };
  it("defaults to no identity with explicit Pi-native delegation", () => {
    const manifest = parseManifest(personal({}));
    expect(manifest.access).toMatchObject({
      identity: { mode: "none" },
      credential: { provider: "pi-native" },
      inference: { provider: "pi-native" },
      network: { publicFallback: "allow" },
    });
  });
  it.each(["local-secret", "none"])(
    "accepts identity none with %s against an explicit endpoint",
    (provider) => {
      expect(
        parseManifest(personal({ credential: { provider }, ...gateway })).access
          ?.credential.provider,
      ).toBe(provider);
    },
  );
  it("accepts a local-secret file store without the managed acknowledgement", () => {
    expect(
      parseManifest(
        personal({
          credential: {
            provider: "local-secret",
            storage: { provider: "file" },
          },
          ...gateway,
        }),
      ).access?.credential.storage.provider,
    ).toBe("file");
  });
  it.each([
    [
      { credential: { provider: "pi-native" }, ...gateway },
      "must be selected together",
    ],
    [{ credential: { provider: "local-secret" } }, "must be selected together"],
    [
      {
        credential: {
          provider: "http-broker",
          broker: { endpoint: "https://b.example" },
        },
        ...gateway,
      },
      "needs an identity session",
    ],
    [
      {
        credential: { provider: "none", storage: { provider: "system" } },
        ...gateway,
      },
      "not stored by PiShip",
    ],
    [{ models: { allowed: ["gpt"] } }, "provider/model"],
    [
      { inference: { provider: "pi-native", baseUrl: "https://x.example" } },
      "pi-native inference uses Pi",
    ],
    [
      {
        credential: { provider: "adapter", adapter: "../escape.mjs" },
        ...gateway,
      },
      "without traversal",
    ],
    [
      {
        credential: { provider: "adapter", adapter: "./adapter.ts" },
        ...gateway,
      },
      "ECMAScript modules",
    ],
  ])("rejects invalid personal combination %#", (extra, message) => {
    expect(() => parseManifest(personal(extra as Json))).toThrow(message);
  });
});

describe("alpha migration", () => {
  it("migrates v1alpha1 to an equivalent v1alpha2 personal profile", () => {
    const source =
      'schema: piship/v1alpha1\n# keep comments\napp:\n  id: mypi\n  name: MyPi\n  command: mypi\n  version: 1.0.0\nruntime:\n  pi: "1.0.0"\ndeployment:\n  mode: personal\n';
    const plan = migrateManifestSource(source, PISHIP_SCHEMA_V1ALPHA2);
    expect(plan.from).toBe("piship/v1alpha1");
    expect(plan.to).toBe("piship/v1alpha2");
    expect(plan.source).toContain("# keep comments");
    expect(plan.source).toContain("provider: pi-native");
    expect(
      migrateManifestSource(plan.source, PISHIP_SCHEMA_V1ALPHA2).changes,
    ).toEqual([]);
  });
});

describe("network.allowHosts", () => {
  const hosts = (allowHosts: unknown) =>
    parseManifest({ ...managed, network: { allowHosts } }).access?.network
      .allowHosts;

  it("takes exact hostnames and IP literals, lowercased", () => {
    expect(
      hosts([
        "SIEM.Corp.Example",
        "10.0.0.5",
        "xn--bcher-kva.example",
        "[::1]",
      ]),
    ).toEqual([
      "siem.corp.example",
      "10.0.0.5",
      "xn--bcher-kva.example",
      "[::1]",
    ]);
  });

  it.each([
    "*.corp.example",
    ".corp.example",
    "corp.example.",
    "https://siem.corp.example",
    "siem.corp.example:8443",
    "siem.corp.example/ingest",
    "10.0.0.0/8",
    "[fd00::1]",
    "b\u00fccher.example",
  ])(
    "rejects %s: no wildcard, suffix, URL, port, path, range, or Unicode form",
    (entry) => {
      expect(() => hosts([entry])).toThrow("Expected a hostname");
    },
  );
});
