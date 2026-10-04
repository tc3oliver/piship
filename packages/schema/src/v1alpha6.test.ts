import { describe, expect, it } from "vitest";
import {
  DATA_CONTRACT_VERSION,
  type Manifest,
  ManifestError,
  MODEL_TYPES,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
  parseManifestHeader,
  RESOURCE_TRUST_CLASSES,
  PROVIDER_TRUST_CLASSES,
  TOOL_EXPOSURES,
  TRUST_CLASSES,
} from "./index.js";

type Json = Record<string, unknown>;

const SHA = "92af01c4d2b7e3f5a6c8d9e0f1a2b3c4d5e6f7a8";
const INTEGRITY = `sha256-${"a".repeat(64)}`;

function personal(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA6,
    app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
    runtime: { pi: "1.0.0" },
    deployment: { mode: "personal" },
    updates: { channel: "stable", channels: ["stable"] },
    ...extra,
  };
}

function managed(extra: Json = {}): Json {
  return {
    ...personal(),
    app: {
      id: "acmecode",
      name: "AcmeCode",
      command: "acmecode",
      version: "1.0.0",
    },
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
      allowed: ["acme/coder", "acme/auto", "acme/classifier"],
      catalog: {
        "acme/coder": {
          name: "Acme Coder",
          contextWindow: 128000,
          maxOutputTokens: 8192,
        },
        "acme/auto": {
          name: "Acme Auto",
          contextWindow: 128000,
          maxOutputTokens: 8192,
          virtual: { router: "company-router", routes: ["acme/coder"] },
        },
        "acme/classifier": {
          name: "Acme Classifier",
          contextWindow: 8192,
          maxOutputTokens: 1024,
          type: "classifier",
          api: "openai-moderations",
        },
      },
    },
    ...extra,
  };
}

function rejects(input: Json, field: string, message?: string): void {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).field).toBe(field);
  if (message) expect((error as ManifestError).message).toContain(message);
}

describe("piship/v1alpha6 schema", () => {
  it("is supported and reported by the header", () => {
    expect(parseManifestHeader(personal())).toEqual({
      schema: PISHIP_SCHEMA_V1ALPHA6,
    });
    expect(parseManifest(personal()).schema).toBe(PISHIP_SCHEMA_V1ALPHA6);
  });

  it("applies defaults for every new section", () => {
    const manifest = parseManifest(personal());
    expect(manifest.runtime).toEqual({
      pi: "1.0.0",
      tools: { codemode: "off", toolSearch: "off", exposure: [] },
      cacheWarming: { mode: "off", userOverride: false },
    });
    expect(manifest.governance?.resources.packages).toEqual([]);
    expect(manifest.governance?.packageTrust).toEqual({
      npm: { requireIntegrity: true },
      git: { requireCommitSha: false },
      local: {},
    });
    expect(manifest.governance?.policy.acknowledgeUnenforced).toEqual([]);
    expect(manifest.data).toBeUndefined();
    expect(manifest.lifecycle?.release.vulnerabilities).not.toHaveProperty(
      "registry",
    );
  });

  it("uses the managed packageTrust defaults", () => {
    expect(parseManifest(managed()).governance?.packageTrust).toEqual({
      npm: { requireIntegrity: true },
      git: { requireCommitSha: true },
      local: { paths: [] },
    });
  });

  it("parses runtime tools and cache warming", () => {
    const manifest = parseManifest(
      personal({
        runtime: {
          pi: "1.0.0",
          tools: {
            codemode: "only",
            toolSearch: "on",
            exposure: { bash: "direct", "company_*": "deferred" },
          },
          cacheWarming: { mode: "idle", userOverride: true },
        },
      }),
    );
    expect(manifest.runtime.tools).toEqual({
      codemode: "only",
      toolSearch: "on",
      exposure: [
        { pattern: "bash", exposure: "direct" },
        { pattern: "company_*", exposure: "deferred" },
      ],
    });
    expect(manifest.runtime.cacheWarming).toEqual({
      mode: "idle",
      userOverride: true,
    });
  });

  it("parses packages of every source and packageTrust", () => {
    const manifest = parseManifest(
      managed({
        resources: {
          packages: [
            {
              id: "company-platform",
              source: "npm",
              package: "@company/pi-platform",
              version: "1.4.2",
              registry: "https://registry.company.example",
              class: "company",
              extensions: ["*"],
              themes: [],
            },
            {
              id: "pi-security",
              source: "git",
              repository: "https://git.company.example/platform/pi-security",
              ref: SHA,
              class: "certified",
              certified: {
                version: "2.0.0",
                source: "https://git.company.example/platform/pi-security",
                integrity: INTEGRITY,
                license: "MIT",
                pi: ["1.0.0"],
                platforms: [],
              },
            },
            {
              id: "local-company",
              source: "local",
              path: "./packages/company",
              class: "company",
              skills: ["review", "!draft-*"],
            },
          ],
        },
        packageTrust: {
          npm: { requireIntegrity: true },
          git: { hosts: ["git.company.example"], requireCommitSha: true },
          local: { paths: ["./packages"] },
        },
      }),
    );
    expect(manifest.governance?.resources.packages).toEqual([
      {
        id: "company-platform",
        class: "company",
        filters: { extensions: ["*"], themes: [] },
        source: "npm",
        package: "@company/pi-platform",
        version: "1.4.2",
        registry: "https://registry.company.example",
      },
      {
        id: "pi-security",
        class: "certified",
        certified: {
          id: "pi-security",
          version: "2.0.0",
          source: "https://git.company.example/platform/pi-security",
          integrity: INTEGRITY,
          license: "MIT",
          pi: ["1.0.0"],
          platforms: [],
        },
        filters: {},
        source: "git",
        repository: "https://git.company.example/platform/pi-security",
        ref: SHA,
      },
      {
        id: "local-company",
        class: "company",
        filters: { skills: ["review", "!draft-*"] },
        source: "local",
        path: "./packages/company",
      },
    ]);
    expect(manifest.governance?.packageTrust).toEqual({
      npm: { requireIntegrity: true },
      git: { hosts: ["git.company.example"], requireCommitSha: true },
      local: { paths: ["./packages"] },
    });
  });

  it("parses MCP server class, exposure, and exposure tools", () => {
    const server = (tools: Json, extra: Json = {}) =>
      parseManifest(
        managed({
          mcp: {
            servers: {
              github: {
                transport: "stdio",
                module: "./mcp/github.mjs",
                tools,
                ...extra,
              },
            },
          },
        }),
      ).governance?.mcp.servers[0];
    expect(
      server(
        {
          "search_*": "codemode",
          "get_*": "deferred",
          "create_*": "direct",
          "delete_*": "hidden",
        },
        { exposure: "deferred", class: "user" },
      ),
    ).toMatchObject({
      class: "user",
      exposure: "deferred",
      toolExposure: [
        { pattern: "search_*", exposure: "codemode" },
        { pattern: "get_*", exposure: "deferred" },
        { pattern: "create_*", exposure: "direct" },
        { pattern: "delete_*", exposure: "hidden" },
      ],
      tools: { allow: [], deny: [] },
    });
    // Defaults: the mode's class and direct exposure.
    expect(server({})).toMatchObject({
      class: "company",
      exposure: "direct",
      toolExposure: [],
      tools: { allow: [], deny: [] },
    });
    // The parser keeps the map as declared; precedence is resolved where
    // tools are registered, so the v0.8 filter stays empty.
    expect(server({ search: "direct", "*": "hidden" })).toMatchObject({
      toolExposure: [
        { pattern: "search", exposure: "direct" },
        { pattern: "*", exposure: "hidden" },
      ],
      tools: { allow: [], deny: [] },
    });
  });

  it("parses model types and virtual models", () => {
    const catalog = parseManifest(managed()).access?.models.catalog;
    expect(catalog?.find((model) => model.id === "acme/auto")).toMatchObject({
      type: "chat",
      virtual: { router: "company-router", routes: ["acme/coder"] },
    });
    expect(
      catalog?.find((model) => model.id === "acme/classifier"),
    ).toMatchObject({ type: "classifier" });
    expect(
      catalog?.find((model) => model.id === "acme/coder"),
    ).not.toHaveProperty("virtual");
    expect(MODEL_TYPES).toEqual(["chat", "classifier", "image"]);
  });

  it("accepts a router as an extension path, a certified id, or a package", () => {
    const router = (value: string) =>
      parseManifest(
        managed({
          models: {
            default: "acme/coder",
            allowed: ["acme/coder", "acme/auto"],
            catalog: {
              "acme/coder": {
                name: "Acme Coder",
                contextWindow: 128000,
                maxOutputTokens: 8192,
              },
              "acme/auto": {
                name: "Acme Auto",
                contextWindow: 128000,
                maxOutputTokens: 8192,
                virtual: { router: value, routes: ["acme/coder"] },
              },
            },
          },
        }),
      ).access?.models.catalog.find((model) => model.id === "acme/auto")
        ?.virtual?.router;
    for (const value of [
      "./resources/extensions/router",
      "company-router",
      "package:company-platform",
    ])
      expect(router(value)).toBe(value);
    for (const value of ["../outside", "./a/../b", "package:Bad", "Router X"])
      expect(() => router(value)).toThrow(
        /models\.catalog\.acme\/auto\.virtual\.router/,
      );
  });

  it("parses image models with api and output", () => {
    const manifest = parseManifest(
      managed({
        models: {
          default: "acme/coder",
          allowed: ["acme/coder", "acme/image"],
          catalog: {
            "acme/coder": {
              name: "Acme Coder",
              contextWindow: 128000,
              maxOutputTokens: 8192,
            },
            "acme/image": {
              name: "Acme Image",
              contextWindow: 4096,
              maxOutputTokens: 1,
              type: "image",
              api: "openai-images",
              output: ["image"],
            },
          },
        },
      }),
    );
    expect(
      manifest.access?.models.catalog.find(
        (model) => model.id === "acme/image",
      ),
    ).toMatchObject({ type: "image", api: "openai-images", output: ["image"] });
  });

  it("lets pi-native inference declare only virtual and non-chat entries", () => {
    const piNative = (catalog: Json) =>
      personal({
        identity: { mode: "none" },
        credential: { provider: "pi-native" },
        inference: { provider: "pi-native" },
        models: { catalog },
      });
    const manifest = parseManifest(
      piNative({
        "company/auto": {
          name: "Company Auto",
          contextWindow: 128000,
          maxOutputTokens: 8192,
          virtual: {
            router: "./extensions/router",
            routes: ["anthropic/claude-opus-x", "openai/gpt-y"],
          },
        },
      }),
    );
    expect(manifest.access?.models.catalog[0]?.virtual?.routes).toEqual([
      "anthropic/claude-opus-x",
      "openai/gpt-y",
    ]);
    rejects(
      piNative({
        "anthropic/claude": {
          name: "Claude",
          contextWindow: 1,
          maxOutputTokens: 1,
        },
      }),
      "models.catalog.anthropic/claude",
      "only virtual and classifier or image entries",
    );
    rejects(
      {
        ...piNative({
          "anthropic/claude": {
            name: "Claude",
            contextWindow: 1,
            maxOutputTokens: 1,
            virtual: { router: "r", routes: ["a/b"] },
          },
        }),
        schema: PISHIP_SCHEMA_V1ALPHA5,
      },
      "models.catalog.anthropic/claude.virtual",
      "Unknown field",
    );
  });

  it("parses the data lifecycle and session export", () => {
    const manifest = parseManifest(
      personal({
        data: {
          sessions: { retention: "30d" },
          audit: { retention: "180d" },
          cache: { retention: "7d" },
          temp: { retention: "12h" },
          purge: { onLogout: ["cache", "temp"], onUninstall: "all" },
          export: { public: "deny", local: "allow" },
        },
      }),
    );
    expect(manifest.data).toEqual({
      retention: {
        sessions: { retentionSeconds: 30 * 86_400 },
        audit: { retentionSeconds: 180 * 86_400 },
        cache: { retentionSeconds: 7 * 86_400 },
        temp: { retentionSeconds: 12 * 3_600 },
      },
      purge: { onLogout: ["cache", "temp"], onUninstall: "all" },
      export: { public: "deny", local: "allow" },
    });
    expect(parseManifest(personal({ data: {} })).data).toEqual({
      retention: {},
      purge: { onLogout: [], onUninstall: "none" },
      export: {},
    });
    expect(DATA_CONTRACT_VERSION).toBe("piship-data/v1");
  });

  it("parses acknowledgeUnenforced and the audit registry", () => {
    const manifest = parseManifest(
      managed({
        policy: {
          acknowledgeUnenforced: ["session.export:public", "model.use:acme/*"],
        },
        release: {
          vulnerabilities: { registry: "https://registry.company.example/npm" },
        },
      }),
    );
    expect(manifest.governance?.policy.acknowledgeUnenforced).toEqual([
      "session.export:public",
      "model.select:acme/*",
    ]);
    expect(manifest.lifecycle?.release.vulnerabilities.registry).toBe(
      "https://registry.company.example/npm",
    );
  });

  it("accepts the new policy actions and reads model.use as model.select", () => {
    const manifest = parseManifest(
      personal({
        policy: {
          enforced: [
            {
              id: "no.share",
              action: "session.export",
              resource: "public",
              effect: "deny",
            },
            { id: "routes", action: "model.dispatch", effect: "allow" },
            { id: "legacy", action: "model.use", effect: "allow" },
          ],
        },
      }),
    );
    expect(
      manifest.governance?.policy.enforced.map((rule) => rule.action),
    ).toEqual(["session.export", "model.dispatch", "model.select"]);
  });
});

describe("piship/v1alpha6 validation", () => {
  it.each<[Json, string, string]>([
    [
      personal({ runtime: { pi: "1.0.0", tools: { codemode: "always" } } }),
      "runtime.tools.codemode",
      "off, on, only",
    ],
    [
      personal({
        runtime: { pi: "1.0.0", tools: { exposure: { bash: "visible" } } },
      }),
      "runtime.tools.exposure.bash",
      TOOL_EXPOSURES.join(", "),
    ],
    [
      personal({
        runtime: { pi: "1.0.0", tools: { exposure: { "a b": "direct" } } },
      }),
      "runtime.tools.exposure.a b",
      "Tool globs",
    ],
    [
      personal({ runtime: { pi: "1.0.0", cacheWarming: { mode: "always" } } }),
      "runtime.cacheWarming.mode",
      "off, streaming, idle",
    ],
    [
      personal({
        resources: { packages: [{ id: "x", source: "svn", class: "user" }] },
      }),
      "resources.packages[0].source",
      "npm, git, local",
    ],
    [
      personal({
        resources: {
          packages: [
            {
              id: "x",
              source: "npm",
              package: "x",
              version: "1.0.0",
              class: "project",
            },
          ],
        },
      }),
      "resources.packages[0].class",
      "certified, company, user",
    ],
    [
      personal({
        resources: {
          packages: [
            {
              id: "x",
              source: "npm",
              package: "x",
              version: "1.0.0",
              class: "certified",
            },
          ],
        },
      }),
      "resources.packages[0].certified",
      "review evidence",
    ],
    [
      personal({
        resources: {
          packages: [
            {
              id: "x",
              source: "git",
              repository: "https://user:pw@git.example.com/x",
              ref: SHA,
              class: "user",
            },
          ],
        },
      }),
      "resources.packages[0].repository",
      "must not embed credentials",
    ],
    [
      personal({
        resources: {
          packages: [
            {
              id: "x",
              source: "npm",
              package: "x",
              version: "1.0.0",
              registry: "https://registry.example.com/?auth=1",
              class: "user",
            },
          ],
        },
      }),
      "resources.packages[0].registry",
      "query or fragment",
    ],
    [
      personal({
        resources: {
          packages: [
            { id: "x", source: "local", path: "../outside", class: "user" },
          ],
        },
      }),
      "resources.packages[0].path",
      "./ relative path",
    ],
    [
      personal({
        resources: {
          packages: [
            { id: "x", source: "local", path: "./a", ref: SHA, class: "user" },
          ],
        },
      }),
      "resources.packages[0].ref",
      "Unknown field",
    ],
    [
      personal({
        resources: {
          packages: [
            { id: "x", source: "local", path: "./a", class: "user" },
            { id: "x", source: "local", path: "./b", class: "user" },
          ],
        },
      }),
      "resources.packages[1]",
      "Duplicate entry",
    ],
    [
      personal({
        packageTrust: { git: { hosts: ["https://git.example.com"] } },
      }),
      "packageTrust.git.hosts[0]",
      "host name",
    ],
    [
      personal({
        mcp: {
          servers: {
            docs: {
              transport: "stdio",
              module: "./mcp/docs.mjs",
              tools: { allow: ["search"] },
            },
          },
        },
      }),
      "mcp.servers.docs.tools",
      "run piship migrate",
    ],
    [
      personal({
        mcp: {
          servers: {
            docs: {
              transport: "stdio",
              module: "./mcp/docs.mjs",
              class: "certified",
            },
          },
        },
      }),
      "mcp.servers.docs.class",
      "company, user",
    ],
    [
      managed({
        models: {
          default: "acme/coder",
          allowed: ["acme/coder"],
          catalog: {
            "acme/coder": {
              name: "Acme Coder",
              contextWindow: 1,
              maxOutputTokens: 1,
              type: "embedding",
            },
          },
        },
      }),
      "models.catalog.acme/coder.type",
      "chat, classifier, image",
    ],
    [
      managed({
        models: {
          default: "acme/coder",
          allowed: ["acme/coder"],
          catalog: {
            "acme/coder": {
              name: "Acme Coder",
              contextWindow: 1,
              maxOutputTokens: 1,
              virtual: { router: "r", routes: [] },
            },
          },
        },
      }),
      "models.catalog.acme/coder.virtual.routes",
      "physical models",
    ],
    [
      managed({
        models: {
          default: "acme/coder",
          allowed: ["acme/coder"],
          catalog: {
            "acme/coder": {
              name: "Acme Coder",
              contextWindow: 1,
              maxOutputTokens: 1,
              type: "image",
              api: "openai-images",
            },
          },
        },
      }),
      "models.catalog.acme/coder.output",
      "lists its output",
    ],
    [
      managed({
        models: {
          default: "acme/coder",
          allowed: ["acme/coder"],
          catalog: {
            "acme/coder": {
              name: "Acme Coder",
              contextWindow: 1,
              maxOutputTokens: 1,
              output: ["text"],
            },
          },
        },
      }),
      "models.catalog.acme/coder.output",
      "applies to image models",
    ],
    [
      personal({ data: { sessions: { retention: "30" } } }),
      "data.sessions.retention",
      "30d or 12h",
    ],
    [
      personal({ data: { purge: { onLogout: ["credentials"] } } }),
      "data.purge.onLogout[0]",
      "sessions, audit, cache, temp",
    ],
    [
      personal({ data: { export: { gist: "deny" } } }),
      "data.export.gist",
      "Unknown field",
    ],
    [
      personal({ policy: { acknowledgeUnenforced: ["web.request"] } }),
      "policy.acknowledgeUnenforced[0]",
      "<action>:<resource>",
    ],
    [
      personal({ policy: { acknowledgeUnenforced: ["web.*:x"] } }),
      "policy.acknowledgeUnenforced[0]",
      "one policy action",
    ],
    [
      personal({
        release: {
          vulnerabilities: { registry: "http://registry.example.com" },
        },
      }),
      "release.vulnerabilities.registry",
      "https",
    ],
  ])("rejects %j at %s", (input, field, message) => {
    rejects(input, field, message);
  });

  it("rejects the v1alpha6 fields in a piship/v1alpha5 manifest", () => {
    const v5 = (extra: Json) => ({
      ...personal(extra),
      schema: PISHIP_SCHEMA_V1ALPHA5,
    });
    rejects(v5({ packageTrust: {} }), "manifest.packageTrust", "Unknown field");
    rejects(v5({ data: {} }), "manifest.data", "Unknown field");
    rejects(
      v5({ runtime: { pi: "1.0.0", tools: {} } }),
      "runtime.tools",
      "Unknown field",
    );
    rejects(
      v5({ resources: { packages: [] } }),
      "resources.packages",
      "Unknown field",
    );
    rejects(
      v5({ policy: { acknowledgeUnenforced: [] } }),
      "policy.acknowledgeUnenforced",
      "Unknown field",
    );
  });

  it("keeps a piship/v1alpha5 manifest's parsed shape", () => {
    const manifest: Manifest = parseManifest({
      ...personal({
        mcp: {
          servers: {
            docs: {
              transport: "stdio",
              module: "./mcp/docs.mjs",
              tools: { deny: ["delete"] },
            },
          },
        },
      }),
      schema: PISHIP_SCHEMA_V1ALPHA5,
    });
    expect(manifest.runtime).toEqual({ pi: "1.0.0" });
    expect(manifest.governance).not.toHaveProperty("packageTrust");
    expect(manifest.governance?.resources).not.toHaveProperty("packages");
    expect(manifest.governance?.mcp.servers[0]).not.toHaveProperty("class");
    expect(manifest.governance?.mcp.servers[0]?.tools).toEqual({
      allow: [],
      deny: ["delete"],
    });
  });
});

describe("unified trust vocabulary", () => {
  it("shares one class list; providers exclude project", () => {
    expect(RESOURCE_TRUST_CLASSES).toBe(TRUST_CLASSES);
    expect(PROVIDER_TRUST_CLASSES).toEqual(
      TRUST_CLASSES.filter((cls) => cls !== "project"),
    );
  });
});
