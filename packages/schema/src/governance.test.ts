import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  BUILTIN_PROVIDER_VERSION,
  DEFAULT_SANDBOX_ENVIRONMENT,
  DEFAULT_SANDBOX_READ_DENY,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  SUPPORTED_SCHEMAS,
  migrateManifestSource,
  parseGovernance,
  parseManifest,
  parseManifestHeader,
} from "./index.js";

type Json = Record<string, unknown>;
const app = {
  id: "acmecode",
  name: "AcmeCode",
  command: "acmecode",
  version: "1.0.0",
};
const INTEGRITY = `sha256-${"a1".repeat(32)}`;
const managedAccess = {
  variables: ["ACME_ISSUER", "ACME_CLIENT_ID", "ACME_GATEWAY_URL"],
  identity: {
    mode: "oidc",
    oidc: {
      issuer: `\${ACME_ISSUER}`,
      clientId: `\${ACME_CLIENT_ID}`,
      redirectUri: "http://127.0.0.1:8765/callback",
    },
  },
  credential: { provider: "adapter", adapter: "./adapters/credential.mjs" },
  inference: { provider: "openai-compatible", baseUrl: `\${ACME_GATEWAY_URL}` },
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
function managed(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA3,
    app,
    runtime: { pi: "0.87.1" },
    deployment: { mode: "managed" },
    ...structuredClone(managedAccess),
    ...extra,
  };
}
function personal(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA3,
    app: { ...app, id: "mypi", command: "mypi" },
    runtime: { pi: "0.87.1" },
    deployment: { mode: "personal" },
    ...extra,
  };
}
function governance(input: Json) {
  const manifest = parseManifest(input);
  if (!manifest.governance) throw new Error("governance missing");
  return manifest.governance;
}
function certified(extra: Json = {}): Json {
  return {
    path: "./vendor/source-citation",
    id: "source-citation",
    version: "1.2.0",
    source: "https://example.org/source-citation",
    integrity: INTEGRITY,
    license: "MIT",
    pi: ["0.87.1"],
    ...extra,
  };
}
function rejects(input: Json, field: string, message?: string) {
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

describe("piship/v1alpha3 schema", () => {
  it("is supported and reported by the header", () => {
    expect(SUPPORTED_SCHEMAS).toContain(PISHIP_SCHEMA_V1ALPHA3);
    expect(parseManifestHeader(personal())).toEqual({
      schema: PISHIP_SCHEMA_V1ALPHA3,
    });
  });
  it("keeps access sections and adds governance only for v1alpha3", () => {
    const manifest = parseManifest(managed());
    expect(manifest.schema).toBe(PISHIP_SCHEMA_V1ALPHA3);
    expect(manifest.access?.identity.mode).toBe("oidc");
    expect(manifest.governance).toBeDefined();
    const v2 = parseManifest({ ...managed(), schema: PISHIP_SCHEMA_V1ALPHA2 });
    expect(v2.governance).toBeUndefined();
    expect(v2.access).toBeDefined();
  });
  it("still enforces v1alpha2 access rules", () => {
    rejects(managed({ identity: undefined }), "identity");
    rejects(
      managed({ network: { publicFallback: "allow" } }),
      "network.publicFallback",
    );
  });
  it.each(["policy", "mcp", "sandbox", "audit", "capabilities"])(
    "rejects the %s section on v1alpha2",
    (key) => {
      rejects(
        { ...managed(), schema: PISHIP_SCHEMA_V1ALPHA2, [key]: {} },
        `manifest.${key}`,
        "Unknown field",
      );
    },
  );
  it("rejects unknown top-level fields and secret-looking ones", () => {
    rejects(personal({ tools: {} }), "manifest.tools", "Unknown field");
    rejects(
      personal({ policy: { apiKey: "x" } }),
      "policy.apiKey",
      "Secrets are never declared",
    );
  });
});

describe("v1alpha3 defaults", () => {
  it("applies managed defaults", () => {
    const result = governance(managed());
    expect(result.resources).toEqual({ declared: [], builtin: [] });
    expect(result.policy).toEqual({
      id: "acmecode",
      version: 1,
      default: "ask",
      enforced: [],
      defaults: [],
      resourceTrust: {
        upstream: "allow",
        builtin: "allow",
        certified: "allow",
        company: "allow",
        user: "deny",
        project: "policy",
      },
      providerTrust: {
        upstream: "allow",
        builtin: "allow",
        certified: "allow",
        company: "allow",
        user: "deny",
      },
      projectTrust: {
        company: {
          match: [],
          dimensions: {
            passiveContext: "allow",
            instructions: "allow",
            skills: "allow",
            agents: "deny",
            hooks: "deny",
            extensions: "company-approved",
            mcp: "company-approved",
            providers: "deny",
          },
        },
        external: {
          match: [],
          dimensions: {
            passiveContext: "allow",
            instructions: "ask",
            skills: "deny",
            agents: "deny",
            hooks: "deny",
            extensions: "deny",
            mcp: "deny",
            providers: "deny",
          },
        },
        unknown: {
          dimensions: {
            passiveContext: "allow",
            instructions: "deny",
            skills: "deny",
            agents: "deny",
            hooks: "deny",
            extensions: "deny",
            mcp: "deny",
            providers: "deny",
          },
        },
      },
    });
    expect(result.mcp).toEqual({
      mode: "allowlist",
      servers: [],
      project: "deny",
      user: "deny",
    });
    expect(result.sandbox).toEqual({
      required: false,
      filesystem: {
        read: { deny: [...DEFAULT_SANDBOX_READ_DENY] },
        write: { allow: ["workspace", "tmp"] },
      },
      network: { mode: "allow" },
      environment: { allow: [...DEFAULT_SANDBOX_ENVIRONMENT] },
    });
    expect(result.audit).toEqual({
      enabled: true,
      sinks: [{ id: "local", type: "file", required: false }],
      buffer: { maxEvents: 1000, flushIntervalMs: 2000 },
      capture: {
        promptContent: false,
        responseContent: false,
        commandText: false,
        sourceContent: false,
      },
    });
  });
  it("applies personal defaults", () => {
    const result = governance(personal());
    expect(result.policy.id).toBe("mypi");
    expect(result.policy.default).toBe("allow");
    expect(Object.values(result.policy.resourceTrust)).toEqual([
      "allow",
      "allow",
      "allow",
      "allow",
      "allow",
      "policy",
    ]);
    expect(Object.values(result.policy.providerTrust)).toEqual([
      "allow",
      "allow",
      "allow",
      "allow",
      "allow",
    ]);
    const allowAll = {
      passiveContext: "allow",
      instructions: "allow",
      skills: "allow",
      agents: "allow",
      hooks: "deny",
      extensions: "allow",
      mcp: "allow",
      providers: "allow",
    };
    expect(result.policy.projectTrust.company.dimensions).toEqual(allowAll);
    expect(result.policy.projectTrust.external.dimensions).toEqual(allowAll);
    expect(result.policy.projectTrust.unknown.dimensions).toEqual({
      passiveContext: "allow",
      instructions: "ask",
      skills: "ask",
      agents: "ask",
      hooks: "deny",
      extensions: "ask",
      mcp: "ask",
      providers: "ask",
    });
    expect(result.mcp).toEqual({
      mode: "explicit",
      servers: [],
      project: "allow",
      user: "allow",
    });
    expect(result.audit.enabled).toBe(false);
    expect(result.audit.sinks).toEqual([]);
  });
  it("defaults capabilities: permissions builtin, the rest disabled", () => {
    const result = governance(personal());
    expect(result.capabilities.map((item) => item.name)).toEqual([
      "permissions",
      "workflow",
      "checkpoint",
      "subagents",
      "code-intel",
      "acp",
    ]);
    expect(result.capabilities[0]).toEqual({
      name: "permissions",
      enabled: true,
      provider: {
        id: "builtin/permissions",
        class: "builtin",
        version: BUILTIN_PROVIDER_VERSION,
        implements: ["piship.capability/permissions/v1"],
      },
      settings: {},
    });
    for (const item of result.capabilities.slice(1))
      expect(item).toEqual({ name: item.name, enabled: false, settings: {} });
  });
  it("uses network deny by default when the sandbox is required", () => {
    expect(
      governance(personal({ sandbox: { required: true } })).sandbox.network,
    ).toEqual({ mode: "deny" });
  });
  it("defaults MCP server settings", () => {
    const [server] = governance(
      personal({
        mcp: { servers: { docs: { transport: "stdio", command: "docs-mcp" } } },
      }),
    ).mcp.servers;
    expect(server).toEqual({
      id: "docs",
      transport: "stdio",
      command: "docs-mcp",
      args: [],
      env: { allow: [], set: {} },
      credential: "none",
      timeoutMs: 30000,
      startupTimeoutMs: 10000,
      retry: { attempts: 1 },
      required: false,
      tools: { allow: [], deny: [] },
    });
  });
  it("exports parseGovernance for direct use", () => {
    expect(parseGovernance({}, "managed", [], { id: "acme" }).policy.id).toBe(
      "acme",
    );
  });
});

describe("v1alpha3 full managed example", () => {
  const full = managed({
    variables: [
      ...managedAccess.variables,
      "ACMECODE_TICKETS_MCP_URL",
      "ACMECODE_AUDIT_URL",
    ],
    resources: {
      instructions: { company: ["./resources/AGENTS.md"] },
      skills: { company: ["./resources/skills"] },
      extensions: {
        builtin: ["piship-ask-user", "piship-workflow"],
        company: ["./resources/extensions/enterprise-context"],
        certified: [certified({ platforms: ["linux", "darwin", "win32"] })],
        user: ["./resources/extensions/mine"],
      },
      prompts: { user: ["./resources/prompts"] },
      themes: { user: ["./resources/themes"] },
    },
    capabilities: {
      permissions: {
        enabled: true,
        provider: {
          id: "company/perm-plus",
          version: "2.3.1",
          implements: ["piship.capability/permissions/v1"],
          path: "./providers/perm-plus",
        },
      },
      workflow: {
        enabled: true,
        provider: { id: "builtin/workflow" },
        settings: {
          defaultMode: "plan",
          planPrompt: "Plan first.\nThen stop.",
          buildPrompt: "Build it.",
        },
      },
      checkpoint: { enabled: false },
      subagents: {
        enabled: true,
        provider: {
          id: "certified/agents-plus",
          version: "0.4.0",
          implements: ["piship.capability/agents/v2"],
          path: "./providers/agents-plus",
          source: "npm:@acme/agents-plus@0.4.0",
          integrity: INTEGRITY,
          license: "Apache-2.0",
          pi: ["0.87.1", "0.88.0"],
          platforms: ["linux"],
        },
      },
    },
    policy: {
      id: "acme-engineering",
      version: 3,
      default: "deny",
      adapter: "./enterprise/policy.mjs",
      resourceTrust: { user: "allow", project: "deny" },
      providerTrust: { user: "allow", certified: "deny" },
      projectTrust: {
        company: {
          match: [{ remote: "git.acme.example/**" }, { path: "/srv/acme/**" }],
          passiveContext: "allow",
          instructions: "allow",
          skills: "allow",
          extensions: "company-approved",
          mcp: "company-approved",
          hooks: "deny",
        },
        external: { match: [{ path: "/opt/vendor/**" }], instructions: "ask" },
        unknown: { instructions: "deny", passiveContext: "deny" },
      },
      enforced: [
        {
          id: "acme.secrets.read",
          action: "filesystem.read",
          resource: "~/.ssh/**",
          effect: "deny",
          reason: "Credentials stay outside the agent",
        },
        { id: "acme.mcp", action: "mcp.*", effect: "ask" },
        { id: "acme.mcp-tools", action: "mcp.tool.*", effect: "ask" },
      ],
      defaults: [
        {
          id: "acme.shell.ask",
          action: "shell.execute",
          resource: "**",
          effect: "ask",
        },
        { id: "acme.all", action: "*", effect: "allow" },
      ],
    },
    mcp: {
      mode: "allowlist",
      project: "deny",
      user: "deny",
      servers: {
        docs: {
          transport: "stdio",
          module: "./resources/mcp/docs-server.mjs",
          args: ["--mode", "demo"],
          env: { allow: ["LANG"], set: { DOCS_MODE: "demo" } },
          expectedServerName: "acme-docs",
          timeout: "1m",
          startupTimeout: "5s",
          retry: { attempts: 2 },
          required: true,
          tools: { allow: ["search", "get_document"], deny: ["delete"] },
        },
        tickets: {
          transport: "streamable-http",
          url: `\${ACMECODE_TICKETS_MCP_URL}`,
          credential: "runtime",
        },
        wiki: {
          transport: "streamable-http",
          url: "https://wiki.acme.example/mcp",
        },
      },
    },
    sandbox: {
      required: true,
      filesystem: {
        read: { deny: ["~/.ssh", "~/.aws", "/etc/acme/"] },
        write: { allow: ["workspace", "tmp", "workspace/build"] },
      },
      network: { mode: "allow" },
      environment: { allow: ["PATH", "HOME", "LANG", "TERM"] },
    },
    audit: {
      enabled: true,
      sinks: [
        { id: "local", type: "file", required: false },
        {
          id: "company",
          type: "http",
          url: `\${ACMECODE_AUDIT_URL}`,
          required: true,
        },
      ],
      buffer: { maxEvents: 500, flushInterval: "5s" },
      capture: {
        promptContent: true,
        responseContent: false,
        commandText: true,
        sourceContent: false,
      },
    },
  });

  it("parses every declared field", () => {
    const manifest = parseManifest(full);
    const result = manifest.governance;
    expect(result?.resources.builtin).toEqual([
      "piship-ask-user",
      "piship-workflow",
    ]);
    expect(result?.resources.declared).toEqual([
      {
        kind: "instructions",
        class: "company",
        path: "./resources/AGENTS.md",
      },
      { kind: "skills", class: "company", path: "./resources/skills" },
      {
        kind: "extensions",
        class: "certified",
        path: "./vendor/source-citation",
        certified: {
          id: "source-citation",
          version: "1.2.0",
          source: "https://example.org/source-citation",
          integrity: INTEGRITY,
          license: "MIT",
          pi: ["0.87.1"],
          platforms: ["linux", "darwin", "win32"],
        },
      },
      {
        kind: "extensions",
        class: "company",
        path: "./resources/extensions/enterprise-context",
      },
      {
        kind: "extensions",
        class: "user",
        path: "./resources/extensions/mine",
      },
      { kind: "prompts", class: "user", path: "./resources/prompts" },
      { kind: "themes", class: "user", path: "./resources/themes" },
    ]);
    expect(manifest.resources).toEqual({
      instructions: ["./resources/AGENTS.md"],
      skills: ["./resources/skills"],
      extensions: [
        "./vendor/source-citation",
        "./resources/extensions/enterprise-context",
        "./resources/extensions/mine",
      ],
      prompts: ["./resources/prompts"],
      themes: ["./resources/themes"],
    });
    const [permissions, workflow, checkpoint, subagents] =
      result?.capabilities ?? [];
    expect(permissions?.provider).toEqual({
      id: "company/perm-plus",
      class: "company",
      version: "2.3.1",
      implements: ["piship.capability/permissions/v1"],
      path: "./providers/perm-plus",
    });
    expect(workflow).toMatchObject({
      enabled: true,
      provider: { id: "builtin/workflow", class: "builtin" },
      settings: { defaultMode: "plan", planPrompt: "Plan first.\nThen stop." },
    });
    expect(checkpoint).toEqual({
      name: "checkpoint",
      enabled: false,
      settings: {},
    });
    expect(subagents?.provider).toEqual({
      id: "certified/agents-plus",
      class: "certified",
      version: "0.4.0",
      implements: ["piship.capability/agents/v2"],
      path: "./providers/agents-plus",
      certified: {
        id: "certified/agents-plus",
        version: "0.4.0",
        source: "npm:@acme/agents-plus@0.4.0",
        integrity: INTEGRITY,
        license: "Apache-2.0",
        pi: ["0.87.1", "0.88.0"],
        platforms: ["linux"],
      },
    });
    expect(result?.policy).toMatchObject({
      id: "acme-engineering",
      version: 3,
      default: "deny",
      adapter: "./enterprise/policy.mjs",
      resourceTrust: { user: "allow", project: "deny", company: "allow" },
      providerTrust: { user: "allow", certified: "deny", builtin: "allow" },
    });
    expect(result?.policy.projectTrust.company).toEqual({
      match: [{ remote: "git.acme.example/**" }, { path: "/srv/acme/**" }],
      dimensions: {
        passiveContext: "allow",
        instructions: "allow",
        skills: "allow",
        agents: "deny",
        hooks: "deny",
        extensions: "company-approved",
        mcp: "company-approved",
        providers: "deny",
      },
    });
    expect(result?.policy.projectTrust.external.dimensions.instructions).toBe(
      "ask",
    );
    expect(result?.policy.projectTrust.unknown.dimensions.passiveContext).toBe(
      "deny",
    );
    expect(result?.policy.enforced[1]).toEqual({
      id: "acme.mcp",
      action: "mcp.*",
      resource: "**",
      effect: "ask",
    });
    expect(result?.policy.defaults.map((rule) => rule.action)).toEqual([
      "shell.execute",
      "*",
    ]);
    const [docs, tickets, wiki] = result?.mcp.servers ?? [];
    expect(docs).toEqual({
      id: "docs",
      transport: "stdio",
      module: "./resources/mcp/docs-server.mjs",
      args: ["--mode", "demo"],
      env: { allow: ["LANG"], set: { DOCS_MODE: "demo" } },
      credential: "none",
      expectedServerName: "acme-docs",
      timeoutMs: 60000,
      startupTimeoutMs: 5000,
      retry: { attempts: 2 },
      required: true,
      tools: { allow: ["search", "get_document"], deny: ["delete"] },
    });
    expect(tickets).toMatchObject({
      transport: "streamable-http",
      url: `\${ACMECODE_TICKETS_MCP_URL}`,
      credential: "runtime",
    });
    expect(wiki?.url).toBe("https://wiki.acme.example/mcp");
    expect(result?.sandbox).toEqual({
      required: true,
      filesystem: {
        read: { deny: ["~/.ssh", "~/.aws", "/etc/acme"] },
        write: { allow: ["workspace", "tmp", "workspace/build"] },
      },
      network: { mode: "allow" },
      environment: { allow: ["PATH", "HOME", "LANG", "TERM"] },
    });
    expect(result?.audit).toEqual({
      enabled: true,
      sinks: [
        { id: "local", type: "file", required: false },
        {
          id: "company",
          type: "http",
          url: `\${ACMECODE_AUDIT_URL}`,
          required: true,
        },
      ],
      buffer: { maxEvents: 500, flushIntervalMs: 5000 },
      capture: {
        promptContent: true,
        responseContent: false,
        commandText: true,
        sourceContent: false,
      },
    });
  });
  it("counts governance runtime references as used variables", () => {
    rejects(
      managed({
        variables: [...managedAccess.variables, "ACMECODE_AUDIT_URL"],
      }),
      "variables[3]",
      "declared but not referenced",
    );
  });
  it("requires governance runtime references to be declared", () => {
    const input = structuredClone(full);
    (input.variables as string[]).pop();
    rejects(input, "audit.sinks[1].url", "not declared in variables");
  });
});

describe("v1alpha3 resources", () => {
  const resources = (value: Json) => personal({ resources: value });
  it("rejects flat lists with a migration hint", () => {
    rejects(
      resources({ skills: ["./skills"] }),
      "resources.skills",
      "piship migrate",
    );
  });
  it.each([
    ["upstream", "pinned Pi package"],
    ["project", "policy.projectTrust"],
  ])("rejects the undeclarable %s class", (trust, message) => {
    rejects(
      resources({ skills: { [trust]: ["./skills"] } }),
      `resources.skills.${trust}`,
      message,
    );
  });
  it("rejects builtin outside extensions and unknown builtin names", () => {
    rejects(
      resources({ skills: { builtin: ["piship-ask-user"] } }),
      "resources.skills.builtin",
      "only valid under resources.extensions",
    );
    rejects(
      resources({ extensions: { builtin: ["piship-unknown"] } }),
      "resources.extensions.builtin[0]",
      "builtin extension",
    );
    rejects(
      resources({ extensions: { builtin: ["./piship-ask-user"] } }),
      "resources.extensions.builtin[0]",
    );
    rejects(
      resources({
        extensions: { builtin: ["piship-ask-user", "piship-ask-user"] },
      }),
      "resources.extensions.builtin[1]",
      "Duplicate",
    );
  });
  it("rejects unknown classes and resource kinds", () => {
    rejects(
      resources({ skills: { vendor: ["./x"] } }),
      "resources.skills.vendor",
      "Unknown field",
    );
    rejects(resources({ agents: { company: ["./x"] } }), "resources.agents");
  });
  it.each([
    ["../outside", "resources.skills.company[0]"],
    ["./a/../../outside", "resources.skills.company[0]"],
    ["/etc/passwd", "resources.skills.company[0]"],
    ["./a\\..\\b", "resources.skills.company[0]"],
    ["./a//b", "resources.skills.company[0]"],
    ["./", "resources.skills.company[0]"],
    ["~/.pi/agent/skills", "resources.skills.company[0]"],
  ])("rejects unsafe path %s", (path, field) => {
    rejects(
      resources({ skills: { company: [path] } }),
      field,
      "without traversal",
    );
  });
  it("rejects runtime references in resource paths", () => {
    rejects(
      resources({ skills: { user: [`./\${HOME}`] } }),
      "resources.skills.user[0]",
      "Runtime references",
    );
  });
  it("rejects a path declared in two classes", () => {
    rejects(
      resources({ skills: { company: ["./skills"], user: ["./skills"] } }),
      "resources.skills.user[0]",
      "exactly one trust class",
    );
    rejects(
      resources({
        extensions: {
          certified: [certified({ path: "./ext" })],
          company: ["./ext"],
        },
      }),
      "resources.extensions.company[0]",
      "already declared as certified",
    );
  });
  it("rejects nested roots that mix classes", () => {
    rejects(
      resources({
        skills: { company: ["./skills"], user: ["./skills/mine"] },
      }),
      "resources.skills.user[0]",
      "overlaps",
    );
  });
  it("rejects duplicate paths within a class", () => {
    rejects(
      resources({ skills: { user: ["./skills", "./skills"] } }),
      "resources.skills.user[1]",
      "Duplicate",
    );
  });
  const certifiedCase = (entry: Json) =>
    resources({ extensions: { certified: [entry] } });
  it.each([
    ["id", { id: undefined }, "non-empty"],
    ["id", { id: "Source Citation" }, "lowercase"],
    ["version", { version: undefined }, "non-empty"],
    ["version", { version: "latest" }, "SemVer"],
    ["version", { version: "v1.2.0" }, "SemVer"],
    ["source", { source: undefined }, "non-empty"],
    ["source", { source: "https://user:pw@example.org/x" }, "credentials"],
    ["integrity", { integrity: undefined }, "non-empty"],
    ["integrity", { integrity: `sha256-${"A1".repeat(32)}` }, "lowercase"],
    ["integrity", { integrity: `sha512-${"a1".repeat(32)}` }, "sha256-"],
    ["integrity", { integrity: `sha256-${"a1".repeat(31)}` }, "64"],
    ["license", { license: undefined }, "non-empty"],
    ["license", { license: "MIT; rm -rf" }, "SPDX"],
    ["pi", { pi: undefined }, "reviewed against"],
    ["pi", { pi: [] }, "reviewed against"],
    ["pi[0]", { pi: ["^0.87.0"] }, "exact Pi version"],
    ["platforms[0]", { platforms: ["freebsd"] }, "linux, darwin, win32"],
    ["path", { path: "../vendor" }, "without traversal"],
  ])("validates certified evidence field %s", (field, patch, message) => {
    rejects(
      certifiedCase(certified(patch)),
      `resources.extensions.certified[0].${field}`,
      message,
    );
  });
  it("rejects unknown and secret-looking certified fields", () => {
    rejects(
      certifiedCase(certified({ signature: "x" })),
      "resources.extensions.certified[0].signature",
      "Unknown field",
    );
    rejects(
      certifiedCase(certified({ token: "x" })),
      "resources.extensions.certified[0].token",
      "Secrets are never declared",
    );
  });
  it("accepts certified entries for any resource kind", () => {
    const result = governance(
      resources({ skills: { certified: [certified({ path: "./skills" })] } }),
    );
    expect(result.resources.declared[0]?.certified?.id).toBe("source-citation");
  });
});

describe("v1alpha3 capabilities", () => {
  const capability = (name: string, value: unknown) =>
    personal({ capabilities: { [name]: value } });
  it("parses model requirements and records only what is declared", () => {
    const [, workflow, checkpoint] = governance(
      personal({
        capabilities: {
          workflow: {
            enabled: true,
            requirements: {
              tools: true,
              structuredOutput: true,
              minContextWindow: 64000,
              input: ["text", "image"],
            },
          },
          checkpoint: { enabled: false },
        },
      }),
    ).capabilities;
    expect(workflow?.requirements).toEqual({
      tools: true,
      structuredOutput: true,
      minContextWindow: 64000,
      input: ["text", "image"],
    });
    expect(checkpoint).not.toHaveProperty("requirements");
    const [, partial] = governance(
      capability("workflow", {
        enabled: true,
        requirements: { minContextWindow: 32000 },
      }),
    ).capabilities;
    expect(partial?.requirements).toEqual({ minContextWindow: 32000 });
  });
  it.each([
    [{}, "capabilities.workflow.requirements", "at least one"],
    [
      { tools: "yes" },
      "capabilities.workflow.requirements.tools",
      "true or false",
    ],
    [
      { minContextWindow: 0 },
      "capabilities.workflow.requirements.minContextWindow",
      "positive integer",
    ],
    [
      { input: ["audio"] },
      "capabilities.workflow.requirements.input[0]",
      "text, image",
    ],
    [
      { input: [] },
      "capabilities.workflow.requirements.input",
      "at least one input",
    ],
    [
      { input: ["text", "text"] },
      "capabilities.workflow.requirements.input[1]",
      "Duplicate",
    ],
    [
      { reasoning: true },
      "capabilities.workflow.requirements.reasoning",
      "Unknown field",
    ],
    [
      { apiKey: "sk-x" },
      "capabilities.workflow.requirements.apiKey",
      "Secrets are never declared",
    ],
  ])("rejects model requirements %j", (requirements, field, message) => {
    rejects(
      capability("workflow", { enabled: true, requirements }),
      field,
      message,
    );
  });
  it("rejects unknown capability names", () => {
    rejects(
      capability("telepathy", { enabled: true }),
      "capabilities.telepathy",
      "Unknown field",
    );
  });
  it("requires an explicit enabled flag", () => {
    rejects(
      capability("workflow", { provider: { id: "builtin/workflow" } }),
      "capabilities.workflow.enabled",
    );
    rejects(
      capability("workflow", { enabled: "yes" }),
      "capabilities.workflow.enabled",
    );
  });
  it("defaults an enabled capability to its builtin provider", () => {
    const [, workflow] = governance(
      capability("workflow", { enabled: true }),
    ).capabilities;
    expect(workflow?.provider?.id).toBe("builtin/workflow");
  });
  it("disables permissions when declared off", () => {
    const [permissions] = governance(
      capability("permissions", { enabled: false }),
    ).capabilities;
    expect(permissions).toEqual({
      name: "permissions",
      enabled: false,
      settings: {},
    });
  });
  it("requires a provider when no builtin implements the contract", () => {
    rejects(
      capability("checkpoint", { enabled: true }),
      "capabilities.checkpoint.provider",
      "No builtin provider",
    );
  });
  it.each([
    ["builtin/unknown", "Unknown builtin provider"],
    ["builtin/workflow", "does not implement"],
    ["upstream/permissions", "no upstream capability providers"],
    ["project/perm", "Expected <class>/<name>"],
    ["enterprise/perm", "Expected <class>/<name>"],
    ["company", "Expected <class>/<name>"],
    ["company/perm/extra", "Expected <class>/<name>"],
    ["company/Perm", "Expected <class>/<name>"],
    ["Builtin/permissions", "Expected <class>/<name>"],
  ])("rejects provider id %s", (id, message) => {
    rejects(
      capability("permissions", { enabled: true, provider: { id } }),
      "capabilities.permissions.provider.id",
      message,
    );
  });
  it("rejects extra fields on builtin providers", () => {
    rejects(
      capability("permissions", {
        enabled: true,
        provider: { id: "builtin/permissions", path: "./p" },
      }),
      "capabilities.permissions.provider.path",
      "declare only id",
    );
    rejects(
      capability("permissions", {
        enabled: true,
        provider: { id: "builtin/permissions", version: "9.9.9" },
      }),
      "capabilities.permissions.provider.version",
    );
  });
  const company = (patch: Json) => ({
    enabled: true,
    provider: {
      id: "company/perm-plus",
      version: "2.3.1",
      implements: ["piship.capability/permissions/v1"],
      path: "./providers/perm-plus",
      ...patch,
    },
  });
  it("accepts user providers and newer contract majors", () => {
    const [permissions] = governance(
      capability(
        "permissions",
        company({
          id: "user/perm",
          implements: [
            "piship.capability/permissions/v2",
            "piship.capability/audit-hooks/v1",
          ],
        }),
      ),
    ).capabilities;
    expect(permissions?.provider?.class).toBe("user");
  });
  it.each([
    ["version", { version: undefined }, "non-empty"],
    ["version", { version: "2.x" }, "SemVer"],
    ["implements", { implements: undefined }, "List the capability"],
    ["implements", { implements: [] }, "must implement"],
    [
      "implements",
      { implements: ["piship.capability/workflow/v1"] },
      "must implement piship.capability/permissions",
    ],
    [
      "implements[0]",
      { implements: ["piship.capability/permissions"] },
      "contract ID",
    ],
    [
      "implements[0]",
      { implements: ["piship.capability/permissions/v0"] },
      "contract ID",
    ],
    [
      "implements[1]",
      {
        implements: [
          "piship.capability/permissions/v1",
          "piship.capability/permissions/v1",
        ],
      },
      "Duplicate",
    ],
    ["path", { path: undefined }, "./ path"],
    ["path", { path: "../perm" }, "without traversal"],
    ["source", { source: "https://x.example" }, "Unknown field"],
    ["integrity", { integrity: INTEGRITY }, "Unknown field"],
  ])("validates non-builtin provider field %s", (field, patch, message) => {
    rejects(
      capability("permissions", company(patch)),
      `capabilities.permissions.provider.${field}`,
      message,
    );
  });
  it("requires evidence on certified providers", () => {
    const base = {
      id: "certified/perm",
      source: "npm:perm@1.0.0",
      integrity: INTEGRITY,
      license: "MIT",
      pi: ["0.87.1"],
    };
    expect(
      governance(capability("permissions", company(base))).capabilities[0]
        ?.provider?.certified?.integrity,
    ).toBe(INTEGRITY);
    for (const field of ["source", "integrity", "license", "pi"])
      rejects(
        capability("permissions", company({ ...base, [field]: undefined })),
        `capabilities.permissions.provider.${field}`,
      );
    rejects(
      capability(
        "permissions",
        company({ ...base, integrity: "sha256-deadbeef" }),
      ),
      "capabilities.permissions.provider.integrity",
    );
  });
  it("validates settings", () => {
    rejects(
      capability("workflow", {
        enabled: true,
        settings: { apiKey: "abc" },
      }),
      "capabilities.workflow.settings.apiKey",
      "Secrets are never declared",
    );
    rejects(
      capability("workflow", { enabled: true, settings: { mode: 3 } }),
      "capabilities.workflow.settings.mode",
    );
    rejects(
      capability("workflow", {
        enabled: true,
        settings: { "plan-prompt": "x" },
      }),
      "capabilities.workflow.settings.plan-prompt",
    );
    rejects(
      capability("workflow", {
        enabled: true,
        settings: { planPrompt: `\${PROMPT}` },
      }),
      "capabilities.workflow.settings.planPrompt",
      "Runtime references",
    );
    rejects(
      capability("workflow", {
        enabled: true,
        settings: { planPrompt: "a\u0007b" },
      }),
      "capabilities.workflow.settings.planPrompt",
      "Control characters",
    );
  });
});

describe("v1alpha3 policy", () => {
  const policy = (value: Json, mode: "personal" | "managed" = "personal") =>
    mode === "managed"
      ? managed({ policy: value })
      : personal({ policy: value });
  it.each(["allow", "ask", "deny"])("accepts default %s", (effect) => {
    expect(governance(policy({ default: effect })).policy.default).toBe(effect);
  });
  it.each([
    [{ default: "block" }, "policy.default"],
    [{ id: "Acme Policy" }, "policy.id"],
    [{ version: 0 }, "policy.version"],
    [{ version: 1.5 }, "policy.version"],
    [{ version: "3" }, "policy.version"],
    [{ adapter: "../policy.mjs" }, "policy.adapter"],
    [{ adapter: "./policy.ts" }, "policy.adapter"],
    [{ resourceTrust: { user: "ask" } }, "policy.resourceTrust.user"],
    [{ resourceTrust: { project: "maybe" } }, "policy.resourceTrust.project"],
    [{ resourceTrust: { vendor: "allow" } }, "policy.resourceTrust.vendor"],
    [{ providerTrust: { project: "allow" } }, "policy.providerTrust.project"],
    [{ providerTrust: { user: "policy" } }, "policy.providerTrust.user"],
    [{ enforced: {} }, "policy.enforced"],
    [{ unknownKey: 1 }, "policy.unknownKey"],
  ])("rejects invalid policy field %#", (value, field) => {
    rejects(policy(value), field);
  });
  const rule = (patch: Json) => ({
    id: "acme.rule",
    action: "tool.execute",
    effect: "deny",
    ...patch,
  });
  it.each([
    ["id", { id: undefined }],
    ["id", { id: "Acme.Rule" }],
    ["id", { id: ".hidden" }],
    ["id", { id: `a${"b".repeat(128)}` }],
    ["action", { action: "tool.run" }],
    ["action", { action: "unknown.*" }],
    ["action", { action: "tool.execute.*" }],
    ["action", { action: "mcp.server.start.*" }],
    ["action", { action: "**" }],
    ["action", { action: undefined }],
    ["effect", { effect: "block" }],
    ["effect", { effect: "company-approved" }],
    ["resource", { resource: "" }],
    ["resource", { resource: "a\nb" }],
    ["reason", { reason: "x".repeat(241) }],
    ["priority", { priority: 1 }],
  ])("rejects invalid rule field %s (%#)", (field, patch) => {
    rejects(policy({ enforced: [rule(patch)] }), `policy.enforced[0].${field}`);
  });
  it.each(["mcp.*", "mcp.server.*", "memory.*", "filesystem.*", "*"])(
    "accepts wildcard action %s",
    (action) => {
      expect(
        governance(policy({ defaults: [rule({ action })] })).policy.defaults[0]
          ?.action,
      ).toBe(action);
    },
  );
  it("defaults the resource glob to **", () => {
    expect(
      governance(policy({ enforced: [rule({})] })).policy.enforced[0],
    ).toEqual({
      id: "acme.rule",
      action: "tool.execute",
      resource: "**",
      effect: "deny",
    });
  });
  it("requires rule IDs unique across enforced and defaults", () => {
    rejects(
      policy({ enforced: [rule({}), rule({})] }),
      "policy.enforced[1]",
      "Duplicate",
    );
    rejects(
      policy({ enforced: [rule({})], defaults: [rule({ effect: "allow" })] }),
      "policy.defaults[0].id",
      "already used in policy.enforced",
    );
  });
  it("fills partial trust with mode defaults", () => {
    const result = governance(
      policy({ resourceTrust: { company: "deny" } }, "managed"),
    ).policy;
    expect(result.resourceTrust.company).toBe("deny");
    expect(result.resourceTrust.user).toBe("deny");
    expect(result.providerTrust.user).toBe("deny");
  });
  const trust = (value: Json) => policy({ projectTrust: value });
  it("keeps a matcher that requires both a remote and a path", () => {
    const result = governance(
      trust({
        company: {
          match: [{ remote: "git.acme.example/**", path: "/srv/**" }],
        },
      }),
    ).policy.projectTrust;
    expect(result.company.match).toEqual([
      { remote: "git.acme.example/**", path: "/srv/**" },
    ]);
  });
  it("fills partial project trust dimensions with mode defaults", () => {
    const result = governance(
      policy({ projectTrust: { unknown: { mcp: "deny" } } }),
    ).policy.projectTrust;
    expect(result.unknown.dimensions.mcp).toBe("deny");
    expect(result.unknown.dimensions.skills).toBe("ask");
  });
  it.each([
    [
      { unknown: { match: [{ path: "/x" }] } },
      "policy.projectTrust.unknown.match",
    ],
    [{ project: {} }, "policy.projectTrust.project"],
    [{ company: { hooks: "maybe" } }, "policy.projectTrust.company.hooks"],
    [{ company: { plugins: "allow" } }, "policy.projectTrust.company.plugins"],
    [{ company: { match: [{}] } }, "policy.projectTrust.company.match[0]"],
    [
      { company: { match: [{ remote: "a/**", path: "relative/**" }] } },
      "policy.projectTrust.company.match[0].path",
    ],
    [
      { company: { match: [{ remote: "https://git.acme.example/**" }] } },
      "policy.projectTrust.company.match[0].remote",
    ],
    [
      { company: { match: [{ remote: "user@git.acme.example/**" }] } },
      "policy.projectTrust.company.match[0].remote",
    ],
    [
      { company: { match: [{ remote: "git.acme.example/app.git" }] } },
      "policy.projectTrust.company.match[0].remote",
    ],
    [
      { external: { match: [{ path: "relative/**" }] } },
      "policy.projectTrust.external.match[0].path",
    ],
    [
      { external: { match: [{ path: "/opt/../etc/**" }] } },
      "policy.projectTrust.external.match[0].path",
    ],
    [
      { external: { match: [{ glob: "/opt/**" }] } },
      "policy.projectTrust.external.match[0].glob",
    ],
  ])("rejects invalid project trust %#", (value, field) => {
    rejects(trust(value), field);
  });
});

describe("v1alpha3 MCP", () => {
  const mcp = (value: Json, mode: "personal" | "managed" = "personal") =>
    mode === "managed" ? managed({ mcp: value }) : personal({ mcp: value });
  const server = (value: Json, extra: Json = {}) =>
    mcp({ servers: { docs: value }, ...extra });
  it("accepts every personal mode and restricts managed modes", () => {
    for (const mode of ["off", "allowlist", "explicit"])
      expect(governance(mcp({ mode })).mcp.mode).toBe(mode);
    expect(governance(mcp({ mode: "off" }, "managed")).mcp.mode).toBe("off");
    rejects(
      mcp({ mode: "explicit" }, "managed"),
      "mcp.mode",
      "off or allowlist",
    );
    rejects(mcp({ mode: "open" }), "mcp.mode");
  });
  it("rejects servers when MCP is off", () => {
    rejects(
      server({ transport: "stdio", command: "docs" }, { mode: "off" }),
      "mcp.servers",
      "off cannot declare servers",
    );
  });
  it.each([
    [{ project: "ask" }, "mcp.project"],
    [{ user: "policy" }, "mcp.user"],
    [{ servers: [] }, "mcp.servers"],
    [{ registry: "https://x.example" }, "mcp.registry"],
  ])("rejects invalid MCP field %#", (value, field) => {
    rejects(mcp(value), field);
  });
  it.each(["Docs", "1docs", "docs_server", "a".repeat(33), "docs.server"])(
    "rejects server id %s",
    (id) => {
      rejects(
        mcp({ servers: { [id]: { transport: "stdio", command: "docs" } } }),
        `mcp.servers.${id}`,
      );
    },
  );
  it.each(["sse", "http+sse", "http-sse"])(
    "rejects legacy transport %s",
    (transport) => {
      rejects(
        server({ transport, url: "https://x.example/sse" }),
        "mcp.servers.docs.transport",
        "Legacy HTTP+SSE",
      );
    },
  );
  it("requires a known transport", () => {
    rejects(server({ command: "docs" }), "mcp.servers.docs.transport");
    rejects(
      server({ transport: "websocket", command: "docs" }),
      "mcp.servers.docs.transport",
    );
  });
  it.each([
    [
      { transport: "stdio" },
      "mcp.servers.docs",
      "exactly one of module or command",
    ],
    [
      { transport: "stdio", module: "./a.mjs", command: "a" },
      "mcp.servers.docs",
      "exactly one of module or command",
    ],
    [
      { transport: "stdio", module: "./a.ts" },
      "mcp.servers.docs.module",
      ".mjs or .js",
    ],
    [
      { transport: "stdio", module: "../a.mjs" },
      "mcp.servers.docs.module",
      "without traversal",
    ],
    [
      { transport: "stdio", module: "/usr/lib/a.mjs" },
      "mcp.servers.docs.module",
      "without traversal",
    ],
    [
      { transport: "stdio", command: "/usr/bin/docs" },
      "mcp.servers.docs.command",
      "without path separators",
    ],
    [
      { transport: "stdio", command: "./docs" },
      "mcp.servers.docs.command",
      "without path separators",
    ],
    [
      { transport: "stdio", command: "bin\\docs" },
      "mcp.servers.docs.command",
      "without path separators",
    ],
    [
      { transport: "stdio", command: "docs; rm -rf ~" },
      "mcp.servers.docs.command",
      "without path separators",
    ],
    [
      { transport: "stdio", command: "..", args: [] },
      "mcp.servers.docs.command",
      "without path separators",
    ],
    [
      { transport: "stdio", command: "docs", url: "https://x.example" },
      "mcp.servers.docs.url",
      "streamable-http",
    ],
    [
      { transport: "stdio", command: "docs", credential: "runtime" },
      "mcp.servers.docs.credential",
      "streamable-http servers only",
    ],
    [
      { transport: "stdio", command: "docs", credential: "bearer" },
      "mcp.servers.docs.credential",
      "none, runtime",
    ],
    [
      { transport: "stdio", command: "docs", args: "--x" },
      "mcp.servers.docs.args",
      "Expected a list",
    ],
    [
      { transport: "stdio", command: "docs", args: [`\${HOME}`] },
      "mcp.servers.docs.args[0]",
      "Runtime references",
    ],
    [
      {
        transport: "stdio",
        command: "docs",
        args: ["--key", "sk-abcdefghijkl"],
      },
      "mcp.servers.docs.args[1]",
      "secret material",
    ],
  ])("validates stdio servers %#", (value, field, message) => {
    rejects(server(value), field, message);
  });
  it.each([
    [{ transport: "streamable-http" }, "mcp.servers.docs.url", "needs a url"],
    [
      { transport: "streamable-http", url: "http://x.example/mcp" },
      "mcp.servers.docs.url",
      "https",
    ],
    [
      { transport: "streamable-http", url: "https://u:p@x.example/mcp" },
      "mcp.servers.docs.url",
      "credentials",
    ],
    [
      { transport: "streamable-http", url: "https://x.example/mcp?token=abc" },
      "mcp.servers.docs.url",
      "query strings",
    ],
    [
      { transport: "streamable-http", url: `\${DOCS_URL}` },
      "mcp.servers.docs.url",
      "not declared in variables",
    ],
    [
      { transport: "streamable-http", url: `\${DOCS_TOKEN}` },
      "mcp.servers.docs.url",
      "looks like secret material",
    ],
    [
      { transport: "streamable-http", url: "https://x.example", command: "x" },
      "mcp.servers.docs.command",
      "stdio servers",
    ],
    [
      {
        transport: "streamable-http",
        url: "https://x.example",
        module: "./x.mjs",
      },
      "mcp.servers.docs.module",
      "stdio servers",
    ],
    [
      { transport: "streamable-http", url: "https://x.example", args: [] },
      "mcp.servers.docs.args",
      "stdio servers",
    ],
    [
      {
        transport: "streamable-http",
        url: "https://x.example",
        env: { allow: ["LANG"] },
      },
      "mcp.servers.docs.env",
      "stdio servers",
    ],
  ])("validates streamable-http servers %#", (value, field, message) => {
    rejects(server(value), field, message);
  });
  it("accepts a loopback http endpoint", () => {
    expect(
      governance(
        server({
          transport: "streamable-http",
          url: "http://127.0.0.1:9000/mcp",
        }),
      ).mcp.servers[0]?.url,
    ).toBe("http://127.0.0.1:9000/mcp");
  });
  const stdio = (extra: Json) =>
    server({ transport: "stdio", command: "docs", ...extra });
  it.each([
    [{ env: { allow: ["GITHUB_TOKEN"] } }, "mcp.servers.docs.env.allow[0]"],
    [
      { env: { allow: ["AWS_SECRET_ACCESS_KEY"] } },
      "mcp.servers.docs.env.allow[0]",
    ],
    [{ env: { allow: ["OPENAI_API_KEY"] } }, "mcp.servers.docs.env.allow[0]"],
    [{ env: { allow: ["DB_PASSWORD"] } }, "mcp.servers.docs.env.allow[0]"],
    [{ env: { allow: ["NPM_AUTH"] } }, "mcp.servers.docs.env.allow[0]"],
    [{ env: { allow: ["lang"] } }, "mcp.servers.docs.env.allow[0]"],
    [{ env: { allow: ["LANG", "LANG"] } }, "mcp.servers.docs.env.allow[1]"],
    [
      { env: { set: { DOCS_TOKEN: "abc" } } },
      "mcp.servers.docs.env.set.DOCS_TOKEN",
    ],
    [
      { env: { set: { AZURE_CREDENTIALS: "x" } } },
      "mcp.servers.docs.env.set.AZURE_CREDENTIALS",
    ],
    [
      { env: { set: { "bad-name": "x" } } },
      "mcp.servers.docs.env.set.bad-name",
    ],
    [{ env: { set: { DOCS_MODE: 1 } } }, "mcp.servers.docs.env.set.DOCS_MODE"],
    [
      { env: { set: { DOCS_MODE: `\${MODE}` } } },
      "mcp.servers.docs.env.set.DOCS_MODE",
    ],
    [
      { env: { set: { DOCS_MODE: "Bearer abcdefghijkl" } } },
      "mcp.servers.docs.env.set.DOCS_MODE",
    ],
    [
      { env: { set: { DOCS_MODE: "ghp_abcdefghijklmnop1234" } } },
      "mcp.servers.docs.env.set.DOCS_MODE",
    ],
    [
      { env: { set: { DOCS_MODE: "AKIAABCDEFGHIJKLMNOP" } } },
      "mcp.servers.docs.env.set.DOCS_MODE",
    ],
    [
      { env: { allow: ["LANG"], set: { LANG: "C" } } },
      "mcp.servers.docs.env.set.LANG",
    ],
    [{ env: { inherit: true } }, "mcp.servers.docs.env.inherit"],
    [{ timeout: "30 seconds" }, "mcp.servers.docs.timeout"],
    [{ timeout: "0s" }, "mcp.servers.docs.timeout"],
    [{ startupTimeout: -1 }, "mcp.servers.docs.startupTimeout"],
    [{ retry: { attempts: 0 } }, "mcp.servers.docs.retry.attempts"],
    [{ retry: { attempts: 11 } }, "mcp.servers.docs.retry.attempts"],
    [{ retry: { backoff: "1s" } }, "mcp.servers.docs.retry.backoff"],
    [{ required: "yes" }, "mcp.servers.docs.required"],
    [{ expectedServerName: "a\nb" }, "mcp.servers.docs.expectedServerName"],
    [{ tools: { allow: ["bad tool"] } }, "mcp.servers.docs.tools.allow[0]"],
    [
      { tools: { allow: ["search"], deny: ["search"] } },
      "mcp.servers.docs.tools.deny[0]",
    ],
    [{ tools: { only: ["x"] } }, "mcp.servers.docs.tools.only"],
    [{ headers: { Authorization: "x" } }, "mcp.servers.docs.headers"],
    [{ apiKey: "x" }, "mcp.servers.docs.apiKey"],
  ])("validates server settings %#", (extra, field) => {
    rejects(stdio(extra), field);
  });
  it("names secret-looking server fields as secrets", () => {
    rejects(
      stdio({ bearerToken: "x" }),
      "mcp.servers.docs.bearerToken",
      "Secrets",
    );
  });
  it("accepts integer-second durations", () => {
    expect(governance(stdio({ timeout: 45 })).mcp.servers[0]?.timeoutMs).toBe(
      45000,
    );
  });
});

describe("v1alpha3 sandbox", () => {
  const sandbox = (value: Json) => personal({ sandbox: value });
  it("rejects a hostname allowlist at the sandbox boundary", () => {
    rejects(
      sandbox({ network: { mode: "allowlist" } }),
      "sandbox.network.mode",
      "Hostname allowlists are not enforced",
    );
    rejects(
      sandbox({ network: { mode: "deny", allowHosts: ["x.example"] } }),
      "sandbox.network.allowHosts",
      "Hostname allowlists are not enforced",
    );
    rejects(
      sandbox({ network: { allow: ["x.example"] } }),
      "sandbox.network.allow",
      "Hostname allowlists are not enforced",
    );
  });
  it("accepts explicit network modes independent of required", () => {
    expect(
      governance(sandbox({ required: true, network: { mode: "allow" } }))
        .sandbox.network.mode,
    ).toBe("allow");
    expect(
      governance(sandbox({ network: { mode: "deny" } })).sandbox.network.mode,
    ).toBe("deny");
  });
  it("accepts path tokens and absolute paths", () => {
    const result = governance(
      sandbox({
        filesystem: {
          read: { deny: ["~", "~/.config/app", "/var/secrets"] },
          write: { allow: ["workspace/out", "tmp/app", "/scratch"] },
        },
      }),
    ).sandbox.filesystem;
    expect(result.read.deny).toEqual(["~", "~/.config/app", "/var/secrets"]);
    expect(result.write.allow).toEqual([
      "workspace/out",
      "tmp/app",
      "/scratch",
    ]);
  });
  it("allows an empty write allowlist", () => {
    expect(
      governance(sandbox({ filesystem: { write: { allow: [] } } })).sandbox
        .filesystem.write.allow,
    ).toEqual([]);
  });
  it.each([
    [{ required: "true" }, "sandbox.required"],
    [{ network: { mode: "open" } }, "sandbox.network.mode"],
    [
      { filesystem: { read: { allow: ["/"] } } },
      "sandbox.filesystem.read.allow",
    ],
    [
      { filesystem: { write: { deny: ["/"] } } },
      "sandbox.filesystem.write.deny",
    ],
    [{ filesystem: { exec: {} } }, "sandbox.filesystem.exec"],
    [
      { filesystem: { write: { allow: ["workspace/../.."] } } },
      "sandbox.filesystem.write.allow[0]",
    ],
    [
      { filesystem: { write: { allow: ["./build"] } } },
      "sandbox.filesystem.write.allow[0]",
    ],
    [
      { filesystem: { write: { allow: ["workspaces"] } } },
      "sandbox.filesystem.write.allow[0]",
    ],
    [
      { filesystem: { read: { deny: ["~user/.ssh"] } } },
      "sandbox.filesystem.read.deny[0]",
    ],
    [
      { filesystem: { read: { deny: ["C:\\Users\\me"] } } },
      "sandbox.filesystem.read.deny[0]",
    ],
    [
      { filesystem: { read: { deny: [`\${HOME}/.ssh`] } } },
      "sandbox.filesystem.read.deny[0]",
    ],
    [
      { filesystem: { read: { deny: ["/a//b"] } } },
      "sandbox.filesystem.read.deny[0]",
    ],
    [{ environment: { allow: ["GH_TOKEN"] } }, "sandbox.environment.allow[0]"],
    [{ environment: { allow: ["path"] } }, "sandbox.environment.allow[0]"],
    [{ environment: { set: { A: "b" } } }, "sandbox.environment.set"],
    [{ mode: "strict" }, "sandbox.mode"],
  ])("rejects invalid sandbox field %#", (value, field) => {
    rejects(sandbox(value), field);
  });
});

describe("sandbox backends", () => {
  const withSandbox = (value: Json) =>
    managed({
      variables: [
        ...managedAccess.variables,
        ...["ACME_SANDBOX_URL", "ACME_ROUTER_URL"].filter((name) =>
          JSON.stringify(value).includes(name),
        ),
      ],
      sandbox: value,
    });
  it("defaults to the native provider without adding fields", () => {
    const result = governance(withSandbox({ required: true })).sandbox;
    expect(result).not.toHaveProperty("provider");
    expect(
      governance(withSandbox({ required: true, provider: "native" })).sandbox,
    ).toEqual(result);
  });
  it("accepts an e2b-compatible backend with a runtime endpoint", () => {
    expect(
      governance(
        withSandbox({
          required: true,
          provider: "e2b-compatible",
          endpoint: `\${ACME_SANDBOX_URL}`,
          template: "piship-workspace",
          workdir: "/workspace/repo",
          credential: "runtime",
        }),
      ).sandbox,
    ).toMatchObject({
      required: true,
      provider: "e2b-compatible",
      endpoint: `\${ACME_SANDBOX_URL}`,
      template: "piship-workspace",
      workdir: "/workspace/repo",
      credential: "runtime",
      network: { mode: "deny" },
    });
  });
  it("accepts credential: stored for every remote provider, and keeps none out of the parsed (and locked) section", () => {
    const e2b = {
      required: true,
      provider: "e2b-compatible",
      endpoint: `\${ACME_SANDBOX_URL}`,
    };
    expect(
      governance(withSandbox({ ...e2b, credential: "stored" })).sandbox
        .credential,
    ).toBe("stored");
    expect(
      governance(
        withSandbox({
          required: true,
          provider: "kubernetes-agent-sandbox",
          endpoint: "https://k8s.example.com",
          router: `\${ACME_ROUTER_URL}`,
          template: "python-pool",
          credential: "stored",
        }),
      ).sandbox.credential,
    ).toBe("stored");
    expect(
      governance(
        withSandbox({
          required: true,
          provider: "custom",
          adapter: "./sandbox/acme-sandbox.mjs",
          endpoint: "https://sandbox.acme.example",
          credential: "stored",
        }),
      ).sandbox.credential,
    ).toBe("stored");
    // `none` parses to the same section as an omitted field, so the lock's
    // sandbox digest changes only for a manifest that uses a credential.
    expect(
      governance(withSandbox({ ...e2b, credential: "none" })).sandbox,
    ).toEqual(governance(withSandbox(e2b)).sandbox);
    expect(
      governance(withSandbox({ ...e2b, credential: "stored" })).sandbox,
    ).not.toEqual(governance(withSandbox(e2b)).sandbox);
  });
  it.each([
    [{ required: true, credential: "stored" }, "sandbox.credential"],
    [
      {
        required: true,
        provider: "custom",
        adapter: "./sandbox/acme-sandbox.mjs",
        credential: "stored",
      },
      "sandbox.endpoint",
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://s.example.com",
        credential: "Stored",
      },
      "sandbox.credential",
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://s.example.com",
        credential: { stored: "fake-secret-value-0001" },
      },
      "sandbox.credential",
    ],
  ])(
    "rejects a stored credential where it cannot be used %#",
    (value, field) => {
      rejects(withSandbox(value), field);
    },
  );
  it("accepts an e2b-compatible user, such as root for CubeSandbox, and keeps the E2B default otherwise", () => {
    const cube = governance(
      withSandbox({
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://cube.acme.example",
        user: "root",
      }),
    ).sandbox;
    expect(cube.user).toBe("root");
    const e2bDefault = governance(
      withSandbox({
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://api.e2b.app",
      }),
    ).sandbox;
    expect(e2bDefault).not.toHaveProperty("user");
  });
  it("accepts a kubernetes-agent-sandbox backend and a custom adapter", () => {
    expect(
      governance(
        withSandbox({
          required: true,
          provider: "kubernetes-agent-sandbox",
          endpoint: "https://k8s.example.com",
          router: `\${ACME_ROUTER_URL}`,
          namespace: "agents",
          template: "python-pool",
        }),
      ).sandbox,
    ).toMatchObject({
      provider: "kubernetes-agent-sandbox",
      router: `\${ACME_ROUTER_URL}`,
      namespace: "agents",
      template: "python-pool",
    });
    const custom = governance(
      withSandbox({
        required: true,
        provider: "custom",
        adapter: "./sandbox/acme-sandbox.mjs",
      }),
    ).sandbox;
    expect(custom).toMatchObject({
      provider: "custom",
      adapter: "./sandbox/acme-sandbox.mjs",
    });
    expect(custom).not.toHaveProperty("credential");
  });
  it.each([
    [
      { provider: "e2b-compatible", endpoint: "https://sandbox.example.com" },
      "sandbox.provider",
      "set sandbox.required: true",
    ],
    [
      { required: true, provider: "firecracker" },
      "sandbox.provider",
      undefined,
    ],
    [
      { required: true, provider: "e2b-compatible" },
      "sandbox.endpoint",
      "needs an endpoint",
    ],
    [
      { required: true, provider: "custom" },
      "sandbox.adapter",
      "needs an adapter module",
    ],
    [
      { required: true, provider: "custom", adapter: "/abs/adapter.mjs" },
      "sandbox.adapter",
      undefined,
    ],
    [
      { required: true, endpoint: "https://sandbox.example.com" },
      "sandbox.endpoint",
      "applies only to",
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://s.example.com",
        router: "https://r.example.com",
      },
      "sandbox.router",
      "kubernetes-agent-sandbox",
    ],
    [
      {
        required: true,
        provider: "kubernetes-agent-sandbox",
        endpoint: "https://k.example.com",
        template: "pool",
      },
      "sandbox.router",
      "router URL",
    ],
    [
      {
        required: true,
        provider: "kubernetes-agent-sandbox",
        endpoint: "https://k.example.com",
        router: "https://r.example.com",
      },
      "sandbox.template",
      "warm pool",
    ],
    [
      {
        required: true,
        provider: "kubernetes-agent-sandbox",
        endpoint: "https://k.example.com",
        router: "https://r.example.com",
        template: "Pool_1",
      },
      "sandbox.template",
      "Kubernetes resource name",
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "http://sandbox.example.com",
      },
      "sandbox.endpoint",
      undefined,
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: `\${UNDECLARED_URL}`,
      },
      "sandbox.endpoint",
      "not declared",
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://s.example.com",
        credential: "api-key",
      },
      "sandbox.credential",
      undefined,
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://s.example.com",
        workdir: "repo",
      },
      "sandbox.workdir",
      "absolute POSIX path",
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://s.example.com",
        apiKey: "e2b_x",
      },
      "sandbox.apiKey",
      "Secrets are never declared",
    ],
    [{ required: true, user: "root" }, "sandbox.user", "e2b-compatible"],
    [
      { required: true, provider: "native", user: "root" },
      "sandbox.user",
      "e2b-compatible",
    ],
    [
      {
        required: true,
        provider: "custom",
        adapter: "./sandbox/a.mjs",
        user: "root",
      },
      "sandbox.user",
      "e2b-compatible",
    ],
    [
      {
        required: true,
        provider: "kubernetes-agent-sandbox",
        endpoint: "https://k.example.com",
        router: "https://r.example.com",
        template: "pool",
        user: "root",
      },
      "sandbox.user",
      "e2b-compatible",
    ],
    [
      {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://s.example.com",
        user: "Root User",
      },
      "sandbox.user",
      "POSIX user name",
    ],
  ])("rejects %j at %s", (value, field, message) => {
    rejects(withSandbox(value as Json), field, message);
  });
});

describe("v1alpha3 audit", () => {
  const audit = (value: Json, mode: "personal" | "managed" = "personal") =>
    mode === "managed" ? managed({ audit: value }) : personal({ audit: value });
  it("enables a default file sink when audit is turned on", () => {
    expect(governance(audit({ enabled: true })).audit.sinks).toEqual([
      { id: "local", type: "file", required: false },
    ]);
  });
  it("allows managed distributions to disable audit", () => {
    expect(
      governance(audit({ enabled: false }, "managed")).audit,
    ).toMatchObject({ enabled: false, sinks: [] });
  });
  it("accepts a loopback http sink", () => {
    expect(
      governance(
        audit({
          enabled: true,
          sinks: [{ id: "dev", type: "http", url: "http://localhost:9000/e" }],
        }),
      ).audit.sinks[0],
    ).toEqual({
      id: "dev",
      type: "http",
      url: "http://localhost:9000/e",
      required: false,
    });
  });
  it.each([
    [{ enabled: true, sinks: [] }, "audit.sinks", "at least one sink"],
    [{ enabled: "yes" }, "audit.enabled", "true or false"],
    [{ sinks: {} }, "audit.sinks", "Expected a list"],
    [
      { sinks: [{ id: "x", type: "http" }] },
      "audit.sinks[0].url",
      "needs a url",
    ],
    [
      { sinks: [{ id: "x", type: "http", url: "http://audit.example/e" }] },
      "audit.sinks[0].url",
      "https",
    ],
    [
      { sinks: [{ id: "x", type: "http", url: `\${AUDIT_URL}` }] },
      "audit.sinks[0].url",
      "not declared",
    ],
    [
      { sinks: [{ id: "x", type: "file", url: "https://a.example" }] },
      "audit.sinks[0].url",
      "only to http sinks",
    ],
    [
      { sinks: [{ id: "x", type: "syslog" }] },
      "audit.sinks[0].type",
      "file, http",
    ],
    [{ sinks: [{ id: "X", type: "file" }] }, "audit.sinks[0].id", "lowercase"],
    [{ sinks: [{ type: "file" }] }, "audit.sinks[0].id", "non-empty"],
    [
      { sinks: [{ id: "x", type: "file", path: "/var/log/a" }] },
      "audit.sinks[0].path",
      "Unknown field",
    ],
    [
      { sinks: [{ id: "x", type: "file", token: "abc" }] },
      "audit.sinks[0].token",
      "Secrets",
    ],
    [
      {
        sinks: [
          { id: "x", type: "file" },
          { id: "x", type: "file" },
        ],
      },
      "audit.sinks[1]",
      "Duplicate",
    ],
    [
      { sinks: [{ id: "x", type: "file", required: 1 }] },
      "audit.sinks[0].required",
      "true or false",
    ],
    [
      { buffer: { maxEvents: 0 } },
      "audit.buffer.maxEvents",
      "positive integer",
    ],
    [{ buffer: { maxEvents: 2_000_000 } }, "audit.buffer.maxEvents", "at most"],
    [
      { buffer: { flushInterval: "2 s" } },
      "audit.buffer.flushInterval",
      "duration",
    ],
    [
      { buffer: { flushInterval: 0 } },
      "audit.buffer.flushInterval",
      "greater than zero",
    ],
    [{ buffer: { size: 1 } }, "audit.buffer.size", "Unknown field"],
    [
      { capture: { promptContent: "true" } },
      "audit.capture.promptContent",
      "true or false",
    ],
    [{ capture: { tokens: true } }, "audit.capture.tokens", "Secrets"],
    [
      { capture: { toolOutput: true } },
      "audit.capture.toolOutput",
      "Unknown field",
    ],
  ])("rejects invalid audit field %#", (value, field, message) => {
    rejects(audit(value), field, message);
  });
});

describe("migration to piship/v1alpha3", () => {
  const v1 =
    'schema: piship/v1alpha1\n# keep comments\napp:\n  id: mypi\n  name: MyPi\n  command: mypi\n  version: 1.0.0\nruntime:\n  pi: "0.87.1"\ndeployment:\n  mode: personal\nresources:\n  skills:\n    - ./skills\n  extensions: [./ext]\n';
  it("migrates v1alpha1 to v1alpha3 in steps", () => {
    const plan = migrateManifestSource(v1, PISHIP_SCHEMA_V1ALPHA3);
    expect(plan.from).toBe("piship/v1alpha1");
    expect(plan.to).toBe(PISHIP_SCHEMA_V1ALPHA3);
    expect(plan.changes[0]).toBe("schema: piship/v1alpha1 -> piship/v1alpha2");
    expect(plan.changes).toContain(
      "schema: piship/v1alpha2 -> piship/v1alpha3",
    );
    expect(plan.changes.at(-1)).toContain("Regenerate piship.lock");
    expect(plan.source).toContain("# keep comments");
    const manifest = parseManifest(yamlToJs(plan.source));
    expect(manifest.governance?.resources.declared).toEqual([
      { kind: "skills", class: "user", path: "./skills" },
      { kind: "extensions", class: "user", path: "./ext" },
    ]);
    expect(manifest.resources.skills).toEqual(["./skills"]);
    expect(
      migrateManifestSource(plan.source, PISHIP_SCHEMA_V1ALPHA3).changes,
    ).toEqual([]);
  });
  it("keeps a v1alpha2 target and does not downgrade", () => {
    const plan = migrateManifestSource(v1, PISHIP_SCHEMA_V1ALPHA2);
    expect(plan.to).toBe(PISHIP_SCHEMA_V1ALPHA2);
    expect(plan.source).not.toContain("policy");
    expect(plan.source).toContain("- ./skills");
    const v3 = migrateManifestSource(v1, PISHIP_SCHEMA_V1ALPHA3).source;
    expect(() => migrateManifestSource(v3, PISHIP_SCHEMA_V1ALPHA2)).toThrow(
      "downgrades are not supported",
    );
  });
  it("migrates a managed v1alpha2 manifest preserving behavior", () => {
    const source = [
      "schema: piship/v1alpha2",
      "app: { id: acmecode, name: AcmeCode, command: acmecode, version: 1.0.0 }",
      'runtime: { pi: "0.87.1" }',
      "deployment: { mode: managed }",
      "variables: [ACME_ISSUER, ACME_CLIENT_ID, ACME_GATEWAY_URL]",
      "identity:",
      "  mode: oidc",
      "  oidc:",
      `    issuer: \${ACME_ISSUER}`,
      `    clientId: \${ACME_CLIENT_ID}`,
      "    redirectUri: http://127.0.0.1:8765/callback",
      "credential: { provider: adapter, adapter: ./adapters/credential.mjs }",
      "inference:",
      "  provider: openai-compatible",
      `  baseUrl: \${ACME_GATEWAY_URL}`,
      "models:",
      "  default: acme/coder",
      "  allowed: [acme/coder]",
      "  catalog:",
      "    acme/coder: { name: Coder, contextWindow: 1000, maxOutputTokens: 100 }",
      "resources:",
      "  instructions: [./AGENTS.md]",
      "  # company skills",
      "  skills: [./skills]",
      "  prompts: []",
      "",
    ].join("\n");
    const plan = migrateManifestSource(source, PISHIP_SCHEMA_V1ALPHA3);
    expect(plan.from).toBe(PISHIP_SCHEMA_V1ALPHA2);
    expect(plan.changes).toEqual([
      "schema: piship/v1alpha2 -> piship/v1alpha3",
      "resources.instructions: flat list -> company trust class (managed distribution resources)",
      "resources.skills: flat list -> company trust class (managed distribution resources)",
      "resources.prompts: flat list -> company trust class (managed distribution resources)",
      "policy.default: allow (v1alpha2 had no tool policy)",
      "policy.projectTrust: project files stay tool-readable; project instructions, skills, extensions, themes, and MCP stay unloaded (as in v1alpha2)",
      "sandbox.required: false (v1alpha2 had no OS sandbox)",
      "audit.enabled: false (v1alpha2 had no audit log)",
      "mcp.mode: off (v1alpha2 had no MCP servers)",
      "Review the new governance defaults for managed mode: resource, provider, and project trust (policy.resourceTrust, policy.providerTrust, policy.projectTrust) and capabilities now apply",
      "Regenerate piship.lock with piship lock, then rebuild",
    ]);
    expect(plan.source).toContain("# company skills");
    const manifest = parseManifest(yamlToJs(plan.source));
    expect(manifest.resources).toEqual({
      instructions: ["./AGENTS.md"],
      skills: ["./skills"],
      extensions: [],
      prompts: [],
      themes: [],
    });
    expect(manifest.governance?.resources.declared.map((r) => r.class)).toEqual(
      ["company", "company"],
    );
    expect(manifest.governance?.policy.default).toBe("allow");
    for (const origin of ["company", "external", "unknown"] as const)
      expect(
        manifest.governance?.policy.projectTrust[origin].dimensions,
      ).toEqual({
        passiveContext: "deny",
        instructions: "deny",
        skills: "deny",
        agents: "deny",
        hooks: "deny",
        extensions: "deny",
        mcp: "deny",
        providers: "deny",
      });
    expect(manifest.governance?.sandbox.required).toBe(false);
    expect(manifest.governance?.sandbox.network.mode).toBe("allow");
    expect(manifest.governance?.audit).toMatchObject({
      enabled: false,
      sinks: [],
    });
    expect(manifest.governance?.mcp.mode).toBe("off");
    expect(manifest.access?.identity.mode).toBe("oidc");
  });
  it("leaves a v1alpha3 manifest unchanged", () => {
    const source =
      'schema: piship/v1alpha3\napp: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }\nruntime: { pi: "0.87.1" }\ndeployment: { mode: personal }\n';
    expect(migrateManifestSource(source, PISHIP_SCHEMA_V1ALPHA3)).toEqual({
      from: PISHIP_SCHEMA_V1ALPHA3,
      to: PISHIP_SCHEMA_V1ALPHA3,
      changes: [],
      source,
    });
  });
});

function yamlToJs(source: string): Json {
  return parseYaml(source) as Json;
}
