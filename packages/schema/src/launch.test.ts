import { redact } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import {
  droppedCredentialNames,
  inertDataPurge,
  inertTaskGrantHosts,
  inertTempRetention,
  launchWarnings,
  ManifestError,
  optionalHttpAuditSinks,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
  runtimeVariableUse,
  unknownMcpServerRules,
} from "./index.js";

type Json = Record<string, unknown>;

const catalog = {
  "acme/coder": {
    name: "Acme Coder",
    contextWindow: 128000,
    maxOutputTokens: 8192,
  },
};
/** A managed v1alpha4 manifest with plain https endpoints. */
function managed(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA4,
    app: {
      id: "acmecode",
      name: "AcmeCode",
      command: "acmecode",
      version: "1.0.0",
    },
    runtime: { pi: "1.5.0" },
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
    models: { default: "acme/coder", allowed: ["acme/coder"], catalog },
    updates: { channel: "stable", channels: ["stable"] },
    ...extra,
  };
}
function rejects(input: Json, field: string, message: string) {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).field).toBe(field);
  expect((error as ManifestError).message).toContain(message);
  // Diagnostic redaction must leave the guidance readable.
  expect(redact((error as ManifestError).message)).toBe(
    (error as ManifestError).message,
  );
}
function warnings(input: Json) {
  const found = launchWarnings(parseManifest(input));
  for (const { message } of found) expect(redact(message)).toBe(message);
  return found;
}

describe("network.tls.additionalCA paths", () => {
  it("warns about a relative bundle path, which is read from the launch directory", () => {
    for (const path of ["certs/acme.pem", "./certs/acme.pem", "~/acme.pem"])
      expect(
        warnings(managed({ network: { tls: { additionalCA: [path] } } })),
      ).toEqual([
        expect.objectContaining({
          path: "network.tls.additionalCA[0]",
          message: expect.stringContaining("absolute"),
        }),
      ]);
  });
  it("accepts absolute paths and a variable that supplies the whole path", () => {
    for (const path of [
      "/etc/acme/ca.pem",
      "C:\\ProgramData\\Acme\\ca.pem",
      `\${ACME_CA_BUNDLE}`,
    ])
      expect(
        warnings(
          managed({
            variables: path.startsWith("$") ? ["ACME_CA_BUNDLE"] : [],
            network: { tls: { additionalCA: [path] } },
          }),
        ),
      ).toEqual([]);
  });
  it("warns when a variable fills only part of a relative path", () => {
    expect(
      warnings(
        managed({
          variables: ["ACME_CA_NAME"],
          network: { tls: { additionalCA: [`certs/\${ACME_CA_NAME}.pem`] } },
        }),
      ).map((item) => item.path),
    ).toEqual(["network.tls.additionalCA[0]"]);
  });
});

describe("a required sandbox's endpoint under a private-only network policy", () => {
  const sandbox = (extra: Json = {}): Json =>
    managed({
      sandbox: {
        required: true,
        provider: "e2b-compatible",
        endpoint: "https://sandbox.acme.example",
      },
      ...extra,
    });
  it("warns that the policy refuses an undeclared endpoint host", () => {
    expect(warnings(sandbox())).toContainEqual({
      path: "sandbox.endpoint",
      message:
        "sandbox.acme.example is not in network.allowHosts, and the private-only network policy refuses it, so the required sandbox cannot start. Add sandbox.acme.example to network.allowHosts",
    });
  });
  it("says nothing once the host is allowed", () => {
    expect(
      warnings(
        sandbox({ network: { allowHosts: ["sandbox.acme.example"] } }),
      ).filter((item) => item.path.startsWith("sandbox.")),
    ).toEqual([]);
  });
});

describe("HTTP audit sinks under a private-only network policy", () => {
  const sink = (url: string, required = true): Json => ({
    audit: {
      enabled: true,
      sinks: [{ id: "siem", type: "http", url, required }],
    },
  });
  const personal = (extra: Json): Json => ({
    ...managed(extra),
    deployment: { mode: "personal" },
    identity: { mode: "none" },
    credential: { provider: "local-secret" },
    models: { default: "acme/coder", allowed: ["acme/coder"], catalog },
  });
  it("rejects a required sink whose host the launch can never contact", () => {
    rejects(
      managed(sink("https://siem.acme.example/events")),
      "audit.sinks[0].url",
      "siem.acme.example is not in network.allowHosts",
    );
    rejects(
      personal({
        ...sink("https://siem.acme.example/events"),
        network: { privateOnly: true },
      }),
      "audit.sinks[0].url",
      "network.allowHosts",
    );
  });
  it("accepts the sink host when it is allowed or is a declared endpoint host", () => {
    for (const extra of [
      {
        ...sink("https://siem.acme.example/events"),
        network: { allowHosts: ["siem.acme.example"] },
      },
      sink("https://gateway.acme.example/audit"),
      sink("https://siem.acme.example/events", false),
    ])
      expect(() => parseManifest(managed(extra))).not.toThrow();
    // Personal mode is not private-only unless it says so.
    expect(
      warnings(personal(sink("https://siem.acme.example/events"))),
    ).toEqual([]);
  });
  it("warns when the host is decided by a runtime variable or the sink is optional", () => {
    expect(
      warnings(managed(sink("https://siem.acme.example/events", false))),
    ).toEqual([
      expect.objectContaining({ path: "audit.sinks[0].required" }),
      expect.objectContaining({
        path: "audit.sinks[0].url",
        message: expect.stringContaining("dropped"),
      }),
    ]);
    expect(
      warnings(
        managed({
          variables: ["ACME_SIEM_URL"],
          ...sink(`\${ACME_SIEM_URL}`),
        }),
      ).map((item) => item.path),
    ).toEqual(["audit.sinks[0].url"]);
    // A templated endpoint may resolve to the sink's host; not certain.
    const templated = managed({
      variables: ["ACME_GATEWAY_URL"],
      ...sink("https://siem.acme.example/events"),
    });
    (templated.inference as Json).baseUrl = `\${ACME_GATEWAY_URL}`;
    expect(warnings(templated).map((item) => item.path)).toEqual([
      "audit.sinks[0].url",
    ]);
  });
  it("ignores the sinks of a disabled audit log", () => {
    const extra = sink("https://siem.acme.example/events");
    (extra.audit as Json).enabled = false;
    expect(warnings(managed(extra))).toEqual([]);
  });
});

describe("sandbox.credential: runtime", () => {
  const sandbox = (extra: Json): Json => ({
    sandbox: {
      required: true,
      provider: "e2b-compatible",
      endpoint: "https://gateway.acme.example/sandbox",
      credential: "runtime",
      ...extra,
    },
  });
  it("accepts a sandbox endpoint on the inference gateway origin", () => {
    expect(warnings(managed(sandbox({})))).toEqual([]);
    expect(
      warnings(
        managed(
          sandbox({
            provider: "kubernetes-agent-sandbox",
            router: "https://gateway.acme.example/router",
            template: "warm",
          }),
        ),
      ),
    ).toEqual([]);
  });
  it("rejects an endpoint or router on another origin", () => {
    rejects(
      managed(sandbox({ endpoint: "https://sandbox.acme.example" })),
      "sandbox.endpoint",
      "https://gateway.acme.example",
    );
    rejects(
      managed(sandbox({ endpoint: "https://gateway.acme.example:8443/x" })),
      "sandbox.endpoint",
      "origin",
    );
    rejects(
      managed(
        sandbox({
          provider: "kubernetes-agent-sandbox",
          router: "https://router.acme.example",
          template: "warm",
        }),
      ),
      "sandbox.router",
      "origin",
    );
  });
  it("rejects it when the launch has no runtime credential", () => {
    const personal = {
      ...managed(sandbox({})),
      deployment: { mode: "personal" },
      identity: { mode: "none" },
      credential: { provider: "none" },
      models: { allowed: ["acme/coder"], catalog },
    };
    rejects(personal, "sandbox.credential", "no runtime credential");
    rejects(
      {
        ...personal,
        credential: { provider: "pi-native" },
        inference: { provider: "pi-native" },
        models: { allowed: ["acme/coder"] },
      },
      "sandbox.credential",
      "no runtime credential",
    );
  });
  it("warns when either origin is decided by a runtime variable", () => {
    const templated = managed({
      variables: ["ACME_SANDBOX_URL"],
      ...sandbox({ endpoint: `\${ACME_SANDBOX_URL}` }),
    });
    expect(warnings(templated)).toEqual([
      expect.objectContaining({
        path: "sandbox.endpoint",
        message: expect.stringContaining("inference.baseUrl"),
      }),
    ]);
  });
});

describe("Streamable HTTP MCP servers", () => {
  const server = (url: string, extra: Json = {}): Json => ({
    mcp: {
      mode: "allowlist",
      servers: {
        docs: {
          transport: "streamable-http",
          url,
          required: true,
          ...extra,
        },
      },
    },
  });
  const personal = (extra: Json): Json => ({
    ...managed(extra),
    deployment: { mode: "personal" },
    identity: { mode: "none" },
    credential: { provider: "local-secret" },
    models: { default: "acme/coder", allowed: ["acme/coder"], catalog },
  });
  const runtime = { credential: "runtime" };
  it("accepts a runtime-credential server on the gateway origin and an allowed host", () => {
    for (const extra of [
      server("https://gateway.acme.example/mcp", runtime),
      {
        ...server("https://mcp.acme.example/mcp"),
        network: { allowHosts: ["mcp.acme.example"] },
      },
    ])
      expect(warnings(managed(extra))).toEqual([]);
    // Personal mode is not private-only unless it says so.
    expect(warnings(personal(server("https://mcp.acme.example/mcp")))).toEqual(
      [],
    );
  });
  it("rejects credential: runtime on another origin than inference.baseUrl", () => {
    rejects(
      managed({
        ...server("https://mcp.acme.example/mcp", runtime),
        network: { allowHosts: ["mcp.acme.example"] },
      }),
      "mcp.servers.docs.url",
      "https://gateway.acme.example",
    );
    rejects(
      managed(server("https://gateway.acme.example:8443/mcp", runtime)),
      "mcp.servers.docs.url",
      "MCP_UNHEALTHY",
    );
  });
  it("rejects credential: runtime when the launch has no runtime credential", () => {
    const base = personal(server("https://gateway.acme.example/mcp", runtime));
    rejects(
      { ...base, credential: { provider: "none" } },
      "mcp.servers.docs.credential",
      "no runtime credential",
    );
    rejects(
      {
        ...base,
        credential: { provider: "pi-native" },
        inference: { provider: "pi-native" },
        models: { allowed: ["acme/coder"] },
      },
      "mcp.servers.docs.credential",
      "no runtime credential",
    );
  });
  it("rejects a host the private-only network policy refuses", () => {
    rejects(
      managed(server("https://mcp.acme.example/mcp")),
      "mcp.servers.docs.url",
      "mcp.acme.example is not in network.allowHosts",
    );
    rejects(
      personal({
        ...server("https://mcp.acme.example/mcp"),
        network: { privateOnly: true },
      }),
      "mcp.servers.docs.url",
      "MCP_UNHEALTHY",
    );
  });
  it("warns when a runtime variable is involved", () => {
    expect(
      warnings(
        managed({
          variables: ["ACME_MCP_URL"],
          ...server(`\${ACME_MCP_URL}`, runtime),
        }),
      ),
    ).toEqual([
      expect.objectContaining({
        path: "mcp.servers.docs.url",
        message: expect.stringContaining("inference.baseUrl"),
      }),
    ]);
    expect(
      warnings(
        managed({
          variables: ["ACME_MCP_URL"],
          ...server(`\${ACME_MCP_URL}`),
        }),
      ),
    ).toEqual([
      expect.objectContaining({
        path: "mcp.servers.docs.url",
        message: expect.stringContaining("network.allowHosts"),
      }),
    ]);
    // A templated gateway may be the server's origin and host.
    const templated = managed({
      variables: ["ACME_GATEWAY_URL"],
      ...server("https://mcp.acme.example/mcp", runtime),
    });
    (templated.inference as Json).baseUrl = `\${ACME_GATEWAY_URL}`;
    expect(warnings(templated).map((item) => item.path)).toEqual([
      "mcp.servers.docs.url",
    ]);
  });
  it("only warns about an optional server", () => {
    for (const extra of [
      server("https://mcp.acme.example/mcp", { required: false }),
      {
        ...server("https://mcp.acme.example/mcp", {
          ...runtime,
          required: false,
        }),
        network: { allowHosts: ["mcp.acme.example"] },
      },
    ])
      expect(warnings(managed(extra))).toEqual([
        expect.objectContaining({
          path: "mcp.servers.docs.url",
          message: expect.stringContaining("optional"),
        }),
      ]);
    expect(
      warnings({
        ...personal(
          server("https://gateway.acme.example/mcp", {
            ...runtime,
            required: false,
          }),
        ),
        credential: { provider: "none" },
      }).map((item) => item.path),
    ).toEqual(["mcp.servers.docs.credential"]);
  });
  it("ignores stdio servers", () => {
    expect(
      warnings(
        managed({
          mcp: {
            servers: {
              local: {
                transport: "stdio",
                command: "acme-mcp",
                required: true,
              },
            },
          },
        }),
      ),
    ).toEqual([]);
  });
});

describe("sandbox.network.mode", () => {
  it("warns that deny is not enforced by a sandbox that is not required", () => {
    for (const sandbox of [
      { network: { mode: "deny" } },
      { required: false, network: { mode: "deny" } },
    ])
      expect(warnings(managed({ sandbox }))).toEqual([
        expect.objectContaining({
          path: "sandbox.network.mode",
          message: expect.stringContaining("sandbox.required: true"),
        }),
      ]);
  });
  it("accepts deny on a required sandbox and allow on an optional one", () => {
    for (const sandbox of [
      { required: true, network: { mode: "deny" } },
      { required: true },
      { network: { mode: "allow" } },
      {},
    ])
      expect(warnings(managed({ sandbox }))).toEqual([]);
  });
});

describe("runtimeVariableUse", () => {
  it("separates launch variables from those only update reads", () => {
    const manifest = parseManifest(
      managed({
        variables: ["ACME_SIEM_URL", "ACME_HOST", "ACME_UPDATES"],
        audit: {
          enabled: true,
          sinks: [{ id: "siem", type: "http", url: `\${ACME_SIEM_URL}` }],
        },
        inference: {
          provider: "openai-compatible",
          baseUrl: `https://\${ACME_HOST}/v1`,
        },
        updates: {
          channel: "stable",
          channels: ["stable"],
          source: `https://\${ACME_HOST}/\${ACME_UPDATES}`,
        },
      }),
    );
    expect(runtimeVariableUse(manifest)).toEqual({
      launch: ["ACME_SIEM_URL", "ACME_HOST"],
      update: ["ACME_UPDATES"],
      optionalMcp: {},
    });
  });

  it("names the variables only optional MCP servers read", () => {
    const manifest = parseManifest(
      managed({
        variables: ["ACME_DOCS", "ACME_HOST", "ACME_JIRA"],
        inference: {
          provider: "openai-compatible",
          baseUrl: `https://\${ACME_HOST}/v1`,
        },
        mcp: {
          mode: "allowlist",
          servers: {
            docs: {
              transport: "streamable-http",
              url: `https://\${ACME_DOCS}/mcp`,
            },
            wiki: {
              transport: "streamable-http",
              url: `https://\${ACME_DOCS}/wiki`,
            },
            host: {
              transport: "streamable-http",
              url: `https://\${ACME_HOST}/mcp`,
            },
            jira: {
              transport: "streamable-http",
              url: `https://\${ACME_JIRA}/mcp`,
              required: true,
            },
          },
        },
      }),
    );
    expect(runtimeVariableUse(manifest).optionalMcp).toEqual({
      ACME_DOCS: ["docs", "wiki"],
    });
  });
});

describe("tool.execute denials", () => {
  const governed = (resource: string, effect: string): Json => ({
    policy: {
      default: "ask",
      enforced: [{ id: "acme.tool", action: "tool.execute", resource, effect }],
    },
    mcp: {
      mode: "allowlist",
      servers: {
        docs: {
          transport: "streamable-http",
          url: "https://mcp.acme.example/docs",
        },
      },
    },
  });
  const denials = (resource: string, effect = "deny") =>
    warnings(managed(governed(resource, effect))).filter(
      (warning) => warning.path === "policy.enforced[0].resource",
    );
  it("warns, without failing, about a tool that is not built in or declared", () => {
    expect(denials("web_fetch")).toEqual([
      expect.objectContaining({
        message: expect.stringMatching(
          /acme\.tool denies tool web_fetch.*only known at run time/,
        ),
      }),
    ]);
  });
  it("knows Pi's, PiShip's, and a declared MCP server's tools, globs, and other effects", () => {
    for (const resource of [
      "bash",
      "grep",
      "codemode",
      "mcp__docs__drop",
      "web_*",
    ])
      expect(denials(resource)).toEqual([]);
    expect(denials("web_fetch", "allow")).toEqual([
      expect.objectContaining({
        message: expect.stringContaining("policy.default decides"),
      }),
    ]);
    expect(denials("web_fetch", "ask")).toHaveLength(1);
    expect(denials("bash", "allow")).toEqual([]);
    expect(denials("mcp__other__drop")).toHaveLength(1);
  });
});

describe("enforced read denies that commands can get around", () => {
  const uncovered = (enforced: Json[], sandbox: Json = {}) =>
    warnings(
      managed({
        policy: { default: "ask", enforced },
        ...(Object.keys(sandbox).length ? { sandbox } : {}),
      }),
    ).filter((warning) => warning.path === "policy.enforced");
  const rule = (id: string, resource: string, extra: Json = {}) => ({
    id,
    action: "filesystem.read",
    resource,
    effect: "deny",
    ...extra,
  });

  it("names, in one warning, each deny no sandbox read-deny directory covers", () => {
    expect(
      uncovered(
        [
          rule("acme.env", "**/.env"),
          rule("acme.vault", "/srv/vault/**", { action: "filesystem.*" }),
          rule("acme.ssh", "~/.ssh/**"),
        ],
        { required: true },
      ),
    ).toEqual([
      {
        path: "policy.enforced",
        message: expect.stringMatching(
          /^acme\.env \(\*\*\/\.env\), acme\.vault \(\/srv\/vault\/\*\*\): these filesystem\.read denies refuse the file tools only; a command such as cat .*sandbox\.filesystem\.read\.deny lists their directory/,
        ),
      },
    ]);
  });

  it("counts the sandbox's read-deny list only when the sandbox is required, and checks policy.defaults too", () => {
    const all = warnings(
      managed({
        policy: {
          default: "ask",
          enforced: [rule("acme.ssh", "~/.ssh/**")],
          defaults: [rule("acme.aws", "~/.aws/**")],
        },
        sandbox: { required: false },
      }),
    ).filter((warning) => warning.path.startsWith("policy."));
    expect(all).toEqual([
      {
        path: "policy.enforced",
        message: expect.stringMatching(
          /^acme\.ssh \(~\/\.ssh\/\*\*\): .* unless sandbox\.required is true and sandbox\.filesystem\.read\.deny lists/,
        ),
      },
      {
        path: "policy.defaults",
        message: expect.stringMatching(/^acme\.aws \(~\/\.aws\/\*\*\): /),
      },
    ]);
  });

  it("is quiet when a read-deny directory covers the rule, and for asks, allows, and writes", () => {
    expect(
      uncovered(
        [
          rule("acme.vault", "/srv/vault/**"),
          rule("acme.key", "/srv/vault/key"),
        ],
        { required: true, filesystem: { read: { deny: ["/srv/vault/"] } } },
      ),
    ).toEqual([]);
    expect(
      uncovered([
        rule("acme.ask", "**/.env", { effect: "ask" }),
        rule("acme.allow", "**/.env", { effect: "allow" }),
        rule("acme.write", "**/.env", { action: "filesystem.write" }),
      ]),
    ).toEqual([]);
  });
});

describe("filesystem rules that can never match", () => {
  const paths = (
    resource: string,
    effect = "deny",
    action = "filesystem.read",
  ) =>
    warnings(
      managed({
        policy: {
          default: "ask",
          enforced: [{ id: "acme.path", action, resource, effect }],
        },
      }),
    ).filter((warning) => warning.path === "policy.enforced[0].resource");

  it("warns, without failing, about patterns no decided path can match", () => {
    const cases: readonly (readonly [string, RegExp])[] = [
      [
        ".env",
        /never matches \.env: it is relative.*workspace\/\.env.*\*\*\/\.env/,
      ],
      ["./.env", /it is relative.*write workspace\/\.env for/],
      ["src/secrets/**", /it is relative/],
      ["~/.ssh/", /it ends with \/.*write ~\/\.ssh\/\*\*/],
      ["/etc/secrets/", /it ends with \//],
      ["workspace/a/../.env", /a \. or \.\. segment/],
      ["workspace/./.env", /a \. or \.\. segment/],
      ["~//.ssh/**", /an empty segment/],
      ["*", /a leading \* never matches.*write \*\*\/\* for/],
      [
        "*.env",
        /never matches \*\.env: a leading \*\.env never matches.*write \*\*\/\*\.env/,
      ],
      ["*.secret/**", /a leading \*\.secret never matches/],
      [
        "*/secrets/**",
        /matches \*\/secrets\/\*\* only at the filesystem root \(as \/secrets\/\*\*\).*write \*\*\/secrets\/\*\*/,
      ],
      [
        "C:\\Users\\me\\.ssh\\**",
        /uses \\ separators.*C:\/Users\/me\/\.ssh\/\*\*/,
      ],
    ];
    for (const [resource, message] of cases)
      expect(paths(resource), resource).toEqual([
        expect.objectContaining({ message: expect.stringMatching(message) }),
      ]);
    expect(paths(".env", "ask", "filesystem.*")).toHaveLength(1);
  });

  it("accepts every pattern a decided path can match, and ignores allow rules", () => {
    for (const resource of [
      "**",
      "**/.env",
      "~",
      "~/",
      "~/.ssh",
      "~/.ssh/**",
      "workspace",
      "workspace/",
      "workspace/.env",
      "workspace/**/node_modules/**",
      "tmp/**",
      "/",
      "/etc/passwd",
      "//server/share/**",
      "C:/",
      "C:/Users/**",
    ])
      expect(paths(resource), resource).toEqual([]);
    expect(paths(".env", "allow")).toEqual([]);
    expect(paths(".env", "deny", "skill.load")).toEqual([]);
  });
});

describe("policy.packs without sandbox.required", () => {
  const routine = (required: boolean): Json =>
    managed({
      schema: PISHIP_SCHEMA_V1ALPHA6,
      policy: { packs: [{ pack: "piship.routine", version: 1 }] },
      sandbox: { required },
    });
  it("warns that the pack's sandbox-gated shell rules are inactive", () => {
    expect(warnings(routine(false))).toContainEqual({
      path: "policy.packs",
      message: expect.stringMatching(
        /^piship\.routine@1: its \d+ sandbox-gated rules .* are inactive because sandbox\.required is not true.*set sandbox\.required: true/,
      ),
    });
  });
  it("is quiet once sandbox.required is true", () => {
    expect(
      warnings(routine(true)).filter((item) => item.path === "policy.packs"),
    ).toEqual([]);
  });
});

describe("MCP rules naming no declared server", () => {
  const rule = (id: string, action: string, resource: string) => ({
    id,
    action,
    resource,
    effect: "allow",
  });
  const manifest = {
    governance: {
      mcp: { mode: "allowlist", servers: [{ id: "docs" }] },
      policy: {
        enforced: [rule("ok.glob", "mcp.tool.call", "**")],
        defaults: [
          rule("ok.start", "mcp.server.start", "docs"),
          rule("ok.tool", "mcp.tool.call", "docs:search"),
          rule("ok.any", "mcp.tool.call", "*:search"),
          rule("model.name", "mcp.tool.call", "mcp__docs__search"),
          rule("typo.tool", "mcp.tool.call", "doc:search"),
          rule("typo.start", "mcp.server.start", "doc"),
        ],
      },
    },
  } as unknown as Parameters<typeof unknownMcpServerRules>[0];

  it("warns about the model-facing name and unknown servers only", () => {
    expect(unknownMcpServerRules(manifest)).toEqual([
      {
        path: "policy.defaults[3].resource",
        message:
          "model.name (allow mcp.tool.call) names the model-facing tool mcp__docs__search, so it matches nothing; write it as docs:search (<server>:<tool>)",
      },
      {
        path: "policy.defaults[4].resource",
        message:
          "typo.tool (allow mcp.tool.call) names doc:search, but doc is not a server declared under mcp.servers, so it matches nothing; the resource is <server>:<tool>",
      },
      {
        path: "policy.defaults[5].resource",
        message:
          "typo.start (allow mcp.server.start) names doc, which is not a server declared under mcp.servers, so it matches nothing; the resource is the server id",
      },
    ]);
  });

  it("does not call a rule for a project server dead when project servers can load", () => {
    const governance = manifest.governance;
    const explicit = {
      governance: {
        ...governance,
        mcp: { mode: "explicit", project: "allow", servers: [{ id: "docs" }] },
      },
    } as unknown as Parameters<typeof unknownMcpServerRules>[0];
    expect(unknownMcpServerRules(explicit).map((item) => item.path)).toEqual([
      "policy.defaults[3].resource",
    ]);
  });
});

describe("purge settings nothing acts on", () => {
  const manifest = (provider: string, onUninstall: string) =>
    ({
      access: { credential: { provider } },
      data: { purge: { onLogout: ["sessions"], onUninstall } },
    }) as unknown as Parameters<typeof inertDataPurge>[0];

  it("warns about a logout purge when sign-in is Pi's and about onUninstall: all", () => {
    expect(
      inertDataPurge(manifest("pi-native", "all")).map((item) => item.path),
    ).toEqual(["data.purge.onLogout", "data.purge.onUninstall"]);
  });
  it("is quiet when the branded logout runs the purge", () => {
    expect(inertDataPurge(manifest("http-broker", "none"))).toEqual([]);
  });
  it("warns that a logout purge of temp is not acted on", () => {
    const temp = {
      access: { credential: { provider: "http-broker" } },
      data: { purge: { onLogout: ["cache", "temp"], onUninstall: "none" } },
    } as unknown as Parameters<typeof inertDataPurge>[0];
    expect(inertDataPurge(temp)).toEqual([
      expect.objectContaining({
        path: "data.purge.onLogout",
        message: expect.stringMatching(/^temp is not acted on/),
      }),
    ]);
  });
});

describe("temp retention nothing applies", () => {
  it("warns only when data.temp.retention is declared", () => {
    const manifest = (retention: object) =>
      ({ data: { retention } }) as unknown as Parameters<
        typeof inertTempRetention
      >[0];
    expect(
      inertTempRetention(manifest({ temp: { retentionSeconds: 3_600 } })).map(
        (item) => item.path,
      ),
    ).toEqual(["data.temp.retention"]);
    expect(
      inertTempRetention(manifest({ cache: { retentionSeconds: 3_600 } })),
    ).toEqual([]);
  });
});

describe("optional HTTP audit sinks in a managed distribution", () => {
  const manifest = (mode: string, enabled = true) =>
    ({
      deployment: { mode },
      governance: {
        audit: {
          enabled,
          sinks: [
            { id: "local", type: "file", required: false },
            { id: "siem", type: "http", url: "https://siem", required: true },
            { id: "copy", type: "http", url: "https://copy", required: false },
          ],
        },
      },
    }) as unknown as Parameters<typeof optionalHttpAuditSinks>[0];

  it("warns that an optional HTTP sink drops undelivered events", () => {
    expect(
      optionalHttpAuditSinks(manifest("managed")).map((item) => item.path),
    ).toEqual(["audit.sinks[2].required"]);
  });
  it("is quiet in personal mode and with audit off", () => {
    expect(optionalHttpAuditSinks(manifest("personal"))).toEqual([]);
    expect(optionalHttpAuditSinks(manifest("managed", false))).toEqual([]);
  });
});

describe("allow-listed names the runtime drops as credentials", () => {
  it("warns with the field path, and leaves other names alone", () => {
    const manifest = {
      governance: {
        sandbox: { environment: { allow: ["PATH", "AWS_REGION"] } },
        mcp: {
          servers: [
            { id: "docs", env: { allow: ["LANG", "HF_HOME", "PI_DEBUG"] } },
          ],
        },
      },
    } as unknown as Parameters<typeof droppedCredentialNames>[0];
    expect(
      droppedCredentialNames(manifest).map(({ path, message }) => [
        path,
        message.split(" ")[0],
      ]),
    ).toEqual([
      ["sandbox.environment.allow", "AWS_REGION"],
      ["mcp.servers.docs.env.allow", "HF_HOME"],
      ["mcp.servers.docs.env.allow", "PI_DEBUG"],
    ]);
  });
});

describe("task grant host settings nothing acts on", () => {
  const manifest = (taskGrants: object | undefined) =>
    ({ governance: { policy: { taskGrants } } }) as unknown as Parameters<
      typeof inertTaskGrantHosts
    >[0];
  it("warns about wildcardHosts and a web.request action", () => {
    expect(
      inertTaskGrantHosts(
        manifest({
          mode: "session",
          wildcardHosts: true,
          actions: ["web.request", "git.push"],
        }),
      ).map((item) => item.path),
    ).toEqual(["policy.taskGrants.wildcardHosts", "policy.taskGrants.actions"]);
  });
  it("is quiet for grants that can take effect", () => {
    expect(
      inertTaskGrantHosts(manifest({ mode: "session", actions: ["git.push"] })),
    ).toEqual([]);
    expect(inertTaskGrantHosts(manifest(undefined))).toEqual([]);
  });
});
