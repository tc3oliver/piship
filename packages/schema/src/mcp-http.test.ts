// piship/v1alpha6 `mcp.servers.<id>.httpTransport` (plain HTTP to a private
// or internal host, by opt-in) and identity-derived `headers`.
import { describe, expect, it } from "vitest";
import {
  launchWarnings,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
} from "./index.js";

type Json = Record<string, unknown>;

/** A `${MCP_URL}` runtime reference. */
const MCP_URL_REF = ["$", "{MCP_URL}"].join("");

const HEADERS = { "X-Company-User": { identityClaim: "preferred_username" } };

function managed(server: Json, extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA6,
    app: {
      id: "acmecode",
      name: "AcmeCode",
      command: "acmecode",
      version: "1.0.0",
    },
    runtime: { pi: "1.0.0" },
    deployment: { mode: "managed" },
    updates: { channel: "stable", channels: ["stable"] },
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
    network: { allowHosts: ["10.20.30.40", "mcp.corp.internal"] },
    mcp: {
      servers: {
        tools: { transport: "streamable-http", ...server },
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

const serverOf = (input: Json) =>
  parseManifest(input).governance?.mcp.servers[0];

describe("mcp.servers.<id>.httpTransport", () => {
  it("is absent unless http-allowed, so existing manifests lock unchanged", () => {
    const plain = serverOf(managed({ url: "https://mcp.acme.example/mcp" }));
    expect(plain).not.toHaveProperty("httpTransport");
    expect(plain).not.toHaveProperty("headers");
    expect(
      serverOf(
        managed({
          url: "https://mcp.acme.example/mcp",
          httpTransport: "https",
        }),
      ),
    ).not.toHaveProperty("httpTransport");
  });

  it("keeps plain HTTP to loopback only without the opt-in", () => {
    rejects(
      managed({ url: "http://10.20.30.40/mcp" }),
      "mcp.servers.tools.url",
      "plain http is accepted only for loopback",
    );
  });

  it("accepts plain HTTP to a private or internal host with http-allowed", () => {
    for (const url of [
      "http://10.20.30.40/mcp",
      "http://mcp.corp.internal/mcp",
    ])
      expect(
        serverOf(managed({ url, httpTransport: "http-allowed" })),
      ).toMatchObject({ url, httpTransport: "http-allowed" });
  });

  it("rejects a public host", () => {
    for (const url of ["http://mcp.acme.example/mcp", "http://8.8.8.8/mcp"])
      rejects(
        managed({ url, httpTransport: "http-allowed" }),
        "mcp.servers.tools.url",
        "is public, so serve it over https",
      );
  });

  it("checks a runtime reference at launch and warns", () => {
    const input = managed(
      { url: MCP_URL_REF, httpTransport: "http-allowed" },
      { variables: ["MCP_URL"] },
    );
    expect(serverOf(input)).toMatchObject({ url: MCP_URL_REF });
    const warnings = launchWarnings(parseManifest(input));
    expect(warnings).toContainEqual({
      path: "mcp.servers.tools.httpTransport",
      message: expect.stringContaining("unencrypted"),
    });
  });

  it("warns that plain HTTP traffic is unencrypted", () => {
    const warnings = launchWarnings(
      parseManifest(
        managed({
          url: "http://10.20.30.40/mcp",
          httpTransport: "http-allowed",
        }),
      ),
    );
    expect(warnings).toContainEqual({
      path: "mcp.servers.tools.httpTransport",
      message: expect.stringContaining("unencrypted"),
    });
    expect(
      launchWarnings(
        parseManifest(
          managed({
            url: "https://10.20.30.40/mcp",
            httpTransport: "http-allowed",
          }),
        ),
      ).filter((w) => w.path === "mcp.servers.tools.httpTransport"),
    ).toEqual([]);
  });

  it("is refused together with credential: runtime", () => {
    rejects(
      managed({
        url: "https://gateway.acme.example/mcp",
        httpTransport: "http-allowed",
        credential: "runtime",
      }),
      "mcp.servers.tools.httpTransport",
      "never sent over plain HTTP",
    );
  });

  it("applies to streamable-http only", () => {
    rejects(
      managed({
        transport: "stdio",
        module: "./mcp/docs.mjs",
        httpTransport: "http-allowed",
      }),
      "mcp.servers.tools.httpTransport",
      "streamable-http",
    );
  });

  it("keeps the private-only network policy", () => {
    rejects(
      managed({
        url: "http://192.168.7.7/mcp",
        httpTransport: "http-allowed",
        required: true,
      }),
      "mcp.servers.tools.url",
      "not in network.allowHosts",
    );
  });

  it("rejects an unknown value", () => {
    rejects(
      managed({ url: "http://10.20.30.40/mcp", httpTransport: "http" }),
      "mcp.servers.tools.httpTransport",
      "Expected https, http-allowed",
    );
  });
});

describe("mcp.servers.<id>.headers", () => {
  it("accepts identity claims and keeps names only", () => {
    expect(
      serverOf(
        managed({ url: "https://mcp.acme.example/mcp", headers: HEADERS }),
      ),
    ).toMatchObject({ headers: HEADERS });
  });

  it("accepts the company's plain-HTTP server with its user header", () => {
    expect(
      serverOf(
        managed({
          url: "http://10.20.30.40/mcp",
          httpTransport: "http-allowed",
          headers: HEADERS,
        }),
      ),
    ).toMatchObject({ httpTransport: "http-allowed", headers: HEADERS });
  });

  it("rejects literal and environment values", () => {
    for (const value of [
      "alice",
      { value: "alice" },
      { env: "USER" },
      { identityClaim: "preferred_username", value: "alice" },
    ])
      expect(() =>
        parseManifest(
          managed({
            url: "https://mcp.acme.example/mcp",
            headers: { "X-Company-User": value },
          }),
        ),
      ).toThrow(ManifestError);
  });

  it("accepts only sub, preferred_username, and email", () => {
    for (const claim of ["groups", "name", "email_verified"])
      rejects(
        managed({
          url: "https://mcp.acme.example/mcp",
          headers: { "X-Company-User": { identityClaim: claim } },
        }),
        "mcp.servers.tools.headers.X-Company-User.identityClaim",
        "Expected sub, preferred_username, email",
      );
  });

  it("rejects an empty headers map and a __proto__ name", () => {
    rejects(
      managed({ url: "https://mcp.acme.example/mcp", headers: {} }),
      "mcp.servers.tools.headers",
      "at least one header",
    );
    rejects(
      managed({
        url: "https://mcp.acme.example/mcp",
        headers: JSON.parse('{"__proto__": {"identityClaim": "sub"}}'),
      }),
      "mcp.servers.tools.headers.__proto__",
      "HTTP tokens",
    );
  });

  it("rejects invalid and reserved header names, case-insensitively", () => {
    for (const name of ["X User", "X:User", "Ä-User", ""])
      expect(() =>
        parseManifest(
          managed({
            url: "https://mcp.acme.example/mcp",
            headers: { [name]: { identityClaim: "sub" } },
          }),
        ),
      ).toThrow(ManifestError);
    for (const name of [
      "Authorization",
      "proxy-authorization",
      "COOKIE",
      "Host",
      "Content-Length",
      "Content-Type",
      "Accept",
      "Connection",
      "Transfer-Encoding",
      "Mcp-Session-Id",
      "MCP-Protocol-Version",
      "Sec-Fetch-Mode",
      "X-Forwarded-For",
      "x-forwarded-user",
      "X-Real-IP",
      "X-HTTP-Method-Override",
    ])
      rejects(
        managed({
          url: "https://mcp.acme.example/mcp",
          headers: { [name]: { identityClaim: "sub" } },
        }),
        `mcp.servers.tools.headers.${name}`,
        "is reserved",
      );
    rejects(
      managed({
        url: "https://mcp.acme.example/mcp",
        headers: {
          "X-User": { identityClaim: "sub" },
          "x-user": { identityClaim: "email" },
        },
      }),
      "mcp.servers.tools.headers.x-user",
      "declared more than once",
    );
  });

  it("needs identity.mode: oidc", () => {
    // A personal distribution without an identity section.
    const {
      identity: _identity,
      credential: _credential,
      inference: _inference,
      models: _models,
      network: _network,
      ...personal
    } = managed({ url: "https://mcp.acme.example/mcp", headers: HEADERS });
    rejects(
      { ...personal, deployment: { mode: "personal" } },
      "mcp.servers.tools.headers",
      "identity.mode: oidc",
    );
  });

  it("applies to streamable-http only", () => {
    rejects(
      managed({
        transport: "stdio",
        module: "./mcp/docs.mjs",
        headers: HEADERS,
      }),
      "mcp.servers.tools.headers",
      "streamable-http",
    );
  });
});

describe("plain HTTP to a name others can answer for", () => {
  it("warns for .local and single-label hosts, not for IPs or FQDNs", () => {
    const warned = (url: string) =>
      launchWarnings(
        parseManifest(
          managed(
            { url, httpTransport: "http-allowed" },
            {
              network: {
                allowHosts: [
                  "mcp",
                  "mcp.local",
                  "10.20.30.40",
                  "mcp.corp.internal",
                ],
              },
            },
          ),
        ),
      ).some(
        (warning) =>
          warning.path === "mcp.servers.tools.url" &&
          warning.message.includes("mDNS"),
      );
    expect(warned("http://mcp/mcp")).toBe(true);
    expect(warned("http://mcp.local/mcp")).toBe(true);
    expect(warned("http://10.20.30.40/mcp")).toBe(false);
    expect(warned("http://mcp.corp.internal/mcp")).toBe(false);
    expect(warned("https://mcp/mcp")).toBe(false);
  });
});

describe("piship/v1alpha5", () => {
  it("rejects both fields", () => {
    for (const field of ["httpTransport", "headers"])
      rejects(
        {
          ...managed({
            url: "https://mcp.acme.example/mcp",
            [field]: field === "headers" ? HEADERS : "http-allowed",
          }),
          schema: PISHIP_SCHEMA_V1ALPHA5,
        },
        `mcp.servers.tools.${field}`,
        "Unknown field",
      );
  });
});
