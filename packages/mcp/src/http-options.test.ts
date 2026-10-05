// httpTransport: http-allowed (plain HTTP to a private or internal host) and
// identity-derived request headers on Streamable HTTP servers.
import { tmpdir } from "node:os";
import { PiShipError } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import { McpGovernor, StreamableHttpTransport } from "./index.js";
import { startFixtureHttpServer } from "./testing/fixture-http.mjs";
import type {
  McpAuditEvent,
  McpFetch,
  McpGovernorOptions,
  McpServerConfig,
} from "./index.js";

const cleanup: (() => Promise<unknown> | unknown)[] = [];
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()?.();
});

function server(
  url: string,
  overrides: Partial<McpServerConfig> = {},
): McpServerConfig {
  return {
    id: "tickets",
    transport: "streamable-http",
    url,
    args: [],
    env: { allow: [], set: {} },
    credential: "none",
    timeoutMs: 5000,
    startupTimeoutMs: 5000,
    retry: { attempts: 1 },
    required: false,
    tools: { allow: [], deny: [] },
    ...overrides,
  };
}

function governor(
  options: Partial<McpGovernorOptions> & { servers: McpServerConfig[] },
): { governor: McpGovernor; audit: McpAuditEvent[] } {
  const audit: McpAuditEvent[] = [];
  const instance = new McpGovernor({
    authorize: async () => ({ allowed: true, reason: "ok" }),
    distributionDir: tmpdir(),
    workspace: tmpdir(),
    fetch: (url, init) => fetch(url, init),
    audit: (event) => audit.push(event),
    retryDelayMs: 10,
    ...options,
  });
  cleanup.push(() => instance.close());
  return { governor: instance, audit };
}

/** A `${MCP_URL}` runtime reference. */
const MCP_URL_REF = ["$", "{MCP_URL}"].join("");

const notCalled: McpFetch = async () => {
  throw new Error("not called");
};

/** A fetch that sends requests for `from`'s origin to the fixture at `to`. */
function rerouted(from: string, to: string, seen: string[]): McpFetch {
  return (url, init) => {
    const target = new URL(url.toString());
    seen.push(target.origin);
    const fixture = new URL(to);
    target.protocol = fixture.protocol;
    target.host = fixture.host;
    expect(new URL(from).origin).toBe(new URL(url.toString()).origin);
    return fetch(target, init);
  };
}

describe("plain HTTP to a private or internal host", () => {
  const transport = (
    url: string,
    options: { plainHttp?: boolean; credential?: boolean } = {},
  ) =>
    new StreamableHttpTransport({
      serverId: "tickets",
      url,
      fetch: notCalled,
      ...(options.plainHttp ? { plainHttp: true } : {}),
      ...(options.credential
        ? {
            credential: async () => "gateway-bearer-1234567",
            credentialOrigins: [new URL(url).origin],
          }
        : {}),
    });

  it("is refused beyond loopback without http-allowed", () => {
    for (const url of [
      "http://127.0.0.1:9/mcp",
      "http://localhost:9/mcp",
      "http://[::1]:9/mcp",
    ]) {
      expect(() => transport(url)).not.toThrow();
      expect(() => transport(url, { credential: true })).not.toThrow();
    }
    for (const url of [
      "http://10.20.30.40/mcp",
      "http://mcp.corp.internal/mcp",
    ])
      expect(() => transport(url)).toThrow(/must use https/);
  });

  it("is accepted for a private or internal host with http-allowed", () => {
    for (const url of [
      "http://10.20.30.40/mcp",
      "http://192.168.1.20:8080/mcp",
      "http://mcp/mcp",
      "http://mcp.corp.internal/mcp",
      "https://mcp.acme.example/mcp",
    ])
      expect(() => transport(url, { plainHttp: true })).not.toThrow();
  });

  it("refuses a public host even with http-allowed", () => {
    for (const url of [
      "http://mcp.acme.example/mcp",
      "http://8.8.8.8/mcp",
      "http://com/mcp",
    ])
      expect(() => transport(url, { plainHttp: true })).toThrow(
        /which is public/,
      );
  });

  it("never sends the runtime credential over plain HTTP", () => {
    expect(() =>
      transport("http://10.20.30.40/mcp", {
        plainHttp: true,
        credential: true,
      }),
    ).toThrow(/runtime credential is never sent over plain HTTP/);
  });

  it("connects through the plain-HTTP fetch and reports plain HTTP", async () => {
    const fixture = await startFixtureHttpServer({ serverName: "tickets" });
    cleanup.push(() => fixture.close());
    const seen: string[] = [];
    const url = "http://10.20.30.40/mcp";
    const { governor: g } = governor({
      // The ordinary fetch keeps the loopback-only rule and is never used.
      fetch: notCalled,
      plainHttpFetch: rerouted(url, fixture.url, seen),
      servers: [server(url, { httpTransport: "http-allowed" })],
    });
    const [report] = await g.start();
    expect(report).toMatchObject({ state: "healthy", plainHttp: true });
    expect(new Set(seen)).toEqual(new Set(["http://10.20.30.40"]));
  });

  it("fails a templated url that resolves to a public host closed", async () => {
    const optional = governor({
      plainHttpFetch: notCalled,
      resolveUrl: () => "http://mcp.acme.example/mcp",
      servers: [server(MCP_URL_REF, { httpTransport: "http-allowed" })],
    });
    const [report] = await optional.governor.start();
    expect(report).toMatchObject({ state: "failed" });
    expect(report?.reason).toMatch(/which is public/);

    const required = governor({
      plainHttpFetch: notCalled,
      resolveUrl: () => "http://mcp.acme.example/mcp",
      servers: [
        server(MCP_URL_REF, {
          httpTransport: "http-allowed",
          required: true,
        }),
      ],
    });
    await expect(required.governor.start()).rejects.toMatchObject({
      code: "MCP_UNHEALTHY",
    });
  });
});

describe("identity headers", () => {
  const user = "alice.chen";
  const headers = { "X-Company-User": { identityClaim: "preferred_username" } };

  it("sends the signed-in identity's claim on every request", async () => {
    const fixture = await startFixtureHttpServer({
      serverName: "tickets",
      recordHeader: "X-Company-User",
    });
    cleanup.push(() => fixture.close());
    const { governor: g, audit } = governor({
      identityClaims: async () => ({ sub: "u-1", preferred_username: user }),
      servers: [server(fixture.url, { headers })],
    });
    const [report] = await g.start();
    expect(report?.state).toBe("healthy");
    const search = g.tools().find((tool) => tool.tool === "search");
    await search?.call({ query: "q" });
    await g.close();
    expect(fixture.requests.length).toBeGreaterThan(2);
    for (const request of fixture.requests) expect(request.recorded).toBe(user);
    // The value is identity data: never in audit events or the report.
    expect(JSON.stringify([audit, g.health()])).not.toContain(user);
  });

  it("asks for the claims on every request, never caching a value", async () => {
    const fixture = await startFixtureHttpServer({
      serverName: "tickets",
      recordHeader: "X-Company-User",
    });
    cleanup.push(() => fixture.close());
    let current = "alice.chen";
    const { governor: g } = governor({
      identityClaims: async () => ({ preferred_username: current }),
      servers: [server(fixture.url, { headers })],
    });
    await g.start();
    current = "bob.lin";
    await g
      .tools()
      .find((tool) => tool.tool === "search")
      ?.call({ query: "q" });
    const recorded = fixture.requests.map((request) => request.recorded);
    expect(recorded[0]).toBe("alice.chen");
    expect(recorded.at(-1)).toBe("bob.lin");
  });

  const failures: [
    string,
    () => Promise<Record<string, unknown> | null>,
    RegExp,
  ][] = [
    ["no identity", async () => null, /nobody is signed in/],
    [
      "an unavailable identity",
      async () => {
        throw new PiShipError("IDENTITY_REQUIRED", "You are not signed in");
      },
      /signed-in identity is unavailable: You are not signed in/,
    ],
    [
      "an unverified email",
      async () => ({ email: "alice@acme.example", email_verified: false }),
      /email claim is not verified/,
    ],
    [
      "an email without email_verified",
      async () => ({ email: "alice@acme.example" }),
      /email claim is not verified/,
    ],
    [
      "a missing claim",
      async () => ({ sub: "u-1" }),
      /no preferred_username claim/,
    ],
    [
      "an empty claim",
      async () => ({ preferred_username: "" }),
      /not a usable header value/,
    ],
    [
      "a claim with CR/LF",
      async () => ({ preferred_username: "alice\r\nX-Admin: 1" }),
      /not a usable header value/,
    ],
    [
      "a claim with a control character",
      async () => ({ preferred_username: "alice\u0000" }),
      /not a usable header value/,
    ],
    [
      "an over-long claim",
      async () => ({ preferred_username: "a".repeat(257) }),
      /not a usable header value/,
    ],
    [
      "a non-string claim",
      async () => ({ preferred_username: ["alice"] }),
      /not a usable header value/,
    ],
  ];
  for (const [name, claims, message] of failures)
    it(`fails the start with ${name}`, async () => {
      const fixture = await startFixtureHttpServer({ serverName: "tickets" });
      cleanup.push(() => fixture.close());
      const declared = name.includes("email")
        ? { "X-Company-User": { identityClaim: "email" } }
        : headers;
      const optional = governor({
        identityClaims: claims,
        servers: [server(fixture.url, { headers: declared })],
      });
      const [report] = await optional.governor.start();
      expect(report?.state).toBe("failed");
      expect(report?.reason).toMatch(message);
      expect(fixture.requests).toEqual([]);

      const required = governor({
        identityClaims: claims,
        servers: [server(fixture.url, { headers: declared, required: true })],
      });
      const error = await required.governor
        .start()
        .catch((caught: unknown) => caught as PiShipError);
      expect(error).toMatchObject({ code: "MCP_UNHEALTHY" });
      expect(String((error as Error).message)).not.toContain("X-Admin");
    });

  it("sends a verified email", async () => {
    const fixture = await startFixtureHttpServer({
      serverName: "tickets",
      recordHeader: "X-Company-Mail",
    });
    cleanup.push(() => fixture.close());
    const { governor: g } = governor({
      identityClaims: async () => ({
        email: "alice@acme.example",
        email_verified: true,
      }),
      servers: [
        server(fixture.url, {
          headers: { "X-Company-Mail": { identityClaim: "email" } },
        }),
      ],
    });
    expect((await g.start())[0]?.state).toBe("healthy");
    expect(fixture.requests[0]?.recorded).toBe("alice@acme.example");
  });

  it("re-checks header names and claims when the transport is built", () => {
    const build = (
      headers: Record<string, { identityClaim: string }>,
    ): StreamableHttpTransport =>
      new StreamableHttpTransport({
        serverId: "tickets",
        url: "https://mcp.acme.example/mcp",
        fetch: notCalled,
        identityHeaders: headers,
        identityClaims: async () => ({ sub: "u-1" }),
      });
    expect(() => build({ "X-User": { identityClaim: "sub" } })).not.toThrow();
    for (const name of ["Authorization", "x-forwarded-for", "X Bad"])
      expect(() => build({ [name]: { identityClaim: "sub" } })).toThrow(
        PiShipError,
      );
    for (const claim of ["name", "groups"])
      expect(() => build({ "X-User": { identityClaim: claim } })).toThrow(
        /not an identity claim a header may carry/,
      );
  });

  it("fails a running session's tool call after the principal changes", async () => {
    const fixture = await startFixtureHttpServer({
      serverName: "tickets",
      recordHeader: "X-Company-User",
    });
    cleanup.push(() => fixture.close());
    let switched = false;
    const { governor: g, audit } = governor({
      identityClaims: async () => {
        if (switched)
          throw new PiShipError(
            "IDENTITY_REQUIRED",
            "Another identity signed in since launch",
          );
        return { preferred_username: user };
      },
      servers: [server(fixture.url, { headers })],
    });
    expect((await g.start())[0]?.state).toBe("healthy");
    const sent = fixture.requests.length;
    switched = true;
    const search = g.tools().find((tool) => tool.tool === "search");
    const failed = await search?.call({ query: "q" }).then(
      (result) => JSON.stringify(result),
      (error: unknown) => String(error),
    );
    expect(failed).toMatch(/Another identity signed in since launch/);
    // The server itself stays up; only requests that need the header fail.
    expect(g.health()[0]?.state).toBe("healthy");
    // Nothing more reached the server, and no value was recorded anywhere.
    expect(fixture.requests.length).toBe(sent);
    expect(JSON.stringify(audit)).not.toContain(user);
  });

  it("fails the start when no identity is offered at all", async () => {
    const { governor: g } = governor({
      fetch: notCalled,
      servers: [server("https://mcp.acme.example/mcp", { headers })],
    });
    const [report] = await g.start();
    expect(report?.reason).toMatch(/no signed-in identity is available/);
  });
});
