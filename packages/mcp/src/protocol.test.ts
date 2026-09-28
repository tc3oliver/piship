import { PiShipError } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import {
  JsonRpcClient,
  McpSession,
  SseParser,
  StreamableHttpTransport,
  matchesToolPattern,
  parseExternalMcpDefinitions,
  parseIncoming,
  renderToolResult,
  toolPermitted,
} from "./index.js";
import type { JsonRpcMessage, McpTransport } from "./types.js";

/** A scripted in-memory transport. */
function memoryTransport(
  respond: (message: JsonRpcMessage) => unknown | undefined,
): McpTransport & { sent: JsonRpcMessage[] } {
  const sent: JsonRpcMessage[] = [];
  const transport: McpTransport & { sent: JsonRpcMessage[] } = {
    kind: "stdio",
    sent,
    onMessage: undefined,
    onClose: undefined,
    async start() {},
    async send(message) {
      sent.push(message);
      const reply = respond(message);
      if (reply !== undefined)
        queueMicrotask(() => transport.onMessage?.(reply));
    },
    setProtocolVersion() {},
    async close() {
      transport.onClose?.(undefined);
    },
  };
  return transport;
}

describe("JSON-RPC validation", () => {
  it("accepts well-formed messages and rejects malformed ones", () => {
    expect(parseIncoming({ jsonrpc: "2.0", id: 1, result: {} }).kind).toBe(
      "result",
    );
    expect(
      parseIncoming({
        jsonrpc: "2.0",
        id: "a",
        error: { code: -1, message: "x" },
      }).kind,
    ).toBe("error");
    expect(parseIncoming({ jsonrpc: "2.0", method: "n" }).kind).toBe(
      "notification",
    );
    for (const bad of [
      null,
      [],
      { id: 1, result: {} },
      { jsonrpc: "1.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: 1 },
      { jsonrpc: "2.0", id: 1, result: {}, error: { code: 1, message: "" } },
      { jsonrpc: "2.0", id: 1, result: "text" },
      { jsonrpc: "2.0", id: 1.5, result: {} },
      { jsonrpc: "2.0", id: 1, error: { code: "x", message: "m" } },
      { jsonrpc: "2.0", method: 3 },
    ])
      expect(() => parseIncoming(bad)).toThrow(PiShipError);
  });

  it("fails the connection on a protocol violation", async () => {
    const transport = memoryTransport(() => ({ jsonrpc: "2.0", id: 1 }));
    const client = new JsonRpcClient(transport, "bad");
    await expect(
      client.request("tools/list", undefined, { timeoutMs: 1000 }),
    ).rejects.toMatchObject({ code: "MCP_UNHEALTHY" });
    expect(client.closed).toBeInstanceOf(PiShipError);
  });

  it("maps JSON-RPC errors and answers ping", async () => {
    const transport = memoryTransport((message) =>
      "id" in message && "method" in message
        ? {
            jsonrpc: "2.0",
            id: message.id,
            error: { code: -32602, message: "bad params password=hunter22" },
          }
        : undefined,
    );
    const client = new JsonRpcClient(transport, "srv");
    const error = await client
      .request("tools/call", {}, { timeoutMs: 1000 })
      .catch((e: unknown) => e as PiShipError);
    expect(error).toMatchObject({ code: "MCP_UNHEALTHY" });
    expect((error as PiShipError).message).not.toContain("hunter22");
    expect((error as PiShipError).sanitizedDetail).toMatchObject({
      rpcCode: -32602,
    });
    transport.onMessage?.({ jsonrpc: "2.0", id: 99, method: "ping" });
    transport.onMessage?.({ jsonrpc: "2.0", id: 100, method: "sampling/x" });
    expect(transport.sent.slice(-2)).toEqual([
      { jsonrpc: "2.0", id: 99, result: {} },
      {
        jsonrpc: "2.0",
        id: 100,
        error: { code: -32601, message: "Method not found" },
      },
    ]);
  });

  it("times out and sends notifications/cancelled", async () => {
    const transport = memoryTransport(() => undefined);
    const client = new JsonRpcClient(transport, "slow");
    await expect(
      client.request("tools/call", {}, { timeoutMs: 30 }),
    ).rejects.toMatchObject({ code: "MCP_UNHEALTHY", retryable: true });
    expect(transport.sent.at(-1)).toEqual({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: 1, reason: "timeout" },
    });
  });

  it("never cancels initialize", async () => {
    const transport = memoryTransport(() => undefined);
    const session = new McpSession(transport, "init");
    await expect(
      session.initialize({
        timeoutMs: 30,
        clientInfo: { name: "t", version: "1" },
      }),
    ).rejects.toMatchObject({ code: "MCP_UNHEALTHY" });
    expect(transport.sent.map((m) => "method" in m && m.method)).toEqual([
      "initialize",
    ]);
  });

  it("negotiates the protocol version and rejects unknown ones", async () => {
    for (const [answer, ok] of [
      ["2025-06-18", true],
      ["2025-03-26", true],
      ["2024-11-05", true],
      ["2099-01-01", false],
      ["2024-10-07", false],
    ] as const) {
      const transport = memoryTransport((message) =>
        "id" in message && "method" in message
          ? {
              jsonrpc: "2.0",
              id: message.id,
              result: {
                protocolVersion: answer,
                capabilities: { tools: {} },
                serverInfo: { name: "s", version: "1" },
              },
            }
          : undefined,
      );
      const session = new McpSession(transport, "v");
      const result = session.initialize({
        timeoutMs: 1000,
        clientInfo: { name: "t", version: "1" },
      });
      if (ok)
        await expect(result).resolves.toMatchObject({
          protocolVersion: answer,
        });
      else await expect(result).rejects.toThrow(/unsupported protocol version/);
      expect(transport.sent[0]).toMatchObject({
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      });
    }
  });

  it("rejects a repeated tools/list cursor", async () => {
    const transport = memoryTransport((message) =>
      "id" in message && "method" in message
        ? {
            jsonrpc: "2.0",
            id: message.id,
            result: { tools: [], nextCursor: "same" },
          }
        : undefined,
    );
    const session = new McpSession(transport, "loop");
    await expect(session.listTools({ timeoutMs: 1000 })).rejects.toThrow(
      /invalid tools\/list cursor/,
    );
  });
});

describe("SSE parser", () => {
  it("joins data lines, ignores comments and other events, handles CRLF", () => {
    const parser = new SseParser(1024);
    expect(parser.push(": comment\r\nevent: ping\r\ndata: x\r\n\r\n")).toEqual(
      [],
    );
    expect(parser.push('data: {"a":\ndata: 1}\n')).toEqual([]);
    expect(parser.push("\nid: 3\ndata:{}\n\n")).toEqual(['{"a":\n1}', "{}"]);
    expect(parser.push("data: x\r")).toEqual([]);
    expect(parser.push("\n\r\n")).toEqual(["x"]);
  });

  it("enforces the event size limit", () => {
    const parser = new SseParser(16);
    expect(() => parser.push(`data: ${"x".repeat(40)}\n`)).toThrow(
      /byte limit/,
    );
  });
});

describe("tool filtering and results", () => {
  it("applies allow and deny lists with globs; deny wins", () => {
    const tools = { allow: ["get_*", "search"], deny: ["get_secret*"] };
    expect(toolPermitted(tools, "search")).toBe(true);
    expect(toolPermitted(tools, "get_document")).toBe(true);
    expect(toolPermitted(tools, "get_secret_key")).toBe(false);
    expect(toolPermitted(tools, "delete_document")).toBe(false);
    expect(toolPermitted({ allow: [], deny: ["delete_*"] }, "anything")).toBe(
      true,
    );
    expect(toolPermitted({ allow: ["*"], deny: ["*"] }, "x")).toBe(false);
    expect(matchesToolPattern(["a.b"], "aXb")).toBe(false);
  });

  it("renders text, summarizes other parts, redacts, and caps", () => {
    const result = renderToolResult({
      content: [
        { type: "text", text: "hello" },
        { type: "image", mimeType: "image/png", data: "AAAA" },
        { type: "resource", resource: { uri: "file:///a", text: "body" } },
        { type: "resource_link", uri: "file:///b", name: "b" },
        { type: "text", text: "token sk-abcdefghijklmnop" },
      ],
      isError: true,
    });
    expect(result.isError).toBe(true);
    expect(result.text).toContain("hello");
    expect(result.text).toContain(
      "[image content: image/png, 3 bytes omitted]",
    );
    expect(result.text).toContain("[resource file:///a]\nbody");
    expect(result.text).toContain("[resource link: file:///b (b)]");
    expect(result.text).not.toContain("sk-abcdefghijklmnop");
    const capped = renderToolResult(
      { content: [{ type: "text", text: "é".repeat(100) }] },
      51,
    );
    expect(capped.truncated).toBe(true);
    expect(capped.text).toMatch(/^é{25}\n\[output truncated at 51 bytes\]$/);
    expect(
      renderToolResult({ content: [], structuredContent: { a: 1 } }).text,
    ).toBe('{"a":1}');
  });

  it("redacts vendor token shapes from output sent to the model", () => {
    const tokens = [
      `ghp_${"a".repeat(36)}`,
      `xoxb-${"1".repeat(12)}-abcdef`,
      "AKIAABCDEFGHIJKLMNOP",
      `AIza${"b".repeat(35)}`,
      `glpat-${"c".repeat(20)}`,
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----",
    ];
    const { text } = renderToolResult({
      content: tokens.map((token) => ({ type: "text", text: `x ${token} y` })),
    });
    for (const token of tokens) expect(text).not.toContain(token);
    expect(text.match(/\[REDACTED\]/g)).toHaveLength(tokens.length);
  });
});

describe("runtime credential origin binding", () => {
  const transport = (url: string, credentialOrigins: readonly string[]) =>
    new StreamableHttpTransport({
      serverId: "tickets",
      url,
      fetch: async () => {
        throw new Error("not called");
      },
      credential: async () => "gateway-bearer-1234567",
      credentialOrigins,
    });
  it("matches origins with and without an explicit default port", () => {
    expect(() =>
      transport("https://gw.acme.example/mcp", [
        "https://gw.acme.example:443/v1",
      ]),
    ).not.toThrow();
    expect(() =>
      transport("https://gw.acme.example:443/mcp", [
        "https://gw.acme.example/v1",
      ]),
    ).not.toThrow();
    expect(() =>
      transport("https://GW.acme.example/mcp", ["https://gw.acme.example/v1"]),
    ).not.toThrow();
  });
  it("refuses another scheme, port, or host", () => {
    for (const url of [
      "http://gw.acme.example/mcp",
      "https://gw.acme.example:8443/mcp",
      "https://mcp.acme.example/mcp",
      "https://gw.acme.example.evil.example/mcp",
    ])
      expect(() => transport(url, ["https://gw.acme.example/v1"])).toThrow(
        /runtime credential is only sent to https:\/\/gw\.acme\.example$/,
      );
    expect(() =>
      transport("https://gw.acme.example/mcp", ["not a url"]),
    ).toThrow(/inference gateway origin, which is not configured/);
  });
});

describe("Streamable HTTP transport limits", () => {
  it("rejects oversized responses and redirects", async () => {
    const big = new StreamableHttpTransport({
      serverId: "big",
      url: "http://127.0.0.1:1/mcp",
      maxMessageBytes: 64,
      fetch: async () =>
        new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            result: { x: "y".repeat(500) },
          }),
          { headers: { "content-type": "application/json" } },
        ),
    });
    await expect(
      big.send({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    ).rejects.toThrow(/byte limit/);
    let redirect: RequestInit | undefined;
    const moved = new StreamableHttpTransport({
      serverId: "moved",
      url: "http://127.0.0.1:1/mcp",
      fetch: async (_url, init) => {
        redirect = init;
        return new Response(null, {
          status: 307,
          headers: { location: "http://elsewhere" },
        });
      },
    });
    await expect(
      moved.send({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    ).rejects.toThrow(/redirects are not followed/);
    expect(redirect?.redirect).toBe("manual");
  });

  it("refuses URLs with embedded credentials", () => {
    expect(
      () =>
        new StreamableHttpTransport({
          serverId: "x",
          url: "https://user:pw@example.com/mcp",
          fetch: fetch,
        }),
    ).toThrow(/must not embed credentials/);
  });
});

describe("external definitions", () => {
  it("parses stdio and http entries as untrusted and reports invalid ones", () => {
    const parsed = parseExternalMcpDefinitions(
      {
        mcpServers: {
          docs: {
            command: "node",
            args: ["server.js"],
            env: {
              LANG: `\${LANG}`,
              MODE: "demo",
              GITHUB_TOKEN: `\${GITHUB_TOKEN}`,
              API_KEY: "plain",
              OPAQUE: "sk-abcdefghijklmnopqrst",
              RENAMED: `\${HOME}`,
            },
          },
          remote: {
            type: "http",
            url: "https://mcp.example.com/mcp",
            headers: { Authorization: "Bearer x" },
          },
          legacy: { type: "sse", url: "https://example.com/sse" },
          pathy: { command: "./bin/server" },
          "bad name": { command: "node" },
          leak: { command: "node", args: ["--token=sk-abcdefghijklmnop"] },
          query: { url: "https://example.com/mcp?key=1" },
        },
      },
      "project",
    );
    expect(parsed.servers.map((s) => s.id)).toEqual(["docs", "remote"]);
    const docs = parsed.servers[0];
    expect(docs).toMatchObject({
      transport: "stdio",
      command: "node",
      source: "project",
      trusted: false,
      credential: "none",
      required: false,
      env: { allow: ["LANG"], set: { MODE: "demo" } },
    });
    expect(parsed.servers[1]).toMatchObject({
      transport: "streamable-http",
      url: "https://mcp.example.com/mcp",
      credential: "none",
    });
    expect(parsed.invalid.map((i) => i.server).sort()).toEqual(
      ['"bad name"', "leak", "legacy", "pathy", "query"].sort(),
    );
    const warnings = JSON.stringify(parsed.warnings);
    expect(warnings).toContain("GITHUB_TOKEN");
    expect(warnings).toContain("API_KEY");
    expect(warnings).toContain("OPAQUE");
    expect(warnings).toContain("RENAMED");
    expect(warnings).toContain("headers are ignored");
    expect(warnings).not.toContain("sk-abcdefghijklmnopqrst");
    expect(warnings).not.toContain("plain");
  });

  it("reports a malformed document without throwing", () => {
    expect(parseExternalMcpDefinitions("nope", "user")).toMatchObject({
      servers: [],
      invalid: [{ server: "*" }],
    });
  });
});
