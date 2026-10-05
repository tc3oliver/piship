// In-process Streamable HTTP MCP fixture for tests and demos.
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { createFixture } from "./fixture-core.mjs";

/**
 * Start a fixture on 127.0.0.1. Options: mode ("json" | "sse"), serverName,
 * protocolVersion, bearer (required Authorization bearer value), session
 * (issue an Mcp-Session-Id, default true), redirect (answer every POST with
 * a 307), recordHeader (a request header whose value each request records
 * as `recorded`). Resolves to { url, calls, cancelled, requests, deleted, close() }.
 */
export async function startFixtureHttpServer(options = {}) {
  const fixture = createFixture({ ...options, envNames: () => [] });
  const requests = [];
  const deleted = [];
  const sessionId = options.session === false ? undefined : randomUUID();
  const server = createServer(async (req, res) => {
    const headers = {
      accept: req.headers.accept,
      sessionId: req.headers["mcp-session-id"],
      protocolVersion: req.headers["mcp-protocol-version"],
      authorized: options.bearer
        ? req.headers.authorization === `Bearer ${options.bearer}`
        : undefined,
      ...(options.recordHeader
        ? { recorded: req.headers[options.recordHeader.toLowerCase()] }
        : {}),
    };
    if (options.redirect) {
      res.writeHead(307, { location: "http://127.0.0.1:9/elsewhere" }).end();
      return;
    }
    if (options.bearer && !headers.authorized) {
      res.writeHead(401).end();
      return;
    }
    if (req.method === "DELETE") {
      deleted.push(headers.sessionId);
      res.writeHead(200).end();
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405).end();
      return;
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const message = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    requests.push({ method: message.method, ...headers });
    const initializing = message.method === "initialize";
    if (sessionId && !initializing && headers.sessionId !== sessionId) {
      res.writeHead(headers.sessionId ? 404 : 400).end();
      return;
    }
    const response = await fixture.handle(message);
    const extra =
      sessionId && initializing ? { "mcp-session-id": sessionId } : {};
    if (!response) {
      res.writeHead(202, extra).end();
      return;
    }
    if (options.mode === "sse") {
      res.writeHead(200, { "content-type": "text/event-stream", ...extra });
      // A server notification first, then the response split across chunks.
      res.write(
        `: keep-alive\nevent: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/message", params: { level: "info", data: "working" } })}\n\n`,
      );
      const payload = JSON.stringify(response);
      const half = Math.floor(payload.length / 2);
      res.write(`id: 1\ndata: ${payload.slice(0, half)}`);
      setTimeout(() => {
        res.write(`${payload.slice(half)}\n\n`);
        // Keep the stream open: the client must stop once it has its answer.
      }, 5);
      return;
    }
    res.writeHead(200, { "content-type": "application/json", ...extra });
    res.end(JSON.stringify(response));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    calls: fixture.calls,
    cancelled: fixture.cancelled,
    requests,
    deleted,
    sessionId,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
