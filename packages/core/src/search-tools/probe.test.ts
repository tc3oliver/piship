import { createServer, type Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { probeSearchToolUpstream, SEARCH_TOOL_UPSTREAM_URL } from "./index.js";

const servers: Server[] = [];
const sockets = new Set<Socket>();

async function listen(
  handler: Parameters<typeof createServer>[1],
): Promise<string> {
  const server = createServer(handler);
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  servers.push(server);
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
}

beforeEach(() => {
  // A loopback address is never sent through a proxy of the test machine.
  for (const name of [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
  ])
    vi.stubEnv(name, "");
  vi.stubEnv("NO_PROXY", "127.0.0.1");
  vi.stubEnv("no_proxy", "127.0.0.1");
});

afterEach(async () => {
  vi.unstubAllEnvs();
  for (const socket of sockets) socket.destroy();
  await Promise.all(
    servers
      .splice(0)
      .map((server) => new Promise((done) => server.close(done))),
  );
});

describe("the search tool upstream probe", () => {
  it("probes GitHub's root by default", () => {
    expect(SEARCH_TOOL_UPSTREAM_URL).toBe("https://github.com/");
  });

  it("reports a host that answers as reachable", async () => {
    const url = await listen((_request, response) => response.end("ok"));
    expect(await probeSearchToolUpstream({ url })).toBe(true);
  });

  it("counts any HTTP status as an answer", async () => {
    for (const status of [301, 403, 404, 503]) {
      const url = await listen((_request, response) => {
        response.statusCode = status;
        response.end();
      });
      expect(await probeSearchToolUpstream({ url }), String(status)).toBe(true);
    }
  });

  it("reports a closed port as unreachable", async () => {
    const url = await listen((_request, response) => response.end());
    const [server] = servers;
    await new Promise((done) => server?.close(done));
    expect(await probeSearchToolUpstream({ url })).toBe(false);
  });

  it("gives up on a host that never answers within the timeout", async () => {
    const url = await listen(() => {});
    const started = Date.now();
    expect(await probeSearchToolUpstream({ url, timeoutMs: 300 })).toBe(false);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("allows 3 seconds by default", async () => {
    const url = await listen(() => {});
    const started = Date.now();
    expect(await probeSearchToolUpstream({ url })).toBe(false);
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(2800);
    expect(elapsed).toBeLessThan(5000);
  });

  it("reports an unusable proxy variable as unreachable instead of throwing", async () => {
    vi.stubEnv("HTTPS_PROXY", "http://");
    expect(await probeSearchToolUpstream({ url: "https://127.0.0.1:1/" })).toBe(
      false,
    );
  });
});
