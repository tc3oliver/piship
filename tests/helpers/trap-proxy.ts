import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { onTestFinished } from "vitest";

/**
 * A proxy that answers every request with 502 and records it. The scenario
 * points the proxy variables at it (loopback excluded), so any outbound
 * request through a proxy-aware client shows up here.
 */
export async function trapProxy(): Promise<{ url: string; hits: string[] }> {
  const hits: string[] = [];
  const server = createServer((request, response) => {
    hits.push(`${request.method} ${request.url}`);
    response.writeHead(502).end();
  });
  server.on("connect", (request, socket) => {
    hits.push(`CONNECT ${request.url}`);
    socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  onTestFinished(
    () => new Promise<void>((resolve) => server.close(() => resolve())),
  );
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    hits,
  };
}
