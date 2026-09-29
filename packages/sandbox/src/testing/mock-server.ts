// A recording HTTP server for mock sandbox services. Test-only: this directory
// is excluded from the package build and never reaches `dist`.
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { SANDBOX_READY_MARKER } from "../activate.js";

export interface Recorded {
  readonly method: string;
  readonly path: string;
  readonly headers: IncomingMessage["headers"];
  readonly body: Buffer;
}

export type Handler = (
  request: Recorded,
  response: ServerResponse,
  raw: IncomingMessage,
) => void | Promise<void>;

export interface MockServer {
  server: Server;
  url: string;
  requests: Recorded[];
}

let servers: Server[] = [];

/**
 * Listen on a loopback port and record every request before it reaches the
 * handler. The server stays open until `closeMockServers()` runs.
 */
export async function serve(handler: Handler): Promise<MockServer> {
  const requests: Recorded[] = [];
  const server = createServer((raw, response) => {
    const chunks: Buffer[] = [];
    raw.on("data", (chunk: Buffer) => chunks.push(chunk));
    raw.on("end", () => {
      const request = {
        method: raw.method ?? "GET",
        path: raw.url ?? "/",
        headers: raw.headers,
        body: Buffer.concat(chunks),
      };
      requests.push(request);
      void Promise.resolve(handler(request, response, raw)).catch(() => {
        response.statusCode = 500;
        response.end();
      });
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  servers.push(server);
  return { server, url: `http://127.0.0.1:${port}`, requests };
}

/** Close every server started since the last call; run it in `afterEach`. */
export async function closeMockServers(): Promise<void> {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise((done) => server.close(done));
  }
  servers = [];
}

/** A check-command answer: the marker line and a blocked outbound check. */
export function checkAnswer(unlisted: string | undefined): string {
  return `${SANDBOX_READY_MARKER} ${unlisted ?? "unset"}\npiship-network-blocked\n`;
}
