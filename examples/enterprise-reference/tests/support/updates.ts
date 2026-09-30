import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";

// A signed update channel as an update host serves it: a directory over
// loopback HTTP. The reference distribution's `updates.source` is the runtime
// variable `ACMECODE_UPDATE_SOURCE`, so pointing it at this host is all a test
// needs to make `update` reach a channel it built and signed itself.

export interface ChannelHost {
  /** The URL to give `ACMECODE_UPDATE_SOURCE`, with its trailing slash. */
  readonly url: string;
  /** Every path requested so far, in order. */
  readonly requests: readonly string[];
  /** Stop serving and drop open connections. */
  close(): void;
}

export async function serveChannel(directory: string): Promise<ChannelHost> {
  const requests: string[] = [];
  const server = createServer((request, response) => {
    const name = decodeURIComponent(
      new URL(request.url ?? "/", "http://127.0.0.1").pathname.slice(1),
    );
    requests.push(name);
    const path = join(directory, name);
    if (!name || name.includes("/") || !existsSync(path)) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-length": statSync(path).size });
    createReadStream(path).pipe(response);
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`,
    requests,
    close() {
      server.close();
      // close() alone waits for idle keep-alive connections from the updater.
      server.closeAllConnections();
    },
  };
}
