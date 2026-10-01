import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { startLoopbackReceiver } from "./loopback.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve) => server.close(() => resolve())),
      ),
  );
});

async function occupiedPort(): Promise<number> {
  const server = createServer();
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

describe("loopback receiver", () => {
  it("names the busy redirect port and how to free it", async () => {
    const port = await occupiedPort();
    const error = await startLoopbackReceiver(
      `http://127.0.0.1:${port}/callback`,
    ).catch((caught: unknown) => caught);
    expect(error).toMatchObject({
      code: "CONFIG_UNAVAILABLE",
      component: "identity",
      message: expect.stringContaining(`port ${port} is already in use`),
      userAction: expect.stringContaining("Another login may still be running"),
    });
    expect((error as { userAction: string }).userAction).toContain(
      String(port),
    );
  });
});
