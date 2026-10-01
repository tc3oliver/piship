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

describe("loopback receiver: stray requests", () => {
  const pending = Symbol("pending");
  const settled = (promise: Promise<URL>) =>
    Promise.race([
      promise.then(
        (url) => url,
        (error: unknown) => error,
      ),
      new Promise((resolve) => setTimeout(() => resolve(pending), 50)),
    ]);

  it("answers stray requests without ending the sign-in, then takes the matching callback", async () => {
    const receiver = await startLoopbackReceiver("http://127.0.0.1/callback", {
      state: "expected-state",
    });
    try {
      const at = (path: string, init?: RequestInit) =>
        fetch(new URL(path, receiver.redirectUri), init);
      expect((await at("/favicon.ico")).status).toBe(404);
      expect((await at("/callback?code=c", { method: "POST" })).status).toBe(
        404,
      );
      const mismatched = await at("/callback?code=c&state=attacker-state");
      expect(mismatched.status).toBe(400);
      expect(await mismatched.text()).toMatch(/does not belong/);
      expect((await at("/callback?code=c")).status).toBe(400);
      expect(
        (await at("/callback?error=access_denied&state=other")).status,
      ).toBe(400);
      expect(await settled(receiver.callback)).toBe(pending);
      const genuine = await at("/callback?code=real&state=expected-state");
      expect(genuine.status).toBe(200);
      const url = await receiver.callback;
      expect(url.searchParams.get("code")).toBe("real");
    } finally {
      await receiver.close();
    }
  });

  it("names refused callbacks and the provider's error in the timeout", async () => {
    const receiver = await startLoopbackReceiver("http://127.0.0.1/callback", {
      state: "expected-state",
      timeoutMs: 300,
    });
    try {
      const refused = await fetch(
        new URL("/callback?error=unauthorized_client", receiver.redirectUri),
      );
      expect(refused.status).toBe(400);
      const error = await receiver.callback.catch((caught: unknown) => caught);
      expect(error).toMatchObject({
        code: "IDENTITY_REQUIRED",
        message: expect.stringMatching(
          /timed out.*refused 1 callback.*state.*unauthorized_client/,
        ),
        userAction: expect.stringMatching(/client/),
      });
    } finally {
      await receiver.close();
    }
  });

  it("keeps cancellation plain when nothing was refused", async () => {
    const controller = new AbortController();
    const receiver = await startLoopbackReceiver("http://127.0.0.1/callback", {
      state: "expected-state",
      signal: controller.signal,
    });
    controller.abort();
    await expect(receiver.callback).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: "Sign-in was cancelled",
    });
    await receiver.close();
  });
});
