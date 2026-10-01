// A file of its own: undici drives its header and body timeouts from one
// shared tick timer, created on first use. These tests fake that timer, so no
// earlier request in this process may have created it with the real one.
import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createManagedFetch, DEFAULT_NETWORK_POLICY } from "./network.js";

/** Past undici's default 300 s header and body timeouts. */
const LONG_MS = 3_600_000;

let held: ServerResponse[] = [];
const server = createServer((_request, response) => {
  // Answer only when the test releases it, as a router does once a long
  // command ends.
  held.push(response);
});
let url = "";

beforeEach(async () => {
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/execute`;
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});

afterEach(async () => {
  vi.useRealTimers();
  held = [];
  server.closeAllConnections();
  await new Promise((done) => server.close(done));
});

/** Real I/O turns until the server holds `count` requests. */
async function received(count: number): Promise<void> {
  for (let turn = 0; held.length < count; turn++) {
    if (turn > 10_000) throw new Error("the request never arrived");
    await new Promise((done) => setImmediate(done));
  }
}

/** Advance the faked clock in 499 ms steps (undici's tick), with real I/O between. */
async function elapse(ms: number): Promise<void> {
  for (let left = ms; left > 0; left -= 499) {
    await vi.advanceTimersByTimeAsync(Math.min(499, left));
    await new Promise((done) => setImmediate(done));
  }
}

describe("a long-running managed request", () => {
  it("waits as long as the work it started, while a normal request still times out", async () => {
    const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY, "sandbox");
    const normal = fetch(url, { method: "POST", body: "{}" });
    normal.catch(() => undefined);
    const long = fetch(url, { method: "POST", body: "{}", longRunning: true });
    let settled = false;
    long.then(
      () => (settled = true),
      () => (settled = true),
    );
    await received(2);
    await elapse(LONG_MS);
    // The default stays: a request nothing bounds is not left waiting forever.
    await expect(normal).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      message: expect.stringContaining("UND_ERR_HEADERS_TIMEOUT"),
    });
    expect(settled).toBe(false);
    held[1]?.end('{"exit_code":0}');
    const response = await long;
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('{"exit_code":0}');
  });

  it("is still ended by its caller's signal", async () => {
    const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY, "sandbox");
    const caller = new AbortController();
    const long = fetch(url, {
      method: "POST",
      body: "{}",
      longRunning: true,
      signal: caller.signal,
    });
    long.catch(() => undefined);
    await received(1);
    caller.abort();
    await expect(long).rejects.toMatchObject({ name: "AbortError" });
  });
});
