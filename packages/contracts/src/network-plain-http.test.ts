// `httpTransport: http-allowed`: plain HTTP is admitted only to the exact
// origin of the endpoint that opted in, on that endpoint's fetch and, for the
// inference gateway, on the process dispatcher Pi's provider requests use.
// A local forward proxy stands in for the private hosts: the destination
// check runs on the target origin before the request reaches the proxy.
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { afterEach, describe, expect, it } from "vitest";
import {
  applyProcessNetworkPolicy,
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
  plainHttpOrigins,
  plainHttpProxy,
} from "./network.js";

const PROXY_NAMES = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
];
const cleanup: (() => void | Promise<void>)[] = [];
afterEach(async () => {
  for (const undo of cleanup.splice(0).reverse()) await undo();
});

function listen(server: Server): Promise<number> {
  return new Promise((done) => {
    server.listen(0, "127.0.0.1", () =>
      done((server.address() as AddressInfo).port),
    );
    cleanup.push(
      () =>
        new Promise<void>((closed) => {
          server.close(() => closed());
          server.closeAllConnections();
        }),
    );
  });
}

/** A forward proxy on loopback that answers every request; the URLs it saw. */
async function proxy(): Promise<string[]> {
  const seen: string[] = [];
  const port = await listen(
    createServer((request: IncomingMessage, response) => {
      seen.push(request.url ?? "");
      response.end("ok");
    }),
  );
  const saved = new Map(PROXY_NAMES.map((name) => [name, process.env[name]]));
  cleanup.push(() => {
    for (const [name, value] of saved)
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
  });
  for (const name of PROXY_NAMES) delete process.env[name];
  process.env.HTTP_PROXY = `http://127.0.0.1:${port}`;
  return seen;
}

const GATEWAY = "http://10.99.236.70:4000/v1";
const privateOnly: NetworkPolicy = {
  ...DEFAULT_NETWORK_POLICY,
  privateOnly: true,
  allowHosts: ["10.99.236.70", "10.99.236.71", "broker.corp.internal"],
};

describe("plainHttpOrigins", () => {
  it("admits plain HTTP to the exact origin of a private plain-HTTP URL only", () => {
    const admit = plainHttpOrigins([GATEWAY]);
    expect(admit?.(new URL("http://10.99.236.70:4000/v1/models"))).toBe(true);
    // Another port, another private host, or https is not this origin.
    expect(admit?.(new URL("http://10.99.236.70:4001/v1"))).toBe(false);
    expect(admit?.(new URL("http://10.99.236.70/v1"))).toBe(false);
    expect(admit?.(new URL("http://10.99.236.71:4000/v1"))).toBe(false);
    expect(admit?.(new URL("https://10.99.236.70:4000/v1"))).toBe(false);
  });

  it("is undefined unless a URL is plain HTTP to a private or internal host", () => {
    expect(plainHttpOrigins([])).toBeUndefined();
    expect(plainHttpOrigins([undefined, "not a url"])).toBeUndefined();
    expect(plainHttpOrigins(["https://10.99.236.70:4000/v1"])).toBeUndefined();
    expect(
      plainHttpOrigins(["http://gateway.acme.example/v1"]),
    ).toBeUndefined();
    expect(plainHttpOrigins(["http://8.8.8.8/v1"])).toBeUndefined();
  });
});

describe("an opted-in endpoint's managed fetch", () => {
  it("reaches its own origin over plain HTTP and refuses every other plain-HTTP host", async () => {
    const seen = await proxy();
    const plainHttp = plainHttpOrigins([GATEWAY]);
    if (!plainHttp) throw new Error("expected a predicate");
    const fetcher = createManagedFetch(privateOnly, "access", { plainHttp });
    const response = await fetcher(`${GATEWAY}/models`);
    expect(await response.text()).toBe("ok");
    expect(seen).toEqual([`${GATEWAY}/models`]);
    for (const other of [
      "http://10.99.236.71:4000/v1/models",
      "http://10.99.236.70:4001/v1/models",
      "http://broker.corp.internal/token",
    ])
      await expect(fetcher(other)).rejects.toMatchObject({
        code: "NETWORK_DENIED",
        message: expect.stringContaining("Refusing non-HTTPS endpoint"),
      });
    // Another consumer's fetch from the same policy is not widened.
    await expect(
      createManagedFetch(privateOnly, "access")(`${GATEWAY}/models`),
    ).rejects.toMatchObject({ code: "NETWORK_DENIED" });
    expect(seen).toHaveLength(1);
  });

  it("never widens a private-only policy's hosts", async () => {
    await proxy();
    const plainHttp = plainHttpOrigins(["http://10.1.1.1/v1"]);
    if (!plainHttp) throw new Error("expected a predicate");
    await expect(
      createManagedFetch(privateOnly, "access", { plainHttp })(
        "http://10.1.1.1/v1",
      ),
    ).rejects.toThrow(/Private-only network policy denies/);
  });
});

describe("plain HTTP through a proxy", () => {
  /** Run with exactly these proxy variables, restored afterwards. */
  function environment(values: Record<string, string>): void {
    const saved = new Map(PROXY_NAMES.map((name) => [name, process.env[name]]));
    cleanup.push(() => {
      for (const [name, value] of saved)
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
    });
    for (const name of PROXY_NAMES) delete process.env[name];
    Object.assign(process.env, values);
  }

  it("names the proxy undici would use, honoring NO_PROXY", () => {
    const target = new URL(`${GATEWAY}/models`);
    const env = { HTTP_PROXY: "http://proxy.acme.example:3128" };
    expect(plainHttpProxy(target, DEFAULT_NETWORK_POLICY, env)?.host).toBe(
      "proxy.acme.example:3128",
    );
    expect(
      plainHttpProxy(
        target,
        { ...DEFAULT_NETWORK_POLICY, inheritProxyEnvironment: false },
        env,
      ),
    ).toBeUndefined();
    for (const noProxy of ["10.99.236.70", "localhost, 10.99.236.70:4000", "*"])
      expect(
        plainHttpProxy(target, DEFAULT_NETWORK_POLICY, {
          ...env,
          NO_PROXY: noProxy,
        }),
        noProxy,
      ).toBeUndefined();
    expect(
      plainHttpProxy(target, DEFAULT_NETWORK_POLICY, {
        ...env,
        NO_PROXY: "10.99.236.70:8080",
      }),
    ).toBeDefined();
    expect(
      plainHttpProxy(
        new URL("http://gw.corp.internal/v1"),
        DEFAULT_NETWORK_POLICY,
        { ...env, no_proxy: ".corp.internal" },
      ),
    ).toBeUndefined();
  });

  it("refuses an opted-in plain-HTTP request through a public proxy, on the fetch and the dispatcher", async () => {
    environment({ HTTP_PROXY: "http://proxy.acme.example:3128" });
    const plainHttp = plainHttpOrigins([GATEWAY]);
    if (!plainHttp) throw new Error("expected a predicate");
    const refusal = {
      code: "NETWORK_DENIED",
      message: expect.stringContaining(
        "through the proxy http://proxy.acme.example:3128, which is not a private or internal host",
      ),
      userAction: expect.stringContaining("Add 10.99.236.70 to NO_PROXY"),
    };
    for (const policy of [privateOnly, DEFAULT_NETWORK_POLICY])
      await expect(
        createManagedFetch(policy, "access", { plainHttp })(
          `${GATEWAY}/models`,
        ),
      ).rejects.toMatchObject(refusal);
    const saved = getGlobalDispatcher();
    cleanup.push(() => setGlobalDispatcher(saved));
    for (const policy of [privateOnly, DEFAULT_NETWORK_POLICY]) {
      applyProcessNetworkPolicy(policy, { plainHttp });
      await expect(fetch(`${GATEWAY}/models`)).rejects.toThrow();
    }
  });
});

describe("applyProcessNetworkPolicy plainHttp", () => {
  it("admits plain HTTP to the gateway's origin only on the process dispatcher", async () => {
    const saved = getGlobalDispatcher();
    cleanup.push(() => setGlobalDispatcher(saved));
    const seen = await proxy();
    const plainHttp = plainHttpOrigins([GATEWAY]);
    applyProcessNetworkPolicy(privateOnly, plainHttp ? { plainHttp } : {});
    const response = await fetch(`${GATEWAY}/chat/completions`);
    expect(await response.text()).toBe("ok");
    expect(seen).toEqual([`${GATEWAY}/chat/completions`]);
    // Another private host the policy allows is still refused over plain HTTP.
    await expect(fetch("http://10.99.236.71:4000/v1")).rejects.toThrow();
    await expect(fetch("http://broker.corp.internal/token")).rejects.toThrow();
    expect(seen).toHaveLength(1);
  });

  it("without the option, the process dispatcher refuses the gateway over plain HTTP", async () => {
    const saved = getGlobalDispatcher();
    cleanup.push(() => setGlobalDispatcher(saved));
    const seen = await proxy();
    applyProcessNetworkPolicy(privateOnly);
    await expect(fetch(`${GATEWAY}/models`)).rejects.toThrow();
    expect(seen).toEqual([]);
  });
});
