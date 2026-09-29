import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
} from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { selfSignedLoopbackCertificate } from "../../../tests/helpers/x509.js";
import {
  applyProcessNetworkPolicy,
  approvedNetworkEnvironment,
  checkDestination,
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  isNetworkEnvironmentName,
  type NetworkPolicy,
  processNetworkEnvironment,
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

function listen(server: Server, host = "127.0.0.1"): Promise<number> {
  return new Promise((done) => {
    server.listen(0, host, () => done((server.address() as AddressInfo).port));
    cleanup.push(
      () =>
        new Promise<void>((closed) => {
          server.close(() => closed());
          server.closeAllConnections();
        }),
    );
  });
}

/** Run with exactly these proxy variables in this process, then restore them. */
function withProxyEnvironment(values: Record<string, string>): void {
  const saved = new Map(PROXY_NAMES.map((name) => [name, process.env[name]]));
  cleanup.push(() => {
    for (const [name, value] of saved)
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
  });
  for (const name of PROXY_NAMES) delete process.env[name];
  Object.assign(process.env, values);
}

const direct: NetworkPolicy = {
  ...DEFAULT_NETWORK_POLICY,
  inheritProxyEnvironment: false,
};
const inherited: NetworkPolicy = DEFAULT_NETWORK_POLICY;

describe("proxy exclusions (NO_PROXY)", () => {
  async function scenario() {
    const proxied: string[] = [];
    const proxy = createHttpServer((request: IncomingMessage, response) => {
      proxied.push(request.url ?? "");
      response.end("via proxy");
    });
    const proxyPort = await listen(proxy);
    const targeted: string[] = [];
    const target = createHttpServer((request, response) => {
      targeted.push(request.url ?? "");
      response.end("direct");
    });
    const targetPort = await listen(target);
    return {
      proxyUrl: `http://127.0.0.1:${proxyPort}`,
      targetUrl: `http://127.0.0.1:${targetPort}/gateway`,
      proxied,
      targeted,
    };
  }

  it("reaches an excluded host directly and every other host through the proxy", async () => {
    const seen = await scenario();
    withProxyEnvironment({
      HTTP_PROXY: seen.proxyUrl,
      NO_PROXY: "127.0.0.1",
    });
    const excluded = createManagedFetch(inherited);
    expect(await (await excluded(seen.targetUrl)).text()).toBe("direct");
    expect(seen.targeted).toEqual(["/gateway"]);
    expect(seen.proxied).toEqual([]);

    withProxyEnvironment({
      HTTP_PROXY: seen.proxyUrl,
      NO_PROXY: "other.internal.example",
    });
    const included = createManagedFetch(inherited);
    expect(await (await included(seen.targetUrl)).text()).toBe("via proxy");
    expect(seen.proxied).toEqual([seen.targetUrl]);
    expect(seen.targeted).toEqual(["/gateway"]);
  });

  it("honors a lowercase no_proxy and a host:port entry", async () => {
    const seen = await scenario();
    const port = new URL(seen.targetUrl).port;
    withProxyEnvironment({
      http_proxy: seen.proxyUrl,
      no_proxy: `127.0.0.1:${port}`,
    });
    expect(
      await (await createManagedFetch(inherited)(seen.targetUrl)).text(),
    ).toBe("direct");
    expect(seen.proxied).toEqual([]);

    withProxyEnvironment({
      http_proxy: seen.proxyUrl,
      no_proxy: "127.0.0.1:1",
    });
    expect(
      await (await createManagedFetch(inherited)(seen.targetUrl)).text(),
    ).toBe("via proxy");
  });

  it("ignores the proxy and NO_PROXY together when the proxy environment is not inherited", async () => {
    const seen = await scenario();
    withProxyEnvironment({
      HTTP_PROXY: seen.proxyUrl,
      NO_PROXY: "unrelated.example",
    });
    expect(
      await (await createManagedFetch(direct)(seen.targetUrl)).text(),
    ).toBe("direct");
    expect(seen.proxied).toEqual([]);
  });
});

describe("TLS is never downgraded or disabled", () => {
  it("never reaches an https endpoint over plain HTTP", async () => {
    let plainRequests = 0;
    const plain = createHttpServer((_request, response) => {
      plainRequests += 1;
      response.end("plain");
    });
    plain.on("clientError", (_error, socket) => socket.destroy());
    const port = await listen(plain);
    await expect(
      createManagedFetch(direct)(`https://127.0.0.1:${port}/`),
    ).rejects.toMatchObject({ code: "GATEWAY_UNREACHABLE" });
    expect(plainRequests).toBe(0);
  });

  it("refuses a plain HTTP endpoint on a non-loopback host before any connection, even with a proxy", async () => {
    const proxied: string[] = [];
    const proxy = createHttpServer((request, response) => {
      proxied.push(request.url ?? "");
      response.end("via proxy");
    });
    const proxyPort = await listen(proxy);
    withProxyEnvironment({ HTTP_PROXY: `http://127.0.0.1:${proxyPort}` });
    await expect(
      createManagedFetch(inherited)("http://gateway.internal.example/v1"),
    ).rejects.toMatchObject({ code: "NETWORK_DENIED" });
    expect(proxied).toEqual([]);
  });

  it("does not follow a redirect from https to http", async () => {
    const certificate = selfSignedLoopbackCertificate();
    let plainRequests = 0;
    const plain = createHttpServer((_request, response) => {
      plainRequests += 1;
      response.end("plain");
    });
    const plainPort = await listen(plain);
    const secure = createHttpsServer(
      { cert: certificate.certificate, key: certificate.key },
      (_request, response) => {
        response.writeHead(302, {
          location: `http://127.0.0.1:${plainPort}/downgraded`,
        });
        response.end();
      },
    );
    const securePort = await listen(secure);
    const directory = mkdtempSync(join(tmpdir(), "piship-network-"));
    cleanup.push(() => rmSync(directory, { recursive: true, force: true }));
    const bundle = join(directory, "ca.pem");
    writeFileSync(bundle, certificate.certificate);
    const response = await createManagedFetch({
      ...direct,
      additionalCA: [bundle],
    })(`https://127.0.0.1:${securePort}/`);
    expect(response.status).toBe(302);
    expect(plainRequests).toBe(0);
  });

  it("keeps verifying against a bundle that does not contain the server certificate", async () => {
    const server = selfSignedLoopbackCertificate("server");
    const other = selfSignedLoopbackCertificate("other");
    let served = 0;
    const secure = createHttpsServer(
      { cert: server.certificate, key: server.key },
      (_request, response) => {
        served += 1;
        response.end("private gateway");
      },
    );
    const port = await listen(secure);
    const directory = mkdtempSync(join(tmpdir(), "piship-network-"));
    cleanup.push(() => rmSync(directory, { recursive: true, force: true }));
    const wrong = join(directory, "other-ca.pem");
    writeFileSync(wrong, other.certificate);
    await expect(
      createManagedFetch({ ...direct, additionalCA: [wrong] })(
        `https://127.0.0.1:${port}/`,
      ),
    ).rejects.toMatchObject({ code: "GATEWAY_UNREACHABLE" });
    expect(served).toBe(0);
    const right = join(directory, "server-ca.pem");
    writeFileSync(right, server.certificate);
    const response = await createManagedFetch({
      ...direct,
      additionalCA: [right],
    })(`https://127.0.0.1:${port}/`);
    expect(await response.text()).toBe("private gateway");
  });
});

describe("private-only destinations", () => {
  const policy: NetworkPolicy = {
    ...DEFAULT_NETWORK_POLICY,
    privateOnly: true,
    allowHosts: ["llm.internal.example", "203.0.113.7"],
  };

  it("matches the hostname only: any port and scheme on an allowed host passes", () => {
    for (const url of [
      "https://llm.internal.example/v1",
      "https://llm.internal.example:8443/v1",
      "https://LLM.Internal.Example:1/v1",
    ])
      expect(() => checkDestination(new URL(url), policy)).not.toThrow();
    expect(() =>
      checkDestination(new URL("https://other.internal.example/v1"), policy),
    ).toThrow(expect.objectContaining({ code: "NETWORK_DENIED" }));
  });

  it("does not check that an allowed address is private", () => {
    // 203.0.113.7 is a documentation address, not a private one: listing a
    // public host in allowHosts is honored, and nothing warns about it.
    expect(() =>
      checkDestination(new URL("https://203.0.113.7:9/"), policy),
    ).not.toThrow();
  });
});

describe("approvedNetworkEnvironment", () => {
  it("passes the inherited proxy variables in both cases, with the value PiShip's own clients use", () => {
    const network = approvedNetworkEnvironment(inherited, {
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      http_proxy: "http://lower.corp.example:3128",
      HTTP_PROXY: "http://upper.corp.example:3128",
      NO_PROXY: "localhost,.corp.example",
    });
    expect(network.variables).toEqual({
      HTTP_PROXY: "http://lower.corp.example:3128",
      http_proxy: "http://lower.corp.example:3128",
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      https_proxy: "http://proxy.corp.example:3128",
      NO_PROXY: "localhost,.corp.example",
      no_proxy: "localhost,.corp.example",
    });
    expect(network.proxy).toEqual({
      inherited: true,
      http: "http://lower.corp.example:3128",
      https: "http://proxy.corp.example:3128",
      noProxy: true,
    });
    expect(network.withheld).toEqual([]);
  });

  it("passes no proxy variable when an empty lowercase name shadows the uppercase one, as it does for PiShip", () => {
    const network = approvedNetworkEnvironment(inherited, {
      http_proxy: "",
      HTTP_PROXY: "http://upper.corp.example:3128",
    });
    expect(network.variables).toEqual({});
    expect(network.proxy.http).toBeUndefined();
  });

  it("passes nothing when the proxy environment is not inherited", () => {
    const network = approvedNetworkEnvironment(direct, {
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      NO_PROXY: "localhost",
    });
    expect(network.variables).toEqual({});
    expect(network.proxy).toEqual({
      inherited: false,
      http: undefined,
      https: undefined,
      noProxy: false,
    });
  });

  it("withholds a proxy URL that embeds credentials, and never prints them", () => {
    const network = approvedNetworkEnvironment(inherited, {
      HTTPS_PROXY: "http://svc-account:hunter2@proxy.corp.example:3128",
      HTTP_PROXY: "http://proxy.corp.example:3128",
    });
    expect(Object.keys(network.variables).sort()).toEqual([
      "HTTP_PROXY",
      "http_proxy",
    ]);
    expect(network.proxy.https).toBe("http://proxy.corp.example:3128");
    expect(network.withheld).toEqual([
      {
        name: "HTTPS_PROXY",
        reason: "not passed to child processes: the URL embeds credentials",
      },
    ]);
    const printed = JSON.stringify(network);
    expect(printed).not.toContain("hunter2");
    expect(printed).not.toContain("svc-account");
  });

  it("withholds a proxy that is not an http(s) URL or that looks like a credential", () => {
    const network = approvedNetworkEnvironment(inherited, {
      HTTP_PROXY: "socks5://proxy.corp.example:1080",
      HTTPS_PROXY: "proxy.corp.example:3128",
      NO_PROXY: "Bearer abcdefghijklmnopqrstuvwxyz",
    });
    expect(network.variables).toEqual({});
    expect(network.withheld.map((entry) => entry.name)).toEqual([
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "NO_PROXY",
    ]);
    expect(JSON.stringify(network)).not.toContain("abcdefghijklmnop");
  });

  it("derives NODE_EXTRA_CA_CERTS from one declared bundle, as an absolute path", () => {
    expect(
      approvedNetworkEnvironment(
        { ...direct, additionalCA: ["/etc/corp/ca.pem"] },
        {},
      ).variables,
    ).toEqual({ NODE_EXTRA_CA_CERTS: resolve("/etc/corp/ca.pem") });
    expect(
      approvedNetworkEnvironment(
        { ...direct, additionalCA: ["relative/ca.pem"] },
        {},
      ).variables.NODE_EXTRA_CA_CERTS,
    ).toBe(resolve("relative/ca.pem"));
  });

  it("withholds the CA variable when several bundles are declared, and sets none when none is", () => {
    const several = approvedNetworkEnvironment(
      { ...direct, additionalCA: ["/a.pem", "/b.pem"] },
      {},
    );
    expect(several.variables).toEqual({});
    expect(several.caBundles).toBe(2);
    expect(several.withheld.map((entry) => entry.name)).toEqual([
      "NODE_EXTRA_CA_CERTS",
    ]);
    const none = approvedNetworkEnvironment(direct, {
      NODE_EXTRA_CA_CERTS: "/etc/ambient.pem",
    });
    expect(none.variables).toEqual({});
    expect(none.caBundles).toBe(0);
  });

  it("never passes an ambient CA, other proxy, or TLS-verification variable", () => {
    const ambient = {
      NODE_EXTRA_CA_CERTS: "/etc/ambient.pem",
      SSL_CERT_FILE: "/etc/ssl/all.pem",
      SSL_CERT_DIR: "/etc/ssl/certs",
      CURL_CA_BUNDLE: "/etc/curl.pem",
      REQUESTS_CA_BUNDLE: "/etc/requests.pem",
      GIT_SSL_CAINFO: "/etc/git.pem",
      GIT_SSL_NO_VERIFY: "1",
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
      ALL_PROXY: "socks5://proxy:1080",
    };
    const network = approvedNetworkEnvironment(
      { ...inherited, additionalCA: ["/etc/corp/ca.pem"] },
      { ...ambient, HTTPS_PROXY: "http://proxy.corp.example:3128" },
    );
    expect(Object.keys(network.variables).sort()).toEqual([
      "HTTPS_PROXY",
      "NODE_EXTRA_CA_CERTS",
      "https_proxy",
    ]);
    expect(network.variables.NODE_EXTRA_CA_CERTS).toBe(
      resolve("/etc/corp/ca.pem"),
    );
    for (const name of Object.keys(ambient))
      expect(isNetworkEnvironmentName(name)).toBe(true);
  });

  it("names variables case-insensitively and leaves everything else alone", () => {
    for (const name of [
      "https_proxy",
      "Https_Proxy",
      "no_proxy",
      "ssl_cert_file",
    ])
      expect(isNetworkEnvironmentName(name)).toBe(true);
    for (const name of ["PATH", "HOME", "HTTP_PROXY_EXTRA", "PROXY", "CERT"])
      expect(isNetworkEnvironmentName(name)).toBe(false);
  });

  it("is what the process records when the policy is applied", async () => {
    const { Agent, setGlobalDispatcher } = await import("undici");
    cleanup.push(() => setGlobalDispatcher(new Agent()));
    withProxyEnvironment({ HTTPS_PROXY: "http://proxy.corp.example:3128" });
    applyProcessNetworkPolicy(inherited);
    expect(processNetworkEnvironment()?.variables).toMatchObject({
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      https_proxy: "http://proxy.corp.example:3128",
    });
    applyProcessNetworkPolicy(direct);
    expect(processNetworkEnvironment()?.variables).toEqual({});
  });
});
