// Transport failures name the hop that failed (the proxy, the target's TLS
// chain, or the target) and carry an action, read from structured error
// fields only. Proxy credentials never appear in what is reported.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
} from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { type AddressInfo, connect as connectSocket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { selfSignedLoopbackCertificate } from "../../../tests/helpers/x509.js";
import { formatError, PiShipError } from "./errors.js";
import {
  checkProxyConnection,
  countCertificates,
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
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

/** A loopback port nothing listens on. */
async function deadPort(): Promise<number> {
  const server = createHttpServer();
  const port = await new Promise<number>((done) =>
    server.listen(0, "127.0.0.1", () =>
      done((server.address() as AddressInfo).port),
    ),
  );
  await new Promise<void>((closed) => server.close(() => closed()));
  return port;
}

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

type ProxyMode = "tunnel" | "auth" | "forbidden" | "blackhole";

/** A loopback proxy: tunnels CONNECT, demands authentication, refuses, or never answers. */
async function proxy(mode: ProxyMode): Promise<{
  port: number;
  seen: string[];
}> {
  const seen: string[] = [];
  const server = createHttpServer((request: IncomingMessage, response) => {
    seen.push(`${request.method} ${request.url}`);
    if (mode === "auth")
      response
        .writeHead(407, { "proxy-authenticate": 'Basic realm="corp"' })
        .end();
    else if (mode === "forbidden") response.writeHead(403).end();
    else if (mode === "blackhole") return;
    else response.writeHead(502).end();
  });
  server.on("connect", (request, socket, head) => {
    seen.push(`CONNECT ${request.url}`);
    // A CONNECT socket leaves the server's connection tracking.
    cleanup.push(() => {
      socket.destroy();
    });
    socket.on("error", () => {});
    if (mode === "auth") {
      socket.end(
        'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="corp"\r\n\r\n',
      );
      return;
    }
    if (mode === "forbidden") {
      socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    if (mode === "blackhole") return;
    const [host, port] = (request.url ?? "").split(":");
    const upstream = connectSocket(Number(port), host ?? "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    cleanup.push(() => {
      upstream.destroy();
    });
    upstream.on("error", () => socket.destroy());
    socket.on("close", () => upstream.destroy());
  });
  const port = await listen(server);
  return { port, seen };
}

async function tlsTarget(): Promise<{ port: number; certificate: string }> {
  const certificate = selfSignedLoopbackCertificate("target");
  const server = createHttpsServer(
    { cert: certificate.certificate, key: certificate.key },
    (_request, response) => response.end("target"),
  );
  return { port: await listen(server), certificate: certificate.certificate };
}

function bundle(pem: string): string {
  const directory = mkdtempSync(join(tmpdir(), "piship-network-failures-"));
  cleanup.push(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, "ca.pem");
  writeFileSync(path, pem);
  return path;
}

async function failure(promise: Promise<unknown>): Promise<PiShipError> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(PiShipError);
  return error as PiShipError;
}

/** Everything a user or a log could see of an error. */
function shown(error: PiShipError): string {
  return `${formatError(error)}\n${JSON.stringify(error)}`;
}

const inherited: NetworkPolicy = DEFAULT_NETWORK_POLICY;
const PROXY_PASSWORD = "pr0xy-hunter2-pass";

describe("a proxy failure names the proxy, not the target", () => {
  it("dead proxy: ECONNREFUSED at the proxy, with an action, and no proxy credential", async () => {
    const target = await tlsTarget();
    const port = await deadPort();
    withProxyEnvironment({
      HTTPS_PROXY: `http://corp-user:${PROXY_PASSWORD}@127.0.0.1:${port}`,
    });
    const error = await failure(
      createManagedFetch(
        { ...inherited, additionalCA: [bundle(target.certificate)] },
        "access",
      )(`https://127.0.0.1:${target.port}/v1/models`),
    );
    expect(error.code).toBe("GATEWAY_UNREACHABLE");
    expect(error.retryable).toBe(true);
    expect(error.message).toContain(`proxy http://127.0.0.1:${port}`);
    expect(error.message).toMatch(/: ECONNREFUSED$/);
    expect(error.userAction).toMatch(/proxy/i);
    expect(error.sanitizedDetail).toMatchObject({
      hop: "proxy",
      proxy: `http://127.0.0.1:${port}`,
      transport: "ECONNREFUSED",
    });
    expect(shown(error)).not.toContain(PROXY_PASSWORD);
    expect(shown(error)).not.toContain("corp-user");
  });

  it("dead forward proxy for a loopback http target names the proxy", async () => {
    const port = await deadPort();
    withProxyEnvironment({
      HTTP_PROXY: `http://corp-user:${PROXY_PASSWORD}@127.0.0.1:${port}`,
    });
    const error = await failure(
      createManagedFetch(
        inherited,
        "access",
      )("http://127.0.0.1:4567/v1/models"),
    );
    expect(error.code).toBe("GATEWAY_UNREACHABLE");
    expect(error.message).toContain(`proxy http://127.0.0.1:${port}`);
    expect(error.message).toMatch(/: ECONNREFUSED$/);
    expect(shown(error)).not.toContain(PROXY_PASSWORD);
  });

  it("407 on CONNECT: the proxy wants credentials", async () => {
    const target = await tlsTarget();
    const auth = await proxy("auth");
    withProxyEnvironment({
      HTTPS_PROXY: `http://corp-user:${PROXY_PASSWORD}@127.0.0.1:${auth.port}`,
    });
    const error = await failure(
      createManagedFetch(
        { ...inherited, additionalCA: [bundle(target.certificate)] },
        "access",
      )(`https://127.0.0.1:${target.port}/v1/models`),
    );
    expect(auth.seen).toEqual([`CONNECT 127.0.0.1:${target.port}`]);
    expect(error.code).toBe("NETWORK_DENIED");
    expect(error.retryable).toBe(false);
    expect(error.message).toContain(`proxy http://127.0.0.1:${auth.port}`);
    expect(error.message).toContain("HTTP 407");
    expect(error.userAction).toMatch(/proxy credential/i);
    expect(error.sanitizedDetail).toMatchObject({ hop: "proxy", status: 407 });
    expect(shown(error)).not.toContain(PROXY_PASSWORD);
    expect(shown(error)).not.toContain("corp-user");
  });

  it("407 from a forward proxy for a loopback http target", async () => {
    const auth = await proxy("auth");
    withProxyEnvironment({ HTTP_PROXY: `http://127.0.0.1:${auth.port}` });
    const error = await failure(
      createManagedFetch(
        inherited,
        "access",
      )("http://127.0.0.1:4567/v1/models"),
    );
    expect(error.code).toBe("NETWORK_DENIED");
    expect(error.message).toContain(`proxy http://127.0.0.1:${auth.port}`);
    expect(error.message).toContain("HTTP 407");
  });

  it("403 on CONNECT: the proxy refuses the destination", async () => {
    const target = await tlsTarget();
    const forbidden = await proxy("forbidden");
    withProxyEnvironment({
      HTTPS_PROXY: `http://127.0.0.1:${forbidden.port}`,
    });
    const error = await failure(
      createManagedFetch(
        inherited,
        "access",
      )(`https://127.0.0.1:${target.port}/`),
    );
    expect(error.code).toBe("NETWORK_DENIED");
    expect(error.message).toContain("HTTP 403");
    expect(error.userAction).toMatch(/proxy/i);
  });

  it("blackholed proxy: a deadline that expires before the tunnel opens names the proxy", async () => {
    const target = await tlsTarget();
    const hole = await proxy("blackhole");
    withProxyEnvironment({
      HTTPS_PROXY: `http://corp-user:${PROXY_PASSWORD}@127.0.0.1:${hole.port}`,
    });
    const error = await failure(
      createManagedFetch(inherited, "inference")(
        `https://127.0.0.1:${target.port}/v1/models`,
        { signal: AbortSignal.timeout(300) },
      ),
    );
    expect(hole.seen).toEqual([`CONNECT 127.0.0.1:${target.port}`]);
    expect(error.code).toBe("GATEWAY_UNREACHABLE");
    expect(error.retryable).toBe(true);
    expect(error.message).toContain(`proxy http://127.0.0.1:${hole.port}`);
    expect(error.message).toMatch(/did not open a tunnel/);
    expect(error.userAction).toMatch(/proxy/i);
    expect(shown(error)).not.toContain(PROXY_PASSWORD);
  });

  it("a caller's own cancellation stays an AbortError, even while the tunnel is pending", async () => {
    const target = await tlsTarget();
    const hole = await proxy("blackhole");
    withProxyEnvironment({ HTTPS_PROXY: `http://127.0.0.1:${hole.port}` });
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 200);
    await expect(
      createManagedFetch(inherited)(`https://127.0.0.1:${target.port}/`, {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("an untrusted TLS chain names the host and suggests additionalCA", () => {
  it("direct: the target's chain is not trusted", async () => {
    const target = await tlsTarget();
    const error = await failure(
      createManagedFetch(
        { ...inherited, inheritProxyEnvironment: false },
        "access",
      )(`https://127.0.0.1:${target.port}/v1/models`),
    );
    expect(error.code).toBe("TLS_POLICY_VIOLATION");
    expect(error.retryable).toBe(false);
    expect(error.message).toContain(`127.0.0.1:${target.port}`);
    expect(error.message).toMatch(
      /\((?:DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE)\)$/,
    );
    expect(error.userAction).toContain("network.tls.additionalCA");
    expect(error.sanitizedDetail).toMatchObject({ hop: "target" });
  });

  it("through a proxy: the target's chain is blamed, not the proxy", async () => {
    const target = await tlsTarget();
    const tunnel = await proxy("tunnel");
    withProxyEnvironment({
      HTTPS_PROXY: `http://corp-user:${PROXY_PASSWORD}@127.0.0.1:${tunnel.port}`,
    });
    const error = await failure(
      createManagedFetch(
        inherited,
        "access",
      )(`https://127.0.0.1:${target.port}/v1/models`),
    );
    expect(tunnel.seen).toEqual([`CONNECT 127.0.0.1:${target.port}`]);
    expect(error.code).toBe("TLS_POLICY_VIOLATION");
    expect(error.message).toContain(`127.0.0.1:${target.port}`);
    expect(error.message).not.toContain("proxy");
    expect(error.userAction).toContain("network.tls.additionalCA");
    expect(shown(error)).not.toContain(PROXY_PASSWORD);
  });

  it("through a proxy: the declared additionalCA is trusted for the target", async () => {
    const target = await tlsTarget();
    const tunnel = await proxy("tunnel");
    withProxyEnvironment({ HTTPS_PROXY: `http://127.0.0.1:${tunnel.port}` });
    const response = await createManagedFetch({
      ...inherited,
      additionalCA: [bundle(target.certificate)],
    })(`https://127.0.0.1:${target.port}/`);
    expect(await response.text()).toBe("target");
    expect(tunnel.seen).toEqual([`CONNECT 127.0.0.1:${target.port}`]);
  });
});

describe("a target failure without a proxy still names the target", () => {
  it("connection refused", async () => {
    const port = await deadPort();
    const error = await failure(
      createManagedFetch(
        { ...inherited, inheritProxyEnvironment: false },
        "access",
      )(`http://127.0.0.1:${port}/`),
    );
    expect(error.code).toBe("GATEWAY_UNREACHABLE");
    expect(error.message).toBe(
      `access request to 127.0.0.1:${port} failed: ECONNREFUSED`,
    );
  });
});

describe("doctor's proxy and CA checks", () => {
  it("opens a connection to a running proxy, and names the code for a dead one", async () => {
    const running = await proxy("tunnel");
    expect(
      await checkProxyConnection(`http://127.0.0.1:${running.port}`),
    ).toBeUndefined();
    const port = await deadPort();
    expect(await checkProxyConnection(`http://127.0.0.1:${port}`)).toBe(
      "ECONNREFUSED",
    );
    expect(running.seen).toEqual([]);
  });

  it("counts the certificates of the declared bundles, and fails as loading does", () => {
    const first = selfSignedLoopbackCertificate("one").certificate;
    const second = selfSignedLoopbackCertificate("two").certificate;
    expect(countCertificates([bundle(first + second), bundle(first)])).toBe(3);
    expect(countCertificates([])).toBe(0);
    expect(() => countCertificates([bundle("not a certificate")])).toThrow(
      expect.objectContaining({ code: "CONFIG_INVALID" }),
    );
    expect(() =>
      countCertificates([
        bundle(
          "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
        ),
      ]),
    ).toThrow(/does not parse/);
  });
});
