// Managed requests through a proxy.
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
import {
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

const inherited: NetworkPolicy = DEFAULT_NETWORK_POLICY;

describe("TLS through a proxy", () => {
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
