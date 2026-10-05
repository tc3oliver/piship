// `credential.broker.httpTransport: http-allowed`: the broker client acquires
// and revokes over plain HTTP to a private broker host through a fetch that
// admits that origin only. A forward proxy on loopback stands in for the
// private host and relays to the local broker fixture.
import {
  createServer,
  type IncomingMessage,
  request as httpRequest,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type IdentitySession,
  plainHttpOrigins,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { HttpBrokerCredentialProvider } from "./index.js";

const PROXY_NAMES = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
];
const BROKER = "http://broker.corp.internal:8080";
const ctx = { distributionId: "acmecode" };

describe("http-broker over plain HTTP (httpTransport: http-allowed)", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  let identity: IdentitySession;
  let relayed: string[];
  let undo: () => Promise<void>;
  beforeEach(async () => {
    services = await startLocalServices();
    const token = `demo-at-test-${Date.now()}`;
    services.state.accessTokens.set(token, {
      subject: "demo-user-1",
      expires: Math.floor(Date.now() / 1000) + 600,
    });
    identity = {
      subject: "demo-user-1",
      issuer: services.issuer,
      accessToken: new SecretValue(token),
    };
    relayed = [];
    const upstream = new URL(services.base);
    // Relays an absolute-form request for the private broker to the fixture.
    const proxy = createServer(
      (incoming: IncomingMessage, outgoing: ServerResponse) => {
        const target = new URL(incoming.url ?? "/");
        relayed.push(`${target.protocol}//${target.host}${target.pathname}`);
        const forward = httpRequest(
          {
            host: upstream.hostname,
            port: upstream.port,
            method: incoming.method,
            path: `${target.pathname}${target.search}`,
            headers: { ...incoming.headers, host: upstream.host },
          },
          (answer) => {
            outgoing.writeHead(answer.statusCode ?? 502, answer.headers);
            answer.pipe(outgoing);
          },
        );
        incoming.pipe(forward);
      },
    );
    await new Promise<void>((done) => proxy.listen(0, "127.0.0.1", done));
    const saved = new Map(PROXY_NAMES.map((name) => [name, process.env[name]]));
    for (const name of PROXY_NAMES) delete process.env[name];
    process.env.HTTP_PROXY = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    undo = async () => {
      for (const [name, value] of saved)
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      await new Promise<void>((closed) => {
        proxy.close(() => closed());
        proxy.closeAllConnections();
      });
      await services.close();
    };
  });
  afterEach(() => undo());

  const endpoint = `${BROKER}/broker/v1/llm-credential`;
  const revokeEndpoint = `${BROKER}/broker/v1/revoke`;

  it("acquires and revokes through a fetch scoped to the broker's origin", async () => {
    const plainHttp = plainHttpOrigins([endpoint, revokeEndpoint]);
    if (!plainHttp) throw new Error("expected a predicate");
    const broker = new HttpBrokerCredentialProvider({
      endpoint,
      revokeEndpoint,
      expectedBaseUrl: services.gatewayUrl,
      fetch: createManagedFetch(DEFAULT_NETWORK_POLICY, "access", {
        plainHttp,
      }),
    });
    const credential = await broker.acquire(identity, ctx);
    expect(credential.credentialId).toBeTruthy();
    await broker.revoke(credential, ctx);
    expect(relayed).toEqual([endpoint, revokeEndpoint]);
    expect(services.state.revokedCredentials).toHaveLength(1);
  });

  it("is refused without the opt-in, before anything is sent", async () => {
    const broker = new HttpBrokerCredentialProvider({
      endpoint,
      revokeEndpoint,
      expectedBaseUrl: services.gatewayUrl,
      fetch: createManagedFetch(DEFAULT_NETWORK_POLICY, "access"),
    });
    await expect(broker.acquire(identity, ctx)).rejects.toMatchObject({
      code: "NETWORK_DENIED",
    });
    expect(relayed).toEqual([]);
  });
});
