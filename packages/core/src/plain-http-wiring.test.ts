// DistributionAccess hands each access client the fetch its own
// httpTransport scopes: the gateway probe, the broker, and OIDC discovery
// reach private plain-HTTP hosts, and nothing else is widened. A forward
// proxy on loopback stands in for the private hosts and relays each request
// to the deterministic local fixtures.
import { mkdtempSync, rmSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  request as httpRequest,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { SecretValue } from "@piship/contracts";
import type { HttpBrokerCredentialProvider } from "@piship/credentials";
import type { AccessManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { DistributionAccess } from "./access/index.js";
import { resolveLock } from "./index.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const PROXY_NAMES = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
];
const GATEWAY = "http://10.20.30.40:4000";
const BROKER = "http://10.20.30.40:8080";
const IDP = "http://keycloak.corp.internal";

type Services = Awaited<ReturnType<typeof startLocalServices>>;
let services: Services;
let relayed: string[];
let undo: () => Promise<void>;
const roots: string[] = [];

beforeEach(async () => {
  services = await startLocalServices();
  relayed = [];
  const upstream = new URL(services.base);
  const proxy = createServer(
    (incoming: IncomingMessage, outgoing: ServerResponse) => {
      const target = new URL(incoming.url ?? "/");
      relayed.push(`${target.origin}${target.pathname}`);
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
    for (const root of roots.splice(0))
      rmSync(root, { recursive: true, force: true });
  };
});
afterEach(() => undo());

/** The demo's access section with the given endpoints opted in. */
function optedIn(
  access: AccessManifest,
  endpoints: readonly ("identity" | "broker" | "inference")[],
): AccessManifest {
  if (access.identity.mode !== "oidc" || !access.credential.broker)
    throw new Error("the demo uses OIDC and the broker");
  const on = { httpTransport: "http-allowed" as const };
  return {
    ...access,
    identity: {
      ...access.identity,
      oidc: {
        ...access.identity.oidc,
        ...(endpoints.includes("identity") ? on : {}),
      },
    },
    credential: {
      ...access.credential,
      broker: {
        ...access.credential.broker,
        ...(endpoints.includes("broker") ? on : {}),
      },
    },
    inference: {
      ...access.inference,
      ...(endpoints.includes("inference") ? on : {}),
    },
  };
}

function open(manifest: AccessManifest): DistributionAccess {
  const lock = resolveLock(DEMO);
  const stateDir = mkdtempSync(join(tmpdir(), "piship-plain-wiring-"));
  roots.push(stateDir);
  const path = (url: string) => new URL(url).pathname;
  return DistributionAccess.open({
    app: lock.app as never,
    mode: "managed",
    access: manifest,
    stateDir,
    distributionDir: stateDir,
    env: {
      ACMECODE_OIDC_ISSUER: `${IDP}${path(services.issuer)}`,
      ACMECODE_OIDC_CLIENT_ID: services.clientId,
      ACMECODE_CREDENTIAL_BROKER_URL: `${BROKER}${path(services.brokerUrl)}`,
      ACMECODE_CREDENTIAL_REVOKE_URL: `${BROKER}${path(services.revokeUrl)}`,
      ACMECODE_LLM_GATEWAY_URL: `${GATEWAY}${path(services.gatewayUrl)}`,
    },
  });
}

const failure = (promise: Promise<unknown>) =>
  promise.then(
    () => undefined,
    (error: unknown) => error as { code?: string },
  );

describe("DistributionAccess plain-HTTP wiring", () => {
  it("gives the gateway, broker, and identity clients their scoped fetches", async () => {
    const lock = resolveLock(DEMO);
    const access = open(
      optedIn(lock.access as AccessManifest, [
        "identity",
        "broker",
        "inference",
      ]),
    );
    // Gateway: the probe reaches the gateway over plain HTTP. Without a
    // credential the fixture answers 401, after the request was relayed.
    const probe = await failure(access.probeGateway());
    expect(probe?.code).not.toBe("NETWORK_DENIED");
    expect(relayed).toContain(
      `${GATEWAY}${new URL(services.gatewayUrl).pathname}/models`,
    );
    // Broker: acquire over plain HTTP with an identity token the fixture knows.
    const token = `demo-at-wiring-${Date.now()}`;
    services.state.accessTokens.set(token, {
      subject: "demo-user-1",
      expires: Math.floor(Date.now() / 1000) + 600,
    });
    const provider = (await access.credentialManager()).options
      .provider as HttpBrokerCredentialProvider;
    const credential = await provider.acquire(
      {
        subject: "demo-user-1",
        issuer: services.issuer,
        accessToken: new SecretValue(token),
      },
      { distributionId: "acmecode" },
    );
    expect(credential.credentialId).toBeTruthy();
    expect(relayed).toContain(
      `${BROKER}${new URL(services.brokerUrl).pathname}`,
    );
    // Identity: discovery is requested from the plain-HTTP issuer. The
    // fixture names itself as issuer, so discovery then fails on the
    // mismatch, after the request was relayed.
    const identity = await access.identityProvider();
    const discovery = await failure(
      (
        identity as unknown as { configuration(): Promise<unknown> }
      ).configuration(),
    );
    expect(discovery?.code).not.toBe("NETWORK_DENIED");
    expect(relayed).toContain(
      `${IDP}${new URL(services.issuer).pathname}/.well-known/openid-configuration`,
    );
  });

  it("scopes each client's fetch to its own origin", async () => {
    const lock = resolveLock(DEMO);
    const access = open(
      optedIn(lock.access as AccessManifest, [
        "identity",
        "broker",
        "inference",
      ]),
    );
    const broker = (
      (await access.credentialManager()).options
        .provider as HttpBrokerCredentialProvider
    ).options.fetch;
    const identity = (
      (await access.identityProvider()) as unknown as {
        options: { fetch: HttpBrokerCredentialProvider["options"]["fetch"] };
      }
    ).options.fetch;
    // The broker shares the gateway's host, not its origin.
    for (const url of [`${GATEWAY}/v1/models`, `${IDP}/realms`])
      expect(await failure(broker(url))).toMatchObject({
        code: "NETWORK_DENIED",
      });
    // Before discovery the identity fetch admits the issuer's origin only.
    for (const url of [`${GATEWAY}/v1/models`, `${BROKER}/token`])
      expect(await failure(identity(url))).toMatchObject({
        code: "NETWORK_DENIED",
      });
    expect(relayed).toEqual([]);
  });
});
