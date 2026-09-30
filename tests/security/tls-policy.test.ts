import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
  PiShipError,
} from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import { selfSignedLoopbackCertificate } from "../helpers/x509.js";

// Security case 10 (spec 30.3), TLS downgrade: a broken trust configuration
// stops the client instead of relaxing verification, and switching
// verification off after a client exists does not reach it either. The
// transport-level cases (plain HTTP to a public name, https to http redirect,
// a bundle without the server's certificate, an https URL answered by a plain
// server) are in packages/contracts/src/network.test.ts, and the
// launcher-level ones are in tests/e2e/network.test.ts and
// tests/e2e/security-lifecycle.test.ts.

const cleanup: (() => void | Promise<void>)[] = [];
afterEach(async () => {
  for (const undo of cleanup.splice(0).reverse()) await undo();
});

function temp(): string {
  const directory = mkdtempSync(join(tmpdir(), "piship-tls-policy-"));
  cleanup.push(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  cleanup.push(
    () =>
      new Promise<void>((closed) => {
        server.close(() => closed());
        server.closeAllConnections();
      }),
  );
  return (server.address() as AddressInfo).port;
}

const direct: NetworkPolicy = {
  ...DEFAULT_NETWORK_POLICY,
  inheritProxyEnvironment: false,
};

describe("the trust roots a policy declares", () => {
  it("stops a client whose CA bundle cannot be read, rather than trusting the default roots alone", () => {
    const missing = join(temp(), "corporate-ca.pem");
    let error: unknown;
    try {
      createManagedFetch({ ...direct, additionalCA: [missing] });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({ code: "CONFIG_UNAVAILABLE" });
    expect((error as Error).message).toContain("unreadable");
  });

  it("stops a client whose CA bundle holds no certificate", () => {
    const bundle = join(temp(), "empty-ca.pem");
    writeFileSync(bundle, "not a certificate\n");
    expect(() =>
      createManagedFetch({ ...direct, additionalCA: [bundle] }),
    ).toThrowError(/contains no PEM certificate/);
  });
});

describe("disabling verification after a client exists", () => {
  it("refuses the next request, before any connection", async () => {
    let connections = 0;
    const served = selfSignedLoopbackCertificate();
    const server = createHttpsServer(
      { cert: served.certificate, key: served.key },
      (_request, response) => {
        response.end("ok");
      },
    );
    server.on("connection", () => {
      connections += 1;
    });
    const port = await listen(server);
    const bundle = join(temp(), "ca.pem");
    writeFileSync(bundle, served.certificate);
    const client = createManagedFetch({ ...direct, additionalCA: [bundle] });
    // The control: the client works while verification is on.
    expect(await (await client(`https://127.0.0.1:${port}/`)).text()).toBe(
      "ok",
    );
    const before = connections;

    const saved = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    // An in-process extension can set this at any time.
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    cleanup.push(() => {
      if (saved === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = saved;
    });
    await expect(client(`https://127.0.0.1:${port}/`)).rejects.toMatchObject({
      code: "TLS_POLICY_VIOLATION",
    });
    expect(connections).toBe(before);
  });
});
