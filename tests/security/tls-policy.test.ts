import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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

// The environment an in-process extension could set at any time is data, read
// from a fixture by a child process that creates the client first: the
// parent never switches verification off in its own process.
const VERIFICATION_OFF = fileURLToPath(
  new URL("../fixtures/tls-verification-off.json", import.meta.url),
);
const REPOSITORY = fileURLToPath(new URL("../../", import.meta.url));
const CHILD = `
import { readFileSync } from "node:fs";
import { createManagedFetch, DEFAULT_NETWORK_POLICY } from "@piship/contracts";
const client = createManagedFetch({
  ...DEFAULT_NETWORK_POLICY,
  inheritProxyEnvironment: false,
  additionalCA: [process.env.TEST_CA],
});
const before = await (await client(process.env.TEST_URL)).text();
Object.assign(process.env, JSON.parse(readFileSync(process.env.TEST_LATE_ENVIRONMENT, "utf8")));
let code = "none";
try {
  await client(process.env.TEST_URL);
} catch (error) {
  code = error.code;
}
console.log(JSON.stringify({ before, code }));
`;

/** Run `script` in a child node process and resolve with its output. */
function inChild(
  script: string,
  env: Record<string, string>,
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ["--input-type=module", "-e", script],
      { cwd: REPOSITORY, env: { ...process.env, ...env } },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

describe("disabling verification after a client exists", () => {
  it("refuses the next request, before any connection", async () => {
    let served = 0;
    const certificate = selfSignedLoopbackCertificate();
    const server = createHttpsServer(
      { cert: certificate.certificate, key: certificate.key },
      (_request, response) => {
        served += 1;
        response.end("ok");
      },
    );
    const port = await listen(server);
    const bundle = join(temp(), "ca.pem");
    writeFileSync(bundle, certificate.certificate);

    const child = await inChild(CHILD, {
      TEST_CA: bundle,
      TEST_URL: `https://127.0.0.1:${port}/`,
      TEST_LATE_ENVIRONMENT: VERIFICATION_OFF,
    });
    expect(child.status, child.stderr).toBe(0);
    const result = JSON.parse(child.stdout) as { before: string; code: string };
    // The control: the client works while verification is on.
    expect(result.before).toBe("ok");
    // Then it refuses, and the server was asked for nothing more.
    expect(result.code).toBe("TLS_POLICY_VIOLATION");
    expect(served).toBe(1);
  });
});
