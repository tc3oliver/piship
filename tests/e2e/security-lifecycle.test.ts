import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { mkdirSync, readFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { STATE_DATA_CLASSES } from "@piship/core";
import { describe, expect, it } from "vitest";
import { branded } from "../helpers/distribution.js";
import {
  lifecycleScenario,
  type Scenario,
  type Services,
  scanDecoded,
} from "../helpers/lifecycle.js";
import {
  describeSightings,
  filesUnder,
  SecretLedger,
  scanTree,
  sightings,
} from "../helpers/security.js";
import { selfSignedLoopbackCertificate } from "../helpers/x509.js";

// Security cases 6, 9, 10 and 11 (docs/security.md, security test map) over the lifecycle of one
// installed distribution: credential leakage in the reports of update and
// rollback and in the rollback snapshots, and the network policy and TLS
// that the update transport keeps. The credential-class matrix of
// rollback resurrection is tests/e2e/lifecycle-credentials.test.ts; user
// switching across update and rollback is tests/e2e/user-switching.ts.
// This file adds what neither looked at: what the commands print, what a
// snapshot holds by class, and that the update host is held to the policy.

/**
 * Give the scenario's commands a temp directory inside the scenario, so what
 * they write there is under the directory the sweeps scan.
 */
function ownTemp(s: Scenario): void {
  const tmp = join(s.temp, "tmp");
  mkdirSync(tmp, { recursive: true });
  Object.assign(s.env, { TMPDIR: tmp, TMP: tmp, TEMP: tmp });
}

/** The environment that switches certificate verification off, kept as data. */
const VERIFICATION_OFF = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL("../fixtures/tls-verification-off.json", import.meta.url),
    ),
    "utf8",
  ),
) as Record<string, string>;

const CREDENTIAL_CLASSES = STATE_DATA_CLASSES.filter(
  (entry) => entry.credential || entry.sensitivity === "secret-reference",
).map((entry) => entry.path);

/** Everything a request-counting loopback server saw, for "nothing was contacted" assertions. */
async function watch(kind: "http" | "https" = "http") {
  const requests: string[] = [];
  let handshakes = 0;
  let failures = 0;
  const handler = (request: IncomingMessage, response: ServerResponse) => {
    requests.push(request.url ?? "");
    response.writeHead(404);
    response.end();
  };
  const server: Server =
    kind === "https"
      ? createHttpsServer(selfSignedLoopbackCertificate(), handler)
      : createHttpServer(handler);
  server.on("secureConnection", () => {
    handshakes += 1;
  });
  server.on("tlsClientError", () => {
    failures += 1;
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const port = (server.address() as { port: number }).port;
  return {
    port,
    requests,
    get handshakes() {
      return handshakes;
    },
    get tlsFailures() {
      return failures;
    },
    close: () =>
      new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}

describe("update and rollback keep secrets out of their reports and snapshots (local fixtures)", () => {
  it("prints, snapshots and stores no secret of the run, across an update, a rollback, a user switch and a second update", async () => {
    const s = await lifecycleScenario("security-reports");
    ownTemp(s);
    const services: Services = s.services;
    const ledger = new SecretLedger();
    const outputs = new Map<string, string>();
    const secrets = join(s.state, "acmecode", "secrets");
    const observe = () => {
      ledger.observeServices(services);
      ledger.observeFileStore(secrets);
    };
    const step = async (label: string, args: string[]) => {
      const done = await s.run(args);
      expect(done.status, `${label}: ${done.stderr}`).toBe(0);
      outputs.set(label, `${done.stdout}\n${done.stderr}`);
      observe();
      return done;
    };
    const as = (subject: string, models: string[]) => {
      services.knobs.subject = subject;
      services.knobs.entitledModels = models;
    };
    await s.installFirst();

    as("alice-0001", ["acme/coder", "acme/general"]);
    await step("login-alice", ["login"]);
    await step("smoke-alice", ["--smoke"]);
    expect(ledger.size).toBeGreaterThanOrEqual(4);

    s.publish(1);
    await step("update-check", ["update", "--check"]);
    await step("update", ["update"]);
    // Everything alice held so far, and so everything that must be gone once
    // bob signs in over her.
    const alice = ledger.all();

    // The snapshot the update took holds no credential class and no secret.
    const snapshots = join(s.state, "acmecode", "migration", "snapshots");
    const snapshotFiles = filesUnder(snapshots).map((file) =>
      relative(snapshots, file).split(sep).join("/"),
    );
    expect(snapshotFiles.length).toBeGreaterThan(0);
    for (const file of snapshotFiles) {
      // <snapshot id>/<state-relative path>, or the snapshot's own record.
      const inner = file.split("/").slice(1).join("/");
      expect(
        CREDENTIAL_CLASSES.filter(
          (path) => inner === path || inner.startsWith(`${path}/`),
        ),
      ).toEqual([]);
      expect(inner.startsWith("secrets/")).toBe(false);
    }
    expect(describeSightings(scanTree(snapshots, ledger.all()))).toEqual([]);

    as("bob-0002", ["acme/coder"]);
    await step("login-bob", ["login"]);
    await step("smoke-bob", ["--smoke"]);
    await step("rollback", ["rollback"]);
    await step("smoke-after-rollback", ["--smoke"]);
    s.publish(2);
    await step("update-again", ["update"]);
    await step("rollback-again", ["rollback"]);

    const everything = ledger.all();
    expect(
      [...outputs].flatMap(([label, text]) =>
        describeSightings(sightings(`output of ${label}`, text, everything)),
      ),
    ).toEqual([]);
    // Everything alice held is gone from every file, the store's own
    // directory included; bob's own credential is in the store, not elsewhere.
    expect(alice.length).toBeGreaterThanOrEqual(4);
    expect(scanDecoded(s.state, alice)).toEqual([]);
    expect(scanDecoded(s.install, alice)).toEqual([]);
    expect(
      describeSightings(scanTree(s.state, everything, ["acmecode/secrets"])),
    ).toEqual([]);
    expect(describeSightings(scanTree(s.install, everything))).toEqual([]);

    await step("logout", ["logout"]);
    expect(describeSightings(scanTree(s.temp, ledger.all()))).toEqual([]);
  }, 1200000);
});

describe("the update transport keeps the network policy and TLS (local fixtures)", () => {
  it("contacts only the declared update host, over verified TLS, and follows no redirect", async () => {
    const s = await lifecycleScenario("security-update-network");
    ownTemp(s);
    await s.installFirst();
    s.publish(1);
    const control = await s.run(["update", "--check"]);
    expect(control.status, control.stderr).toBe(0);
    expect(control.stdout).toContain("is available");

    // A --from source the distribution did not declare gets no exception
    // from private-only, though localhost is the same machine.
    const undeclared = await watch();
    try {
      const refused = await s.run([
        "update",
        "--check",
        "--from",
        `http://localhost:${undeclared.port}/`,
      ]);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain("NETWORK_DENIED");
      expect(undeclared.requests).toEqual([]);
    } finally {
      await undeclared.close();
    }

    // Plain HTTP is for loopback only: a public name is refused before any
    // connection, so a proxy that would carry it sees nothing either.
    const proxy = await watch();
    try {
      const via = `http://127.0.0.1:${proxy.port}`;
      const refused = await branded(
        s.command,
        ["update", "--check", "--from", "http://updates.public.invalid/"],
        { cwd: s.temp, env: { ...s.env, HTTP_PROXY: via, http_proxy: via } },
      );
      expect(refused.status).toBe(1);
      expect(refused.stderr).toMatch(/CONFIG_INVALID|NETWORK_DENIED/);
      expect(proxy.requests).toEqual([]);
    } finally {
      await proxy.close();
    }

    // A source with a certificate no root vouches for fails, and PiShip does
    // not fall back to plain HTTP or skip verification for it.
    const untrusted = await watch("https");
    try {
      const failed = await s.run([
        "update",
        "--check",
        "--from",
        `https://127.0.0.1:${untrusted.port}/`,
      ]);
      expect(failed.status).toBe(1);
      // The client refused the certificate (the server counts the failed
      // handshake); it never sent the request, and never retried in the clear.
      expect(failed.stderr).toContain("GATEWAY_UNREACHABLE");
      expect(untrusted.requests).toEqual([]);
      expect(untrusted.handshakes).toBe(0);
      expect(untrusted.tlsFailures).toBeGreaterThan(0);
      // With verification switched off in the environment the command
      // refuses to start the request at all.
      const before = untrusted.tlsFailures;
      const insecure = await branded(
        s.command,
        ["update", "--check", "--from", `https://127.0.0.1:${untrusted.port}/`],
        { cwd: s.temp, env: { ...s.env, ...VERIFICATION_OFF } },
      );
      expect(insecure.status).toBe(1);
      expect(insecure.stderr).toContain("TLS_POLICY_VIOLATION");
      expect(untrusted.handshakes).toBe(0);
      expect(untrusted.tlsFailures).toBe(before);
    } finally {
      await untrusted.close();
    }

    // A redirect is not followed, not even to a host the policy allows.
    const target = await watch();
    const redirecting = createHttpServer((_request, response) => {
      response.writeHead(302, {
        location: `http://127.0.0.1:${target.port}/stable.json`,
      });
      response.end();
    });
    await new Promise<void>((done) => redirecting.listen(0, "127.0.0.1", done));
    try {
      const port = (redirecting.address() as { port: number }).port;
      const redirected = await s.run([
        "update",
        "--check",
        "--from",
        `http://127.0.0.1:${port}/`,
      ]);
      expect(redirected.status).toBe(1);
      expect(target.requests).toEqual([]);
    } finally {
      await new Promise<void>((done) => {
        redirecting.close(() => done());
        redirecting.closeAllConnections();
      });
      await target.close();
    }
  }, 900000);
});
