// The pending credential issuance through DistributionAccess, the branded
// logout, and update and rollback: a sign-in whose broker answer was lost
// repeats its key, and no logout, change of principal, or switch to a
// release that cannot read it leaves the key behind.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { MemorySecretStore } from "@piship/credentials";
import type { AccessManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { DistributionAccess } from "./access/index.js";
import type { BrandedContext } from "./branded/context.js";
import { runLogout } from "./branded/login.js";
import { resolveLock } from "./index.js";
import { checkStateMigration, STATE_SCHEMAS } from "./migration.js";
import { clearCredentials, snapshotState } from "./update/state.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const ID = "acmecode";

let temp: string;
let services: Awaited<ReturnType<typeof startLocalServices>>;
let savedEnv: NodeJS.ProcessEnv;
beforeEach(async () => {
  savedEnv = { ...process.env };
  temp = mkdtempSync(join(tmpdir(), "piship-issuance-access-"));
  services = await startLocalServices({ knobs: { brokerIdempotency: true } });
  Object.assign(process.env, services.env());
});
afterEach(async () => {
  process.env = savedEnv;
  // runLogout applies the distribution's network policy to this process.
  const { Agent, setGlobalDispatcher } = await import("undici");
  setGlobalDispatcher(new Agent());
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

const stateDir = () => join(temp, "state");
const path = (...parts: string[]) => join(stateDir(), ...parts);
const issuanceFile = () =>
  path("credentials-metadata", "pending-issuance.json");
const pendingKey = (): string | null =>
  existsSync(issuanceFile())
    ? JSON.parse(readFileSync(issuanceFile(), "utf8")).idempotency_key
    : null;

function manifest(): {
  lock: ReturnType<typeof resolveLock>;
  access: AccessManifest;
} {
  const lock = resolveLock(DEMO);
  const access = lock.access as AccessManifest;
  return {
    lock,
    access: {
      ...access,
      identity: {
        ...access.identity,
        oidc: {
          ...(access.identity as { oidc: object }).oidc,
          redirectUri: "http://127.0.0.1/callback",
        },
      },
      credential: {
        ...access.credential,
        storage: { provider: "file", acknowledgePlaintext: true },
      },
    } as AccessManifest,
  };
}

function open(): DistributionAccess {
  const { lock, access } = manifest();
  return DistributionAccess.open({
    app: lock.app,
    mode: "managed",
    access,
    stateDir: stateDir(),
    distributionDir: temp,
    env: services.env(),
  });
}

const login = (access = open()) =>
  access.login({ openUrl: (url) => void services.approve(url) });

/** The broker issues, then drops the connection before it answers. */
function loseNextAnswer(): void {
  services.knobs.brokerFaults.push({ timeoutMs: 50, timeoutServes: true });
}

describe("pending credential issuance through sign-in and sign-out", () => {
  it("a second login of the same principal repeats the key of the first, whose answer was lost", async () => {
    loseNextAnswer();
    await expect(login()).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      sanitizedDetail: { outcome: "unknown" },
    });
    const key = pendingKey();
    expect(key).toBe(services.state.idempotencyKeys[0]);
    expect(services.state.credentialCount).toBe(1);
    // A new process: the login replaces the (absent) credential, keeps the
    // pending key of the same principal, and repeats it.
    const result = await login();
    expect(services.state.idempotencyKeys).toEqual([key, key]);
    expect(services.state.credentialCount).toBe(1);
    expect(result.credential.metadata?.credential_id).toBe("vk_demo_1");
    expect(pendingKey()).toBeNull();
  });

  it("a login of another principal, and a logout, leave no pending key", async () => {
    loseNextAnswer();
    await expect(login()).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
    });
    const first = pendingKey();
    expect(first).not.toBeNull();
    services.knobs.subject = "demo-user-2";
    await login();
    expect(services.state.idempotencyKeys[1]).not.toBe(first);
    expect(services.state.credentialCount).toBe(2);
    expect(pendingKey()).toBeNull();

    loseNextAnswer();
    await expect(login()).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
    });
    expect(pendingKey()).not.toBeNull();
    await open().logout();
    expect(existsSync(issuanceFile())).toBe(false);
  });

  it("the branded logout removes it, also without the runtime variables", async () => {
    const { lock, access } = manifest();
    const ctx: BrandedContext = {
      metadata: { ...lock, access },
      distributionDir: temp,
      stateDir: stateDir(),
      mode: "managed",
      out: () => {},
      err: () => {},
    };
    for (const withVariables of [true, false]) {
      loseNextAnswer();
      await expect(login()).rejects.toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
      });
      expect(pendingKey()).not.toBeNull();
      if (!withVariables)
        for (const name of Object.keys(services.env()))
          delete process.env[name];
      await runLogout(ctx);
      expect(existsSync(issuanceFile())).toBe(false);
      Object.assign(process.env, services.env());
    }
  });
});

describe("pending credential issuance across update and rollback", () => {
  function plant(): void {
    mkdirSync(path("credentials-metadata"), { recursive: true });
    writeFileSync(
      issuanceFile(),
      JSON.stringify({
        schema: "piship-credential-issuance/v1",
        idempotency_key: "0b8f5a4e-3c1d-4e2f-9a6b-7c8d9e0f1a2b",
        mode: "http-broker",
        principal: { issuer: "https://idp.example.test", subject: "alice" },
        created_at: new Date().toISOString(),
      }),
    );
  }
  const current = { version: "1.1.0", pi: "0.87.1" };

  it("a release without the schema key has it cleared, and no snapshot holds it", async () => {
    plant();
    const { credentialIssuance: _absent, ...older } = STATE_SCHEMAS;
    const report = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "0.87.1", schemas: older },
      current,
    );
    expect(
      report.items.find((item) => item.name === "pending credential issuance"),
    ).toMatchObject({ action: "clear-and-reacquire", verdict: "safe" });
    const snapshot = snapshotState(stateDir(), "1.1.0", "1.0.0", new Date());
    await clearCredentials(stateDir(), ID, report, {
      secretStore: new MemorySecretStore(),
    });
    expect(existsSync(issuanceFile())).toBe(false);
    const listed = JSON.parse(
      readFileSync(join(snapshot as string, "snapshot.json"), "utf8"),
    ) as { excluded: string[]; files: string[] };
    expect(listed.excluded).toContain(
      "credentials-metadata/pending-issuance.json",
    );
    expect(listed.files).not.toContain(
      "credentials-metadata/pending-issuance.json",
    );
  });

  it("is kept by a release that reads it, and cleared with the runtime credential", async () => {
    plant();
    const keep = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "0.87.1", schemas: STATE_SCHEMAS },
      current,
    );
    expect(
      keep.items.find((item) => item.name === "pending credential issuance")
        ?.action,
    ).toBe("keep");
    // A target that cannot read the runtime credential clears it, and the
    // pending key goes with it: it is judged against that credential.
    writeFileSync(
      path("credentials-metadata", "inference.json"),
      JSON.stringify({ schema: "piship-credential-metadata/v9" }),
    );
    const report = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "0.87.1", schemas: STATE_SCHEMAS },
      current,
    );
    await clearCredentials(stateDir(), ID, report, {
      secretStore: new MemorySecretStore(),
    });
    expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
      false,
    );
    expect(existsSync(issuanceFile())).toBe(false);
  });
});
