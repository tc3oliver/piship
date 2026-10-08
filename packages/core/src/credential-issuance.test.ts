// The pending credential issuance through DistributionAccess, the branded
// logout, and update and rollback: a sign-in whose broker answer was lost
// repeats its key, and no logout, change of principal, or switch to a
// release that cannot read it leaves the key behind.
import {
  chmodSync,
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
import { SecretValue } from "@piship/contracts";
import {
  MemorySecretStore,
  RestrictedFileSecretStore,
} from "@piship/credentials";
import type { AccessManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { DistributionAccess } from "./access/index.js";
import type { BrandedContext } from "./branded/context.js";
import { runLogout } from "./branded/login.js";
import { resolveLock } from "./index.js";
import { purgeDistributionState } from "./install/purge.js";
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
  const current = { version: "1.1.0", pi: "1.1.0" };

  it("a release without the schema key has it cleared, and no snapshot holds it", async () => {
    plant();
    const { credentialIssuance: _absent, ...older } = STATE_SCHEMAS;
    const report = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "1.1.0", schemas: older },
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
      { version: "1.0.0", pi: "1.1.0", schemas: STATE_SCHEMAS },
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
      { version: "1.0.0", pi: "1.1.0", schemas: STATE_SCHEMAS },
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

  it("clearing a pending renewal for an older release never deletes the live credential it names", async () => {
    await login();
    const metadataFile = path("credentials-metadata", "inference.json");
    const metadata = JSON.parse(readFileSync(metadataFile, "utf8"));
    const store = new RestrictedFileSecretStore(path("secrets"));
    expect(await store.get(metadata.credential_ref)).not.toBeNull();
    // An ambiguous renewal of the stored credential is pending.
    writeFileSync(
      issuanceFile(),
      JSON.stringify({
        schema: "piship-credential-issuance/v1",
        idempotency_key: "0b8f5a4e-3c1d-4e2f-9a6b-7c8d9e0f1a2b",
        mode: "http-broker",
        request: "renewal",
        renews: {
          credential_ref: metadata.credential_ref,
          acquired_at: metadata.acquired_at,
        },
        created_at: new Date().toISOString(),
      }),
    );
    const { credentialIssuance: _absent, ...older } = STATE_SCHEMAS;
    const report = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "1.1.0", schemas: older },
      current,
    );
    expect(
      report.items.find((item) => item.name === "runtime credential metadata")
        ?.action,
    ).toBe("keep");
    await clearCredentials(stateDir(), ID, report, { secretStore: store });
    expect(existsSync(issuanceFile())).toBe(false);
    expect(readFileSync(metadataFile, "utf8")).toContain(
      metadata.credential_ref,
    );
    expect(await store.get(metadata.credential_ref)).not.toBeNull();
    // The next launch reuses it: nothing is acquired.
    await open().activate();
    expect(services.state.credentialCount).toBe(1);
    expect(services.state.idempotencyKeys).toHaveLength(1);
  });
});

describe("a switch that clears one secret class keeps the file store of the others", () => {
  const current = { version: "1.1.0", pi: "1.1.0" };

  it("clearing only the sandbox credential keeps the runtime credential's and identity's secrets", async () => {
    await login();
    const store = new RestrictedFileSecretStore(path("secrets"));
    const credential = JSON.parse(
      readFileSync(path("credentials-metadata", "inference.json"), "utf8"),
    );
    const identity = JSON.parse(
      readFileSync(path("identity", "session.json"), "utf8"),
    );
    const sandboxRef = `piship:${ID}:sandbox#1`;
    await store.put(sandboxRef, new SecretValue("fake-sandbox-SENTINEL-0001"));
    writeFileSync(
      path("credentials-metadata", "sandbox.json"),
      JSON.stringify({
        schema: "piship-sandbox-credential-metadata/v1",
        mode: "local-secret",
        source: "stored",
        origins: ["https://sandbox.example.test"],
        credential_ref: sandboxRef,
        generation: 1,
        kind: "api_key",
        acquired_at: new Date().toISOString(),
        secret_store: "file",
      }),
    );
    // A release that reads the runtime credential and identity, but not the
    // sandbox credential.
    const { sandboxCredential: _absent, ...older } = STATE_SCHEMAS;
    const report = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "1.1.0", schemas: older },
      current,
    );
    expect(
      report.items
        .filter((item) => item.action === "clear-and-reacquire")
        .map((item) => item.name),
    ).toEqual(["sandbox credential metadata"]);
    await clearCredentials(stateDir(), ID, report, { secretStore: store });
    expect(existsSync(path("credentials-metadata", "sandbox.json"))).toBe(
      false,
    );
    expect(await store.get(sandboxRef)).toBeNull();
    expect(await store.get(credential.credential_ref)).not.toBeNull();
    expect(await store.get(identity.secretRef)).not.toBeNull();
    // The next launch reuses both: no sign-in, no new credential.
    await open().activate();
    expect(services.state.credentialCount).toBe(1);
  });
});

describe("the pending issuance never names a secret to delete", () => {
  // A reference the stored credential does not name, planted where only
  // the pending record points.
  const planted = `piship:${ID}:inference#7`;
  const record = () =>
    JSON.stringify({
      schema: "piship-credential-issuance/v1",
      idempotency_key: "0b8f5a4e-3c1d-4e2f-9a6b-7c8d9e0f1a2b",
      mode: "http-broker",
      request: "renewal",
      renews: {
        credential_ref: planted,
        acquired_at: new Date().toISOString(),
      },
      created_at: new Date().toISOString(),
    });

  it("in purge", async () => {
    const home = join(temp, "home");
    const saved = {
      state: process.env.PISHIP_STATE_HOME,
      install: process.env.PISHIP_INSTALL_HOME,
    };
    process.env.PISHIP_STATE_HOME = home;
    process.env.PISHIP_INSTALL_HOME = join(temp, "install");
    try {
      const metadata = join(home, ID, "credentials-metadata");
      mkdirSync(metadata, { recursive: true });
      writeFileSync(
        join(metadata, "inference.json"),
        JSON.stringify({
          schema: "piship-credential-metadata/v1",
          mode: "http-broker",
          credential_ref: `piship:${ID}:inference#1`,
          generation: 1,
          kind: "api_key",
          acquired_at: new Date().toISOString(),
          secret_store: "system",
        }),
      );
      writeFileSync(join(metadata, "pending-issuance.json"), record());
      const store = new MemorySecretStore();
      for (const ref of [`piship:${ID}:inference#1`, planted])
        await store.put(ref, new SecretValue("fake-purge-SENTINEL-0001"));
      const result = await purgeDistributionState(ID, {
        secretStore: store,
        withoutLogout: true,
      });
      expect(result.deletedSecrets).toEqual([
        `piship:${ID}:inference#1`,
        `piship:${ID}:inference#2`,
      ]);
      expect(await store.get(planted)).not.toBeNull();
    } finally {
      for (const [key, value] of [
        ["PISHIP_STATE_HOME", saved.state],
        ["PISHIP_INSTALL_HOME", saved.install],
      ] as const)
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
    }
  });

  it("in logout, with and without the runtime variables", async () => {
    const { lock, access } = manifest();
    const ctx: BrandedContext = {
      metadata: { ...lock, access },
      distributionDir: temp,
      stateDir: stateDir(),
      mode: "managed",
      out: () => {},
      err: () => {},
    };
    const store = new RestrictedFileSecretStore(path("secrets"));
    for (const withVariables of [true, false]) {
      await login();
      await store.put(planted, new SecretValue("fake-logout-SENTINEL-0001"));
      writeFileSync(issuanceFile(), record());
      if (!withVariables)
        for (const name of Object.keys(services.env()))
          delete process.env[name];
      await runLogout(ctx);
      expect(existsSync(issuanceFile())).toBe(false);
      expect(await store.get(planted)).not.toBeNull();
      Object.assign(process.env, services.env());
      await store.delete(planted);
    }
  });
});

describe("an unreadable file secret store at launch", () => {
  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "reports SECRET_STORE_UNAVAILABLE naming the path, not IDENTITY_REQUIRED",
    async () => {
      await login();
      const secrets = path("secrets");
      chmodSync(secrets, 0o000);
      try {
        const error = await open()
          .activate()
          .then(
            () => null,
            (caught: unknown) => caught,
          );
        expect(error).toMatchObject({
          code: "SECRET_STORE_UNAVAILABLE",
          message: expect.stringContaining(secrets),
          userAction: expect.stringContaining(secrets),
        });
      } finally {
        chmodSync(secrets, 0o700);
      }
      await expect(open().activate()).resolves.toBeTruthy();
    },
  );
});
