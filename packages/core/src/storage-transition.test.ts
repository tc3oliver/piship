import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type SecretStore, SecretValue } from "@piship/contracts";
import {
  MemorySecretStore,
  RestrictedFileSecretStore,
  type SecretStoreProvider,
} from "@piship/credentials";
import {
  type AccessManifest,
  type Manifest,
  readManifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { DistributionAccess } from "./access/index.js";
import { purgeDistributionState } from "./install/index.js";
import { checkStateMigration, STATE_SCHEMAS } from "./migration.js";
import { storageOf } from "./storage-transition.js";
import { clearCredentials } from "./update/state.js";

// A change of credential.storage.provider (file <-> system) is a credential
// lifecycle transition. The platform store is stood in for by a memory store
// that records every lookup, so a test can prove an old-store reference is
// never looked up in the new store.

const demo = readManifest(
  fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;
const ID = demo.app.id;

type Services = Awaited<ReturnType<typeof startLocalServices>>;

/** The platform store: memory, recording lookups and deletions. */
class PlatformStore implements SecretStore {
  readonly kind = "memory";
  readonly description = "platform store (test)";
  readonly inner = new MemorySecretStore();
  readonly lookups: string[] = [];
  readonly deleted: string[] = [];
  put(ref: string, value: SecretValue) {
    return this.inner.put(ref, value);
  }
  get(ref: string) {
    this.lookups.push(ref);
    return this.inner.get(ref);
  }
  delete(ref: string) {
    this.deleted.push(ref);
    return this.inner.delete(ref);
  }
  refs() {
    return this.inner.refs();
  }
}

let temp: string;
let services: Services;
let platform: PlatformStore;
const saved: Record<string, string | undefined> = {};
beforeEach(async () => {
  temp = mkdtempSync(join(tmpdir(), "piship-storage-transition-"));
  for (const key of ["PISHIP_STATE_HOME", "PISHIP_INSTALL_HOME"])
    saved[key] = process.env[key];
  process.env.PISHIP_STATE_HOME = join(temp, "state");
  process.env.PISHIP_INSTALL_HOME = join(temp, "install");
  services = await startLocalServices();
  platform = new PlatformStore();
});
afterEach(async () => {
  await services.close();
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  rmSync(temp, { recursive: true, force: true });
});

const stateDir = () => join(temp, "state", ID);
const secretsDir = () => join(stateDir(), "secrets");
const identityFile = () => join(stateDir(), "identity", "session.json");
const credentialFile = () =>
  join(stateDir(), "credentials-metadata", "inference.json");
const fileStore = () => new RestrictedFileSecretStore(secretsDir());
const storeOf = (provider: SecretStoreProvider): SecretStore =>
  provider === "file" ? fileStore() : platform;

function manifest(provider: SecretStoreProvider): AccessManifest {
  return {
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
      storage: { provider, acknowledgePlaintext: true },
    },
  } as AccessManifest;
}

/** A release configured for `provider`; the other store is reachable too. */
function open(provider: SecretStoreProvider): DistributionAccess {
  return DistributionAccess.open({
    app: demo.app as Manifest["app"],
    mode: "managed",
    access: manifest(provider),
    stateDir: stateDir(),
    distributionDir: temp,
    env: services.env(),
    secretStore: storeOf(provider),
    secretStoreFor: storeOf,
  });
}

function login(distribution: DistributionAccess) {
  return distribution.login({ openUrl: (url) => void services.approve(url) });
}

/** The references the old release's state names. */
function stateRefs(): string[] {
  return [identityFile(), credentialFile()].flatMap((file) => {
    const value = JSON.parse(readFileSync(file, "utf8"));
    return [value.secretRef ?? value.credential_ref];
  });
}

/** What update or rollback from `from` to `to` does before activation. */
async function switchStore(from: SecretStoreProvider, to: SecretStoreProvider) {
  const report = checkStateMigration(
    stateDir(),
    { version: "1.1.0", pi: "0.87.1", schemas: STATE_SCHEMAS, storage: to },
    { version: "1.0.0", pi: "0.87.1", storage: from },
  );
  const notices = await clearCredentials(stateDir(), ID, report, {
    secretStore: storeOf(from),
    revokeCredential: () => open(from).revokeCredential(),
  });
  return { report, notices };
}

describe.each([
  ["file", "system"],
  ["system", "file"],
] as const)("storage provider %s -> %s", (from, to) => {
  it("clears identity and credential state from the old store, revokes the credential, and never looks old references up in the new store", async () => {
    await login(open(from));
    const refs = stateRefs();
    for (const file of [identityFile(), credentialFile()])
      expect(JSON.parse(readFileSync(file, "utf8")).secret_store).toBe(from);
    const oldStore = storeOf(from);
    for (const ref of refs) expect(await oldStore.get(ref)).not.toBeNull();
    const credentialId = [...services.state.credentials.values()][0]?.id;

    const { report, notices } = await switchStore(from, to);
    // An explicit migration action and notice for each class.
    for (const name of ["identity session", "runtime credential metadata"])
      expect(report.items.find((item) => item.name === name)).toMatchObject({
        verdict: "safe",
        action: "clear-and-reacquire",
        reason: expect.stringContaining(
          `The secret store changes from ${from} to ${to}`,
        ),
        storageTransition: { from, to },
      });
    expect(report.verdict).toBe("safe");
    expect(notices).toEqual([
      `identity session was cleared because the secret store changes from ${from} to ${to}: its secrets were deleted from the ${from} store; sign in again`,
      `runtime credential metadata was cleared because the secret store changes from ${from} to ${to}: its secrets were deleted from the ${from} store; sign in again`,
    ]);
    // Revoked by the switching release, deleted from the old store.
    expect(services.state.revokedCredentials).toContain(credentialId);
    for (const ref of refs) expect(await oldStore.get(ref)).toBeNull();
    expect(existsSync(identityFile())).toBe(false);
    expect(existsSync(credentialFile())).toBe(false);
    if (from === "file") expect(existsSync(secretsDir())).toBe(false);
    else expect(platform.refs()).toEqual([]);

    // The target signs in again, deterministically, into its own store; it
    // has nothing to look up before that.
    platform.lookups.length = 0;
    await expect(open(to).activate()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
    expect(platform.lookups).toEqual([]);
    await login(open(to));
    const activated = await open(to).activate();
    expect(activated.identity).not.toBeNull();
    for (const file of [identityFile(), credentialFile()])
      expect(JSON.parse(readFileSync(file, "utf8")).secret_store).toBe(to);
    const newStore = storeOf(to);
    for (const ref of stateRefs())
      expect(await newStore.get(ref)).not.toBeNull();
  });

  it("keeps identity and credential state when the store stays the same", () => {
    mkdirSync(join(stateDir(), "identity"), { recursive: true });
    writeFileSync(
      identityFile(),
      JSON.stringify({ schema: "piship-identity-metadata/v1" }),
    );
    const report = checkStateMigration(
      stateDir(),
      {
        version: "1.1.0",
        pi: "0.87.1",
        schemas: STATE_SCHEMAS,
        storage: from,
      },
      { version: "1.0.0", pi: "0.87.1", storage: from },
    );
    expect(
      report.items.find((item) => item.name === "identity session"),
    ).toMatchObject({ action: "keep" });
    // Absent classes are not cleared by a transition either.
    const changing = checkStateMigration(
      stateDir(),
      { version: "1.1.0", pi: "0.87.1", schemas: STATE_SCHEMAS, storage: to },
      { version: "1.0.0", pi: "0.87.1", storage: from },
    );
    expect(
      changing.items.find(
        (item) => item.name === "runtime credential metadata",
      ),
    ).toMatchObject({ action: "keep", current: null });
  });

  it("never reads state recorded for the other store in its own store; it deletes it from the store that holds it", async () => {
    // State written under the old store, then launched by a release
    // configured for the new one without a switch (another payload of the
    // same distribution, or an older switching release).
    await login(open(from));
    const refs = stateRefs();
    const credentialId = [...services.state.credentials.values()][0]?.id;
    platform.lookups.length = 0;
    const status = await open(to).status();
    expect(status.identity).toBeNull();
    expect(status.credential).toMatchObject({
      state: "absent",
      notice: expect.stringContaining(`in the ${from} secret store`),
    });
    await expect(open(to).activate()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
    // The identity is deleted from the old store, where it was.
    expect(await storeOf(from).get(refs[0] as string)).toBeNull();
    expect(existsSync(identityFile())).toBe(false);
    // The platform store was never asked for what the file store holds.
    if (to === "system") expect(platform.lookups).toEqual([]);
    // A login revokes the old credential through the store that holds it,
    // deletes it there, and stores the new one in the new store.
    await login(open(to));
    expect(services.state.revokedCredentials).toContain(credentialId);
    for (const ref of refs) expect(await storeOf(from).get(ref)).toBeNull();
    expect(
      JSON.parse(readFileSync(credentialFile(), "utf8")).secret_store,
    ).toBe(to);
  });

  it("revokes and deletes a credential recorded for the other store at launch", async () => {
    await login(open(from));
    const [, credentialRef] = stateRefs();
    const credentialId = [...services.state.credentials.values()][0]?.id;
    // Only the credential is left from the old store (the identity was
    // already moved), as an interrupted switch can leave it.
    const identity = JSON.parse(readFileSync(identityFile(), "utf8"));
    const bundle = await storeOf(from).get(identity.secretRef);
    await storeOf(from).delete(identity.secretRef);
    await storeOf(to).put(identity.secretRef, bundle as SecretValue);
    writeFileSync(
      identityFile(),
      JSON.stringify({ ...identity, secret_store: to }),
    );
    const activated = await open(to).activate();
    expect(activated.notices).toEqual(
      expect.arrayContaining([
        `The credential stored in the ${from} secret store was deleted from it: this distribution now stores credentials in the ${to} store. A new credential is required`,
      ]),
    );
    expect(services.state.revokedCredentials).toContain(credentialId);
    expect(await storeOf(from).get(credentialRef as string)).toBeNull();
    expect(
      JSON.parse(readFileSync(credentialFile(), "utf8")).secret_store,
    ).toBe(to);
  });

  it("keeps the other store's references tracked, and fails closed, while that store is not available", async () => {
    await login(open(from));
    const refs = stateRefs();
    const unavailable = DistributionAccess.open({
      app: demo.app as Manifest["app"],
      mode: "managed",
      access: manifest(to),
      stateDir: stateDir(),
      distributionDir: temp,
      env: services.env(),
      secretStore: storeOf(to),
      secretStoreFor: () => null,
    });
    await expect(unavailable.activate()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    const marker = JSON.parse(readFileSync(identityFile(), "utf8"));
    expect(marker).toMatchObject({
      schema: "piship-identity-discarded/v1",
      secret_store: from,
      orphans: expect.arrayContaining([refs[0]]),
    });
    for (const ref of refs) expect(await storeOf(from).get(ref)).not.toBeNull();
    // Once the old store is reachable, the next command deletes them.
    await expect(open(to).activate()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
    expect(await storeOf(from).get(refs[0] as string)).toBeNull();
  });
});

describe("purge after a storage provider change", () => {
  it("deletes platform-owned references from the platform store and leaves file-owned ones to the state directory", async () => {
    // The credential is in the file store, the identity in the platform
    // store: state a storage change left behind.
    await login(open("file"));
    const fileRef = stateRefs()[1] as string;
    const identityRef = "piship:acmecode:identity#1";
    await platform.put(identityRef, new SecretValue("platform-token-bundle"));
    writeFileSync(
      identityFile(),
      JSON.stringify({
        schema: "piship-identity-discarded/v1",
        orphans: [identityRef],
        secret_store: "system",
      }),
    );
    expect(readdirSync(secretsDir()).length).toBeGreaterThan(0);
    const result = await purgeDistributionState(ID, { secretStore: platform });
    expect(platform.refs()).toEqual([]);
    expect(result.deletedSecrets).toContain(identityRef);
    // A file-store reference is never looked up in the platform store.
    expect(platform.deleted).not.toContain(fileRef);
    expect(existsSync(stateDir())).toBe(false);
  });

  it("still guesses the file store for metadata that records no store, as before", async () => {
    await login(open("file"));
    for (const file of [identityFile(), credentialFile()]) {
      const value = JSON.parse(readFileSync(file, "utf8"));
      delete value.secret_store;
      writeFileSync(file, JSON.stringify(value));
    }
    const result = await purgeDistributionState(ID, { secretStore: platform });
    expect(result.deletedSecrets).toEqual([]);
    expect(platform.deleted).toEqual([]);
    expect(existsSync(stateDir())).toBe(false);
  });
});

describe("storageOf", () => {
  it("reads the storage provider of a lock, and nothing without access", () => {
    expect(storageOf({ access: manifest("file") })).toEqual({
      storage: "file",
    });
    expect(storageOf({})).toEqual({});
  });
});
