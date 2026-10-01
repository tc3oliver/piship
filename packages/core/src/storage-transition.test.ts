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
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type SecretStore, SecretValue } from "@piship/contracts";
import {
  type CommandRunner,
  MemorySecretStore,
  RestrictedFileSecretStore,
  SecretServiceSecretStore,
  type SecretStoreProvider,
  withFileLock,
} from "@piship/credentials";
import {
  type AccessManifest,
  type Manifest,
  readManifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { DistributionAccess, SandboxCredential } from "./access/index.js";
import { purgeDistributionState } from "./install/index.js";
import {
  checkStateMigration,
  LEGACY_STATE_SCHEMAS,
  STATE_SCHEMAS,
} from "./migration.js";
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

const SANDBOX_SECRET = "fake-sandbox-key-SENTINEL-0001";

/** The stored sandbox credential slot of a release configured for `provider`. */
function sandboxSlot(
  provider: SecretStoreProvider,
  principal: { issuer: string; subject: string },
): SandboxCredential {
  return new SandboxCredential({
    distributionId: ID,
    command: demo.app.command,
    stateDir: stateDir(),
    provider: "e2b-compatible",
    storage: { provider },
    secretStore: storeOf(provider),
    secretStoreFor: storeOf,
    principal,
    targets: ["https://sandbox-api.test.invalid:8443/v1"],
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

  it("clears the stored sandbox credential from the old store too, and sign-in still works", async () => {
    const before = open(from);
    await login(before);
    const identity = before.readIdentityMetadata();
    const principal = {
      issuer: identity?.issuer ?? "",
      subject: identity?.subject ?? "",
    };
    await sandboxSlot(from, principal).save(async () => SANDBOX_SECRET);
    const sandboxFile = join(
      stateDir(),
      "credentials-metadata",
      "sandbox.json",
    );
    const sandboxRefs = [
      JSON.parse(readFileSync(sandboxFile, "utf8")).credential_ref,
    ];
    expect(JSON.parse(readFileSync(sandboxFile, "utf8")).secret_store).toBe(
      from,
    );
    const oldStore = storeOf(from);
    for (const ref of sandboxRefs)
      expect(await oldStore.get(ref)).not.toBeNull();

    const { report, notices } = await switchStore(from, to);
    expect(
      report.items.find(
        (item) => item.path === "credentials-metadata/sandbox.json",
      ),
    ).toMatchObject({
      verdict: "safe",
      action: "clear-and-reacquire",
      storageTransition: { from, to },
    });
    expect(notices.join("\n")).toContain("sandbox credential");
    for (const ref of sandboxRefs) expect(await oldStore.get(ref)).toBeNull();
    expect(existsSync(sandboxFile)).toBe(false);

    // Nobody is locked out: the target signs in, and a sandbox login works.
    const after = open(to);
    await login(after);
    await sandboxSlot(to, principal).save(async () => SANDBOX_SECRET);
    expect(JSON.parse(readFileSync(sandboxFile, "utf8")).secret_store).toBe(to);
  });

  it("deletes a sandbox credential that records the other store when the provider changed without a switch clearing it", async () => {
    const before = open(from);
    await login(before);
    const identity = before.readIdentityMetadata();
    const principal = {
      issuer: identity?.issuer ?? "",
      subject: identity?.subject ?? "",
    };
    await sandboxSlot(from, principal).save(async () => SANDBOX_SECRET);
    const sandboxFile = join(
      stateDir(),
      "credentials-metadata",
      "sandbox.json",
    );
    const ref = JSON.parse(readFileSync(sandboxFile, "utf8")).credential_ref;
    // The distribution is now configured for the other store, and its
    // sandbox metadata still names the old one.
    await sandboxSlot(to, {
      ...principal,
      subject: "someone-else",
    }).clearUnlessBoundTo({ ...principal, subject: "someone-else" });
    expect(await storeOf(from).get(ref)).toBeNull();
    expect(existsSync(sandboxFile)).toBe(false);
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

describe("the other store of the sandbox credential", () => {
  it("is opened by the rule of the access, as for the runtime credential: an injected store has none", async () => {
    // The sandbox credential was stored in the file store, and the
    // distribution now uses an injected platform-like store (not in memory)
    // and no way to reach the other one.
    const before = open("file");
    await login(before);
    const identity = before.readIdentityMetadata();
    const principal = {
      issuer: identity?.issuer ?? "",
      subject: identity?.subject ?? "",
    };
    await sandboxSlot("file", principal).save(async () => SANDBOX_SECRET);
    const sandboxFile = join(
      stateDir(),
      "credentials-metadata",
      "sandbox.json",
    );
    const ref = JSON.parse(readFileSync(sandboxFile, "utf8")).credential_ref;
    const injected: SecretStore = {
      kind: "system",
      description: "platform store (test, not in memory)",
      put: (name, value) => platform.put(name, value),
      get: (name) => platform.get(name),
      delete: (name) => platform.delete(name),
    };
    const moved = DistributionAccess.open({
      app: demo.app as Manifest["app"],
      mode: "managed",
      access: manifest("system"),
      stateDir: stateDir(),
      distributionDir: temp,
      env: services.env(),
      secretStore: injected,
    });
    const problems = await moved.sandboxCredential().clear();
    // Not deleted from a file store the slot opened on its own: the secret
    // stays, tracked, and the failure is reported.
    expect(problems.join("\n")).toContain(
      "the file secret store that holds it is not available",
    );
    expect(await fileStore().get(ref)).not.toBeNull();
    expect(moved.sandboxCredential().present()).toBe(true);
    expect(existsSync(sandboxFile)).toBe(true);
    // Once the other store is reachable, the next command deletes it.
    await open("system").sandboxCredential().clear();
    expect(await fileStore().get(ref)).toBeNull();
    expect(existsSync(sandboxFile)).toBe(false);
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
    const result = await purgeDistributionState(ID, {
      secretStore: platform,
      withoutLogout: true,
    });
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
    const result = await purgeDistributionState(ID, {
      secretStore: platform,
      withoutLogout: true,
    });
    expect(result.deletedSecrets).toEqual([]);
    expect(platform.deleted).toEqual([]);
    expect(existsSync(stateDir())).toBe(false);
  });
});

/** A file store whose deletions wait until the test lets them go. */
class GatedFileStore extends RestrictedFileSecretStore {
  constructor(
    directory: string,
    private readonly entered: () => void,
    private readonly gate: Promise<void>,
  ) {
    super(directory);
  }
  override async delete(ref: string): Promise<void> {
    this.entered();
    await this.gate;
    return super.delete(ref);
  }
}

describe("clearing what the target cannot read", () => {
  const switching = (from: SecretStoreProvider, to: SecretStoreProvider) =>
    checkStateMigration(
      stateDir(),
      { version: "1.1.0", pi: "0.87.1", schemas: STATE_SCHEMAS, storage: to },
      { version: "1.0.0", pi: "0.87.1", storage: from },
    );

  /**
   * Signed in with the file store, then the identity's tokens are in the
   * platform store and its session says so: what a Pi session of the old
   * release leaves when it refreshes the identity after the switch cleared
   * it.
   */
  async function identityInPlatformStore(): Promise<string> {
    await login(open("file"));
    const identity = JSON.parse(readFileSync(identityFile(), "utf8"));
    await platform.put(
      identity.secretRef,
      (await fileStore().get(identity.secretRef)) as SecretValue,
    );
    await fileStore().delete(identity.secretRef);
    writeFileSync(
      identityFile(),
      JSON.stringify({ ...identity, secret_store: "system" }),
    );
    return identity.secretRef;
  }

  it("deletes the secrets of each file from the store that file records", async () => {
    const identityRef = await identityInPlatformStore();
    const [, credentialRef] = stateRefs();
    expect(platform.refs()).toContain(identityRef);
    const notices = await clearCredentials(
      stateDir(),
      ID,
      switching("file", "system"),
      { secretStore: fileStore(), secretStoreFor: storeOf },
    );
    expect(notices).toHaveLength(2);
    // Not looked up in the configured file store, where nothing was found
    // and the deletion would have counted as confirmed.
    expect(platform.refs()).toEqual([]);
    expect(await fileStore().get(credentialRef as string)).toBeNull();
    expect(existsSync(identityFile())).toBe(false);
    expect(existsSync(credentialFile())).toBe(false);
  });

  it("stops the switch, and keeps the metadata, while the store a file records is not available", async () => {
    const identityRef = await identityInPlatformStore();
    await expect(
      clearCredentials(stateDir(), ID, switching("file", "system"), {
        secretStore: fileStore(),
      }),
    ).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
      message: expect.stringContaining(
        `${identityRef}: the system secret store that holds it is not available`,
      ),
      sanitizedDetail: { refs: expect.arrayContaining([identityRef]) },
    });
    expect(platform.refs()).toContain(identityRef);
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).toMatchObject({
      secretRef: identityRef,
      secret_store: "system",
    });
    expect(existsSync(credentialFile())).toBe(true);
    // Once it is reachable, the switch deletes them.
    await clearCredentials(stateDir(), ID, switching("file", "system"), {
      secretStore: fileStore(),
      secretStoreFor: storeOf,
    });
    expect(platform.refs()).toEqual([]);
    expect(existsSync(identityFile())).toBe(false);
  });

  it("holds the credential and identity locks from the deletion to the removal of the metadata", async () => {
    await login(open("file"));
    let entered = () => {};
    let release = () => {};
    const inside = new Promise<void>((resolve) => (entered = resolve));
    const gate = new Promise<void>((resolve) => (release = resolve));
    const clearing = clearCredentials(
      stateDir(),
      ID,
      switching("file", "system"),
      { secretStore: new GatedFileStore(secretsDir(), entered, gate) },
    );
    await inside;
    // A live session of the active release cannot commit a generation now:
    // its secret would have no metadata to name it once the files are gone.
    for (const file of [credentialFile(), identityFile()])
      await expect(
        withFileLock(file, async () => {}, { waitMs: 200 }),
      ).rejects.toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
        sanitizedDetail: { reason: "lock-timeout" },
      });
    expect(existsSync(credentialFile())).toBe(true);
    release();
    await clearing;
    expect(existsSync(credentialFile())).toBe(false);
    for (const file of [credentialFile(), identityFile()])
      await withFileLock(file, async () => {}, { waitMs: 200 });
  });

  it("takes no lock, and creates no directory, for state that is not there", async () => {
    const ref = `piship:${ID}:inference#1`;
    mkdirSync(dirname(credentialFile()), { recursive: true });
    writeFileSync(
      credentialFile(),
      JSON.stringify({
        schema: "piship-credential-metadata/v1",
        mode: "local-secret",
        credential_ref: ref,
        generation: 1,
        kind: "api_key",
        acquired_at: "2026-01-01T00:00:00.000Z",
        secret_store: "file",
      }),
    );
    await fileStore().put(ref, new SecretValue("fake-secret-for-the-test"));
    const notices = await clearCredentials(
      stateDir(),
      ID,
      switching("file", "system"),
      { secretStore: fileStore() },
    );
    expect(notices).toHaveLength(1);
    expect(existsSync(credentialFile())).toBe(false);
    expect(existsSync(dirname(identityFile()))).toBe(false);
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

describe("rollback to a release before the Linux Secret Service part layout", () => {
  // A `secret-tool` double: items match on every attribute given; `clear`
  // removes every match unless `failClear` is set.
  function secretTool() {
    const items: Record<string, string>[] = [];
    const texts = new Map<Record<string, string>, string>();
    const knobs = { failClear: false };
    const attributesOf = (args: string[]) => {
      const words = args.slice(1).filter((word) => !word.startsWith("--"));
      const attrs: Record<string, string> = {};
      for (let index = 0; index + 1 < words.length; index += 2)
        attrs[words[index] as string] = words[index + 1] as string;
      return attrs;
    };
    const matching = (query: Record<string, string>) =>
      items.filter((item) =>
        Object.entries(query).every(([name, value]) => item[name] === value),
      );
    const run: CommandRunner = (_command, args, stdin) => {
      const attrs = attributesOf(args);
      const found = matching(attrs);
      if (args[0] === "store") {
        for (const item of found) items.splice(items.indexOf(item), 1);
        items.push(attrs);
        texts.set(attrs, stdin ?? "");
        return { status: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "lookup")
        return found[0]
          ? { status: 0, stdout: texts.get(found[0]) ?? "", stderr: "" }
          : { status: 1, stdout: "", stderr: "" };
      if (args[0] === "search") return { status: 0, stdout: "", stderr: "" };
      if (knobs.failClear)
        return { status: 1, stdout: "", stderr: "secret-tool: keyring error" };
      for (const item of found) items.splice(items.indexOf(item), 1);
      return { status: 0, stdout: "", stderr: "" };
    };
    return { items, knobs, store: new SecretServiceSecretStore(run) };
  }

  const ref = `piship:${ID}:inference#1`;
  const metadata = {
    schema: "piship-credential-metadata/v1",
    mode: "local-secret",
    credential_ref: ref,
    generation: 1,
    kind: "api_key",
    acquired_at: "2026-01-01T00:00:00.000Z",
    secret_store: "system",
  };

  /** A v0.7 install on Linux signed in with a secret long enough to split. */
  async function signedIn() {
    const tool = secretTool();
    mkdirSync(dirname(credentialFile()), { recursive: true });
    writeFileSync(credentialFile(), JSON.stringify(metadata));
    await tool.store.put(ref, new SecretValue("x".repeat(20_000)));
    expect(tool.items.length).toBeGreaterThan(1);
    return tool;
  }

  const rollback = (
    schemas: typeof STATE_SCHEMAS,
    platform: NodeJS.Platform = "linux",
  ) =>
    checkStateMigration(
      stateDir(),
      { version: "0.6.0", pi: "0.87.1", schemas, storage: "system" },
      { version: "0.7.0", pi: "0.87.1", storage: "system", platform },
    );

  it("deletes every part and the metadata before the switch, and the target signs in again", async () => {
    const tool = await signedIn();
    const report = rollback(LEGACY_STATE_SCHEMAS);
    expect(
      report.items.find((item) => item.name === "runtime credential metadata"),
    ).toMatchObject({
      verdict: "safe",
      action: "clear-and-reacquire",
      reason: expect.stringContaining("predates the Linux Secret Service"),
    });
    const notices = await clearCredentials(stateDir(), ID, report, {
      secretStore: tool.store,
    });
    expect(notices).toEqual([
      "runtime credential metadata was cleared because the target cannot read it; sign in again",
    ]);
    // No part is orphaned, and no `chunks:` marker is left to be read as the secret.
    expect(tool.items).toEqual([]);
    expect(existsSync(credentialFile())).toBe(false);
  });

  it("stops before the switch, and keeps the metadata, when the parts cannot be deleted", async () => {
    const tool = await signedIn();
    tool.knobs.failClear = true;
    await expect(
      clearCredentials(stateDir(), ID, rollback(LEGACY_STATE_SCHEMAS), {
        secretStore: tool.store,
      }),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(existsSync(credentialFile())).toBe(true);
    expect(tool.items.length).toBeGreaterThan(1);
  });

  it("keeps the credential for a target that knows the layout, and off Linux", async () => {
    await signedIn();
    for (const report of [
      rollback(STATE_SCHEMAS),
      rollback(LEGACY_STATE_SCHEMAS, "darwin"),
      rollback(LEGACY_STATE_SCHEMAS, "win32"),
    ])
      expect(
        report.items.find(
          (item) => item.name === "runtime credential metadata",
        ),
      ).toMatchObject({ action: "keep" });
  });
});
