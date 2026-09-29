import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { SecretStore, SecretValue } from "@piship/contracts";
import { MemorySecretStore } from "@piship/credentials";
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

// Ownership of secret-store entries: PiShip never forgets a reference it
// still owns, whether a deletion failed, the metadata naming it is damaged,
// or the process stopped between writing a secret and committing metadata.

const demo = readManifest(
  fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;
const ID = demo.app.id;

type Services = Awaited<ReturnType<typeof startLocalServices>>;

/** A store whose deletions (and, once, a write) can be made to fail. */
class FlakyStore implements SecretStore {
  readonly kind = "memory";
  readonly description = "test store";
  failDeletes: RegExp | null = null;
  /** The next put stores the value, then fails, as a timed-out keychain write can. */
  failAfterPut = false;
  readonly inner = new MemorySecretStore();
  async put(ref: string, value: SecretValue) {
    await this.inner.put(ref, value);
    if (this.failAfterPut) {
      this.failAfterPut = false;
      throw new Error("the keychain did not answer");
    }
  }
  get(ref: string) {
    return this.inner.get(ref);
  }
  async delete(ref: string) {
    if (this.failDeletes?.test(ref)) throw new Error("the keyring is locked");
    return this.inner.delete(ref);
  }
  refs() {
    return this.inner.refs();
  }
}

let temp: string;
let services: Services;
const saved: Record<string, string | undefined> = {};
beforeEach(async () => {
  temp = mkdtempSync(join(tmpdir(), "piship-ownership-"));
  for (const key of ["PISHIP_STATE_HOME", "PISHIP_INSTALL_HOME"])
    saved[key] = process.env[key];
  process.env.PISHIP_STATE_HOME = join(temp, "state");
  process.env.PISHIP_INSTALL_HOME = join(temp, "install");
  services = await startLocalServices();
});
afterEach(async () => {
  await services.close();
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  rmSync(temp, { recursive: true, force: true });
});

const stateDir = () => join(temp, "state", ID);
const identityFile = () => join(stateDir(), "identity", "session.json");
const credentialFile = () =>
  join(stateDir(), "credentials-metadata", "inference.json");

function open(store: SecretStore): DistributionAccess {
  return DistributionAccess.open({
    app: demo.app as Manifest["app"],
    mode: "managed",
    access: {
      ...access,
      identity: {
        ...access.identity,
        oidc: {
          ...(access.identity as { oidc: object }).oidc,
          redirectUri: "http://127.0.0.1/callback",
        },
      },
      credential: { ...access.credential, storage: { provider: "system" } },
    } as AccessManifest,
    stateDir: stateDir(),
    distributionDir: temp,
    env: services.env(),
    secretStore: store,
  });
}

function login(distribution: DistributionAccess) {
  return distribution.login({ openUrl: (url) => void services.approve(url) });
}

/** Cut a JSON file short, as a damaged disk or an interrupted copy leaves it. */
function truncate(path: string, keep: (text: string) => number): void {
  const text = readFileSync(path, "utf8");
  writeFileSync(path, text.slice(0, keep(text)));
  expect(() => JSON.parse(readFileSync(path, "utf8"))).toThrow();
}

describe("identity token bundles", () => {
  it("keeps a replaced generation whose deletion failed tracked across another refresh, then deletes it", async () => {
    const store = new FlakyStore();
    services.knobs.accessTokenTtl = 30;
    await login(open(store));
    // #1 -> #2: deleting #1 fails.
    store.failDeletes = /:identity#1$/;
    await open(store).activate();
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).toMatchObject({
      secretRef: `piship:${ID}:identity#2`,
      orphans: [`piship:${ID}:identity#1`],
    });
    // #2 -> #3 succeeds for #2; #1 still fails and stays tracked.
    await open(store).activate();
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).toMatchObject({
      secretRef: `piship:${ID}:identity#3`,
      orphans: [`piship:${ID}:identity#1`],
    });
    expect(store.refs()).toEqual(
      expect.arrayContaining([`piship:${ID}:identity#1`]),
    );
    expect(store.refs()).not.toContain(`piship:${ID}:identity#2`);
    // The store recovers: the next refresh deletes it.
    store.failDeletes = null;
    await open(store).activate();
    expect(store.refs().filter((ref) => ref.includes(":identity#"))).toEqual([
      `piship:${ID}:identity#4`,
    ]);
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).not.toHaveProperty(
      "orphans",
    );
  });

  it("deletes the token bundle a truncated session file still names, and signs the user out", async () => {
    const store = new FlakyStore();
    await login(open(store));
    const ref = `piship:${ID}:identity#1`;
    expect(await store.get(ref)).not.toBeNull();
    truncate(identityFile(), (text) => text.indexOf(ref) + ref.length + 1);
    await expect(open(store).activate()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
    expect(await store.get(ref)).toBeNull();
    expect(existsSync(identityFile())).toBe(false);
  });

  it("keeps a truncated session's token bundle tracked while it cannot be deleted", async () => {
    const store = new FlakyStore();
    await login(open(store));
    const ref = `piship:${ID}:identity#1`;
    truncate(identityFile(), (text) => text.indexOf(ref) + ref.length + 1);
    store.failDeletes = /:identity#/;
    await expect(open(store).activate()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: expect.arrayContaining([ref]),
    });
    store.failDeletes = null;
    await expect(open(store).logout()).resolves.toEqual([]);
    expect(store.refs().filter((item) => item.includes(":identity#"))).toEqual(
      [],
    );
  });

  it("tracks a first token bundle whose write failed before the session was committed", async () => {
    const store = new FlakyStore();
    store.failAfterPut = true;
    await expect(login(open(store))).rejects.toThrow();
    expect(store.refs()).toContain(`piship:${ID}:identity#1`);
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: [`piship:${ID}:identity#1`],
    });
    // Never restored as a session.
    expect(open(store).readIdentityMetadata()).toBeNull();
    await expect(open(store).logout()).resolves.toEqual([]);
    expect(store.refs()).toEqual([]);
  });
});

describe("purge retries what logout could not delete", () => {
  it("deletes the identity and credential secrets a failed logout left tracked", async () => {
    const store = new FlakyStore();
    await login(open(store));
    store.failDeletes = /./;
    const problems = await open(store).logout();
    expect(problems.length).toBeGreaterThan(0);
    for (const file of [identityFile(), credentialFile()])
      expect(JSON.parse(readFileSync(file, "utf8")).schema).toMatch(
        /-discarded\/v1$/,
      );
    await expect(
      purgeDistributionState(ID, { secretStore: store }),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(existsSync(stateDir())).toBe(true);
    store.failDeletes = null;
    await purgeDistributionState(ID, { secretStore: store });
    expect(store.refs()).toEqual([]);
    expect(existsSync(stateDir())).toBe(false);
  });

  it("deletes the secrets damaged metadata files still name", async () => {
    const store = new FlakyStore();
    await login(open(store));
    const identity = `piship:${ID}:identity#1`;
    const credential = `piship:${ID}:inference#1`;
    truncate(
      identityFile(),
      (text) => text.indexOf(identity) + identity.length,
    );
    truncate(
      credentialFile(),
      (text) => text.indexOf(credential) + credential.length,
    );
    const result = await purgeDistributionState(ID, { secretStore: store });
    expect(result.deletedSecrets).toEqual(
      expect.arrayContaining([identity, credential]),
    );
    expect(store.refs()).toEqual([]);
  });
});
