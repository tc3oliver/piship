import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type SecretStore, SecretValue } from "@piship/contracts";
import {
  CREDENTIAL_METADATA_SCHEMA,
  MemorySecretStore,
  RestrictedFileSecretStore,
  withFileLock,
} from "@piship/credentials";
import { identityMetadata, identitySecret } from "@piship/identity";
import {
  type AccessManifest,
  type Manifest,
  readManifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { type AccessEvent, DistributionAccess } from "./access/index.js";
import { readPreferences, setPreference } from "./config.js";
import { snapshotState } from "./update/state.js";

// User switching: Alice and Bob sign in through the fixture's subject knob.
// Nothing Alice's runtime credential, entitlement, or model selection
// consisted of may survive into Bob's session, whatever the path: logout
// first, login over her, a crash in the middle, a failing secret store, or
// her metadata put back under his identity.

const demo = readManifest(
  fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;

const ALICE = {
  subject: "alice-0001",
  displayName: "Alice",
  email: "alice@demo.example",
  models: ["acme/coder", "acme/general"],
};
const BOB = {
  subject: "bob-0002",
  displayName: "Bob",
  email: "bob@demo.example",
  models: ["acme/coder"],
};
type Person = typeof ALICE;

type Services = Awaited<ReturnType<typeof startLocalServices>>;

/** Wraps a store so tests can make deletions fail, as a locked keyring does. */
class FlakyStore implements SecretStore {
  readonly kind = "memory";
  readonly description = "test store with failing deletes";
  /** References whose deletion fails; null lets every deletion through. */
  failDeletes: RegExp | null = null;
  constructor(readonly inner = new MemorySecretStore()) {}
  put(ref: string, value: SecretValue) {
    return this.inner.put(ref, value);
  }
  get(ref: string) {
    return this.inner.get(ref);
  }
  async delete(ref: string) {
    if (this.failDeletes?.test(ref))
      throw new Error("the keyring is locked: Bearer demo-at-not-a-real-one");
    return this.inner.delete(ref);
  }
  refs() {
    return this.inner.refs();
  }
}

let temp: string;
let services: Services;
let events: AccessEvent[];
beforeEach(async () => {
  temp = mkdtempSync(join(tmpdir(), "piship-user-switch-"));
  services = await startLocalServices();
  events = [];
});
afterEach(async () => {
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

const stateDir = () => join(temp, "state");

function options(
  store: SecretStore | "file",
  extra: Partial<Parameters<typeof DistributionAccess.open>[0]> = {},
): Parameters<typeof DistributionAccess.open>[0] {
  return {
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
      credential: {
        ...access.credential,
        storage: { provider: store === "file" ? "file" : "system" },
      },
    } as AccessManifest,
    stateDir: stateDir(),
    distributionDir: temp,
    env: services.env(),
    ...(store === "file" ? {} : { secretStore: store }),
    onEvent: (event) => events.push(event),
    ...extra,
  };
}

function as(person: Person): void {
  services.knobs.subject = person.subject;
  services.knobs.displayName = person.displayName;
  services.knobs.email = person.email;
  services.knobs.entitledModels = [...person.models];
}

async function login(distribution: DistributionAccess, person: Person) {
  as(person);
  return distribution.login({ openUrl: (url) => void services.approve(url) });
}

/** Every secret the fixture issued to `person`: credentials and tokens. */
function secretsOf(person: Person): string[] {
  const { state } = services;
  const owned = (map: Map<string, { subject: string }>) =>
    [...map].filter(([, entry]) => entry.subject === person.subject);
  return [
    ...owned(state.credentials),
    ...owned(state.accessTokens),
    ...owned(state.refreshTokens),
  ].map(([secret]) => secret);
}

function credentialOf(person: Person): { secret: string; id: string }[] {
  return [...services.state.credentials]
    .filter(([, entry]) => entry.subject === person.subject)
    .map(([secret, entry]) => ({ secret, id: entry.id }));
}

/**
 * Where a sentinel could survive: every file under the state directory
 * (including rollback snapshots and the file fallback), and every value the
 * secret store holds.
 */
async function residue(
  store: SecretStore,
  sentinels: readonly string[],
): Promise<string[]> {
  const hits: string[] = [];
  const check = (where: string, text: string) => {
    for (const sentinel of sentinels)
      if (text.includes(sentinel)) hits.push(`${where}: ${sentinel}`);
  };
  const visit = (directory: string) => {
    if (!existsSync(directory)) return;
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      if (statSync(path).isDirectory()) visit(path);
      else check(path, readFileSync(path, "utf8"));
    }
  };
  visit(stateDir());
  let refs: string[] = [];
  if (store instanceof MemorySecretStore || store instanceof FlakyStore)
    refs = store.refs();
  else if (
    store instanceof RestrictedFileSecretStore &&
    existsSync(store.directory)
  )
    refs = readdirSync(store.directory).map(
      (name) =>
        (
          JSON.parse(readFileSync(join(store.directory, name), "utf8")) as {
            ref: string;
          }
        ).ref,
    );
  for (const ref of refs) {
    const value = await store.get(ref);
    if (value) check(`store ${ref}`, value.reveal());
  }
  return hits;
}

const gatewayKeysSince = (index: number): string[] =>
  services.state.requests
    .slice(index)
    .filter((item: { path: string }) => item.path.startsWith("/gateway/"))
    .map((item: { authorization: string | null }) =>
      (item.authorization ?? "").replace(/^Bearer /, ""),
    );

const credentialFile = () =>
  join(stateDir(), "credentials-metadata", "inference.json");
const identityFile = () => join(stateDir(), "identity", "session.json");
const preferencesFile = () => join(stateDir(), "config", "preferences.json");

function selectModel(model: string) {
  setPreference(preferencesFile(), access, undefined, "model", model);
}

describe.each([
  ["the system secret store", () => new MemorySecretStore()],
  ["the file fallback", () => "file" as const],
])("user switching with %s (fixtures)", (_name, makeStore) => {
  let selected: SecretStore | "file";
  let store: SecretStore;
  let distribution: DistributionAccess;
  // Every instance in a test shares one store (the same directory for the
  // file fallback).
  const reopen = (
    extra: Partial<Parameters<typeof DistributionAccess.open>[0]> = {},
  ) => DistributionAccess.open(options(selected, extra));
  beforeEach(() => {
    selected = makeStore();
    distribution = reopen();
    store = distribution.store as SecretStore;
  });

  it("case 2: logging in as Bob over Alice reuses none of her credential, entitlement, metadata, cache, or model selection", async () => {
    await login(distribution, ALICE);
    const alice = await distribution.activate();
    expect(alice.identity?.subject).toBe(ALICE.subject);
    expect(alice.config.allowedModels).toEqual(ALICE.models);
    selectModel("acme/general");
    setPreference(
      preferencesFile(),
      access,
      undefined,
      "thinkingLevel",
      "high",
    );
    // A rollback snapshot taken while Alice was signed in.
    snapshotState(stateDir(), "1.0.0", "1.1.0", new Date());
    const aliceSecrets = secretsOf(ALICE);
    const [aliceCredential] = credentialOf(ALICE);
    expect(aliceCredential).toBeDefined();
    // The same instance's cached secret is Alice's before the switch.
    expect((await distribution.requestSecret())?.reveal()).toBe(
      aliceCredential?.secret,
    );

    events.length = 0;
    const requests = services.state.requests.length;
    const signedIn = await login(distribution, BOB);
    expect(signedIn.identity?.subject).toBe(BOB.subject);
    expect(events.map((event) => event.event)).toEqual([
      "credential.revoke",
      "identity.login",
      "credential.acquire",
    ]);
    expect(events[1]?.detail).toMatchObject({ principalChange: true });
    // Alice's credential was revoked at the broker, not only deleted.
    expect(services.state.revokedCredentials).toEqual([aliceCredential?.id]);

    const bob = await reopen().activate();
    const [bobCredential] = credentialOf(BOB);
    expect(bob.identity).toMatchObject({
      subject: BOB.subject,
      email: BOB.email,
    });
    // Credential and team metadata (the broker's credential ID and
    // entitlement) are Bob's own.
    expect(bob.credential.ref?.credentialId).toBe(bobCredential?.id);
    expect(bob.credential.ref?.credentialId).not.toBe(aliceCredential?.id);
    // Entitlement: Bob is entitled to acme/coder only.
    expect(bob.config.allowedModels).toEqual(BOB.models);
    const metadata = JSON.parse(readFileSync(credentialFile(), "utf8"));
    expect(metadata).toMatchObject({
      schema: CREDENTIAL_METADATA_SCHEMA,
      credential_id: bobCredential?.id,
      models: BOB.models,
      principal: { issuer: services.issuer, subject: BOB.subject },
    });
    // Model selection was Alice's and is gone; her other preferences stay.
    expect(readPreferences(preferencesFile()).values).toEqual({
      thinkingLevel: "high",
    });
    expect(bob.selectedModel).toBe("acme/coder");
    // Cache: the catalog and every gateway call after the switch used Bob's
    // key, and the in-memory secret of the long-lived instance is his.
    const keys = gatewayKeysSince(requests);
    expect(keys.length).toBeGreaterThan(0);
    expect(new Set(keys)).toEqual(new Set([bobCredential?.secret]));
    expect((await distribution.requestSecret())?.reveal()).toBe(
      bobCredential?.secret,
    );
    expect(distribution.enterpriseContext(bob).identity?.subject).toBe(
      BOB.subject,
    );
    // Case 6: no Alice secret anywhere, rollback snapshots included.
    snapshotState(stateDir(), "1.1.0", "1.0.0", new Date());
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("case 1: Alice logs out, then Bob logs in; case 6: nothing of Alice remains", async () => {
    await login(distribution, ALICE);
    selectModel("acme/general");
    const aliceSecrets = secretsOf(ALICE);
    expect(await distribution.logout()).toEqual([]);
    // Logout keeps the principal binding, so Bob's sign-in still sees the
    // change of user and clears Alice's model selection.
    expect(distribution.readPrincipalBinding()).toMatchObject({
      subject: ALICE.subject,
    });
    await login(distribution, BOB);
    expect(distribution.readPrincipalBinding()).toMatchObject({
      subject: BOB.subject,
    });
    expect(readPreferences(preferencesFile()).values.model).toBeUndefined();
    const bob = await reopen().activate();
    expect(bob.identity?.subject).toBe(BOB.subject);
    expect(bob.config.allowedModels).toEqual(BOB.models);
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("rollback cannot resurrect Alice's credential, and Alice signing in again gets a new one", async () => {
    await login(distribution, ALICE);
    const [aliceCredential] = credentialOf(ALICE);
    snapshotState(stateDir(), "1.0.0", "1.1.0", new Date());
    await login(distribution, BOB);
    // What any release, older ones included, finds after a rollback: the
    // metadata it can read points at Bob's secret, and no reference in the
    // store or the snapshots holds Alice's.
    const metadata = JSON.parse(readFileSync(credentialFile(), "utf8"));
    expect(metadata.schema).toBe(CREDENTIAL_METADATA_SCHEMA);
    expect((await store.get(metadata.credential_ref))?.reveal()).toBe(
      credentialOf(BOB)[0]?.secret,
    );
    for (
      let generation = 0;
      generation <= metadata.generation + 1;
      generation++
    )
      expect(
        (await store.get(`piship:acmecode:inference#${generation}`))?.reveal(),
      ).not.toBe(aliceCredential?.secret);
    const snapshots = join(stateDir(), "migration", "snapshots");
    for (const snapshot of readdirSync(snapshots))
      expect(
        JSON.parse(
          readFileSync(join(snapshots, snapshot, "snapshot.json"), "utf8"),
        ).files,
      ).not.toContain("credentials-metadata/inference.json");
    expect(await residue(store, secretsOf(ALICE))).toEqual([]);
    // A to B to A: Alice gets a new credential; the revoked one never returns.
    await login(distribution, ALICE);
    const again = await reopen().activate();
    expect(again.credential.ref?.credentialId).not.toBe(aliceCredential?.id);
    expect(
      services.state.credentials.get(aliceCredential?.secret)?.revoked,
    ).toBe(true);
  });

  it("the same user signing in again keeps the model selection and resumes", async () => {
    await login(distribution, ALICE);
    selectModel("acme/general");
    events.length = 0;
    await login(distribution, ALICE);
    expect(
      events.find((event) => event.event === "identity.login")?.detail,
    ).not.toHaveProperty("principalChange");
    expect(readPreferences(preferencesFile()).values.model).toBe(
      "acme/general",
    );
    expect((await reopen().activate()).selectedModel).toBe("acme/general");
  });

  it("case 3: a crash after Bob's identity is stored leaves no Alice credential for Bob's launch", async () => {
    await login(distribution, ALICE);
    const aliceSecrets = secretsOf(ALICE);
    const crashing = reopen({
      onPhase: (phase: string) => {
        if (phase === "identity-stored") throw new Error("simulated crash");
      },
    });
    await expect(login(crashing, BOB)).rejects.toThrow("simulated crash");
    // The crash point is after Alice's credential was deleted: no state ever
    // held Bob's identity together with Alice's credential.
    expect(existsSync(credentialFile())).toBe(false);
    expect(distribution.readIdentityMetadata()?.subject).toBe(BOB.subject);
    const bob = await reopen().activate();
    expect(bob.credential.ref?.credentialId).toBe(credentialOf(BOB)[0]?.id);
    expect(bob.config.allowedModels).toEqual(BOB.models);
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("case 3: a crash before Bob's identity is stored leaves Alice's session without her old credential", async () => {
    await login(distribution, ALICE);
    const [aliceCredential] = credentialOf(ALICE);
    const crashing = reopen({
      onPhase: (phase: string) => {
        if (phase === "credential-cleared") throw new Error("simulated crash");
      },
    });
    await expect(login(crashing, BOB)).rejects.toThrow("simulated crash");
    expect(existsSync(credentialFile())).toBe(false);
    expect(distribution.readIdentityMetadata()?.subject).toBe(ALICE.subject);
    expect(
      await residue(store, [aliceCredential?.secret ?? "missing"]),
    ).toEqual([]);
  });

  it("case 3 and 5: Bob's identity stored beside Alice's credential (an interrupted older release) discards hers at Bob's launch", async () => {
    await login(distribution, ALICE);
    selectModel("acme/general");
    const aliceSecrets = secretsOf(ALICE);
    const [aliceCredential] = credentialOf(ALICE);
    // What the previous login order left after a crash: Bob's identity is
    // stored, Alice's credential is not cleared yet.
    as(BOB);
    const provider = await distribution.identityProvider();
    const bobSession = await provider?.login({
      openUrl: (url) => void services.approve(url),
    });
    if (!bobSession) throw new Error("no session");
    const alicesIdentity = distribution.readIdentityMetadata();
    await store.put("piship:acmecode:identity#2", identitySecret(bobSession));
    writeFileSync(
      join(stateDir(), "identity", "session.json"),
      JSON.stringify(
        identityMetadata(bobSession, "piship:acmecode:identity#2"),
      ),
    );
    if (alicesIdentity) await store.delete(alicesIdentity.secretRef);

    events.length = 0;
    const requests = services.state.requests.length;
    const bob = await reopen().activate();
    expect(bob.identity?.subject).toBe(BOB.subject);
    expect(bob.credential.ref?.credentialId).toBe(credentialOf(BOB)[0]?.id);
    expect(bob.config.allowedModels).toEqual(BOB.models);
    expect(bob.selectedModel).toBe("acme/coder");
    expect(bob.notices).toEqual(
      expect.arrayContaining([
        expect.stringContaining("not issued to the signed-in identity"),
        expect.stringContaining("model selection"),
      ]),
    );
    expect(events).toContainEqual({
      event: "credential.revoke",
      detail: expect.objectContaining({
        reason: "principal-change",
        revocation: "revoked",
        credentialId: aliceCredential?.id,
      }),
    });
    expect(gatewayKeysSince(requests)).not.toContain(aliceCredential?.secret);
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("case 5: Alice's credential metadata restored under Bob's identity is discarded, not used", async () => {
    await login(distribution, ALICE);
    const [aliceCredential] = credentialOf(ALICE);
    const aliceMetadata = readFileSync(credentialFile(), "utf8");
    const aliceRef = JSON.parse(aliceMetadata).credential_ref;
    await login(distribution, BOB);
    // Put Alice's metadata and secret back, as a restore from a backup would.
    writeFileSync(credentialFile(), aliceMetadata);
    await store.put(aliceRef, new SecretValue(aliceCredential?.secret ?? ""));
    services.state.credentials.get(aliceCredential?.secret).revoked = false;
    const requests = services.state.requests.length;
    const bob = await reopen().activate();
    expect(bob.credential.ref?.credentialId).not.toBe(aliceCredential?.id);
    expect(gatewayKeysSince(requests)).not.toContain(aliceCredential?.secret);
    expect(await store.get(aliceRef)).not.toSatisfy(
      (value: SecretValue | null) =>
        value?.reveal() === aliceCredential?.secret,
    );
    expect(
      await residue(store, [aliceCredential?.secret ?? "missing"]),
    ).toEqual([]);
  });
});

describe("user switching when the secret store fails (fixtures)", () => {
  it("case 4: a failed deletion blocks Bob's login before his identity is stored, and a recovered store completes it", async () => {
    const store = new FlakyStore();
    const distribution = DistributionAccess.open(options(store));
    await login(distribution, ALICE);
    const aliceSecrets = secretsOf(ALICE);
    // Only the runtime credential's secrets fail to delete.
    store.failDeletes = /:inference#/;
    const error = await login(distribution, BOB).catch((caught) => caught);
    expect(error).toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(String(error.message)).not.toContain("demo-at-not-a-real-one");
    // Bob's identity was never stored, so no state pairs him with Alice's
    // credential, and the credential is a discarded marker nobody can use.
    expect(distribution.readIdentityMetadata()?.subject).toBe(ALICE.subject);
    const marker = JSON.parse(
      readFileSync(
        join(stateDir(), "credentials-metadata", "inference.json"),
        "utf8",
      ),
    );
    expect(marker.schema).not.toBe(CREDENTIAL_METADATA_SCHEMA);
    expect(marker.orphans).toEqual(
      expect.arrayContaining(["piship:acmecode:inference#1"]),
    );
    // Neither user can launch on it while the store still fails.
    await expect(
      DistributionAccess.open(options(store)).activate(),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    await expect(
      DistributionAccess.open(options(store)).requestSecret(),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    store.failDeletes = null;
    await login(distribution, BOB);
    const bob = await DistributionAccess.open(options(store)).activate();
    expect(bob.identity?.subject).toBe(BOB.subject);
    expect(bob.config.allowedModels).toEqual(BOB.models);
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("case 4: Alice's identity tokens that cannot be deleted also block Bob's login", async () => {
    const store = new FlakyStore();
    const distribution = DistributionAccess.open(options(store));
    await login(distribution, ALICE);
    const aliceSecrets = secretsOf(ALICE);
    store.failDeletes = /:identity#/;
    await expect(login(distribution, BOB)).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    // Bob's identity was never stored. Alice's session (already revoked at
    // the identity provider) is a discarded marker that still tracks her
    // token bundle and is never restored as a session.
    expect(distribution.readIdentityMetadata()).toBeNull();
    const marker = JSON.parse(readFileSync(identityFile(), "utf8"));
    expect(marker).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: expect.arrayContaining(["piship:acmecode:identity#1"]),
    });
    expect(JSON.stringify(marker)).not.toContain(ALICE.subject);
    // Alice's runtime credential was already gone before her tokens.
    expect(existsSync(credentialFile())).toBe(false);
    store.failDeletes = null;
    await login(distribution, BOB);
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("a failed deletion during logout is reported and the secret stays tracked", async () => {
    const store = new FlakyStore();
    const distribution = DistributionAccess.open(options(store));
    await login(distribution, ALICE);
    store.failDeletes = /./;
    const problems = await distribution.logout();
    expect(problems).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^delete piship:acmecode:inference#1: /),
        expect.stringMatching(/^identity secret piship:acmecode:identity#1: /),
      ]),
    );
    for (const problem of problems)
      expect(problem).not.toContain("demo-at-not-a-real-one");
    // The session is signed out all the same: a discarded marker keeps its
    // tokens tracked and no release restores it as a session.
    expect(distribution.readIdentityMetadata()).toBeNull();
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).toMatchObject({
      schema: "piship-identity-discarded/v1",
    });
    store.failDeletes = null;
    expect(await distribution.logout()).toEqual([]);
    expect(store.refs()).toEqual([]);
  });

  it("a failed broker revocation does not block Bob; it is recorded without the secret and re-checked at the next login", async () => {
    let now = Date.now();
    const store = new MemorySecretStore();
    const distribution = DistributionAccess.open(
      options(store, { now: () => now }),
    );
    await login(distribution, ALICE);
    const [aliceCredential] = credentialOf(ALICE);
    services.knobs.revokeStatus = 503;
    events.length = 0;
    const bob = await login(distribution, BOB);
    expect(bob.identity?.subject).toBe(BOB.subject);
    expect(bob.notices).toEqual(
      expect.arrayContaining([
        expect.stringContaining("deleted locally but not revoked"),
      ]),
    );
    expect(events[0]).toMatchObject({
      event: "credential.revoke",
      detail: { revocation: "failed", retryPending: true },
    });
    // Deleted locally all the same.
    expect(
      await residue(store, [aliceCredential?.secret ?? "missing"]),
    ).toEqual([]);
    const pending = distribution.pendingRevocations();
    expect(pending).toMatchObject({
      readable: true,
      count: 1,
      entries: [{ credentialId: aliceCredential?.id, reason: "replace" }],
    });
    const file = readFileSync(
      join(stateDir(), "credentials-metadata", "revocation-retry.json"),
      "utf8",
    );
    for (const secret of secretsOf(ALICE)) expect(file).not.toContain(secret);
    // The next login re-checks it and keeps showing it.
    services.knobs.revokeStatus = undefined;
    now += 60_000;
    const again = await login(distribution, BOB);
    expect(again.notices).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `Credential ${aliceCredential?.id} could not be revoked`,
        ),
      ]),
    );
    expect(distribution.pendingRevocations()).toMatchObject({
      count: 1,
      oldestAgeSeconds: 60,
    });
    // Once Alice's credential has expired, it can no longer be used anywhere.
    now += 2 * 3600 * 1000;
    await login(distribution, BOB);
    expect(distribution.pendingRevocations().count).toBe(0);
  });

  it("refuses an identity refresh that returns another subject and keeps the stored identity", async () => {
    const store = new MemorySecretStore();
    const distribution = DistributionAccess.open(options(store));
    services.knobs.accessTokenTtl = 30;
    await login(distribution, ALICE);
    services.knobs.refreshSubject = BOB.subject;
    await expect(
      DistributionAccess.open(options(store)).currentIdentity({
        required: true,
      }),
    ).rejects.toMatchObject({ code: "IDENTITY_INVALID" });
    expect(distribution.readIdentityMetadata()?.subject).toBe(ALICE.subject);
  });

  it("does not bring a signed-out identity back when a refresh that started earlier returns", async () => {
    const store = new MemorySecretStore();
    const distribution = DistributionAccess.open(options(store));
    services.knobs.accessTokenTtl = 30;
    await login(distribution, ALICE);
    services.knobs.tokenDelayMs = 400;
    const refreshing = DistributionAccess.open(options(store)).currentIdentity({
      required: true,
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    // A sign-out that did not wait for the refresh: the metadata and the
    // token bundles are gone while the provider call is still in flight.
    for (const ref of store.refs()) await store.delete(ref);
    rmSync(distribution.paths.identity);
    await expect(refreshing).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
    expect(existsSync(distribution.paths.identity)).toBe(false);
    expect(store.refs().filter((ref) => ref.includes(":identity#"))).toEqual(
      [],
    );
  });
});

/** A promise the test resolves by hand: `wait` blocks until `open()`. */
function gate(): { open: () => void; wait: Promise<void> } {
  let open: () => void = () => undefined;
  const wait = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { open, wait };
}

const settle = (ms = 150) => new Promise((resolve) => setTimeout(resolve, ms));

const PIN_ERROR = {
  code: "IDENTITY_REQUIRED",
  message: "The signed-in user changed; restart the session",
};

describe("a running session while another sign-in happens (fixtures)", () => {
  let store: FlakyStore;
  const open = (
    extra: Partial<Parameters<typeof DistributionAccess.open>[0]> = {},
  ) => DistributionAccess.open(options(store, extra));
  beforeEach(() => {
    store = new FlakyStore();
  });

  /** Bob's credential is untouched and the only one bound in the state. */
  function expectBobsCredentialIntact(): void {
    const [bobCredential] = credentialOf(BOB);
    expect(bobCredential).toBeDefined();
    expect(services.state.credentials.get(bobCredential?.secret)?.revoked).toBe(
      false,
    );
    expect(JSON.parse(readFileSync(credentialFile(), "utf8"))).toMatchObject({
      credential_id: bobCredential?.id,
      principal: { subject: BOB.subject },
    });
    expect(open().readIdentityMetadata()?.subject).toBe(BOB.subject);
  }

  it("does not mark Bob's credential as rejected when a request of Alice's session fails after Bob signed in", async () => {
    await login(open(), ALICE);
    const running = open();
    await running.activate();
    services.knobs.revokeStatus = 503;
    await login(open(), BOB);
    services.knobs.revokeStatus = undefined;
    const before = readFileSync(credentialFile(), "utf8");
    // A request Alice's session sent before Bob signed in is rejected.
    await running.markCredentialRejected();
    expect(readFileSync(credentialFile(), "utf8")).toBe(before);
    expect(JSON.parse(before)).not.toHaveProperty("rejected_at");
    expectBobsCredentialIntact();
  });

  it("does not mark a credential re-issued to the same user under the same reference as rejected", async () => {
    await login(open(), ALICE);
    const running = open();
    await running.activate();
    // Alice signs in again elsewhere: generations restart, so the new
    // credential reuses the reference the running session holds.
    await login(open(), ALICE);
    const stored = JSON.parse(readFileSync(credentialFile(), "utf8"));
    await running.markCredentialRejected();
    expect(JSON.parse(readFileSync(credentialFile(), "utf8"))).toEqual(stored);
    // The session does not go on serving the revoked secret from its cache.
    const [current] = credentialOf(ALICE).slice(-1);
    expect((await running.requestSecret())?.reveal()).toBe(current?.secret);
  });

  it("never serves Alice's cached secret, or a credential issued to Bob, after Bob signs in elsewhere", async () => {
    await login(open(), ALICE);
    const running = open();
    const alice = await running.activate();
    const aliceSecret = alice.credential.secret?.reveal();
    expect((await running.requestSecret())?.reveal()).toBe(aliceSecret);
    // Alice's credential cannot be revoked at the broker, so it would still
    // work at the gateway if the running session kept using it.
    services.knobs.revokeStatus = 503;
    await login(open(), BOB);
    services.knobs.revokeStatus = undefined;
    const requests = services.state.requests.length;
    // Fast path: the cached secret is Alice's, the stored credential Bob's.
    await expect(running.requestSecret()).rejects.toMatchObject(PIN_ERROR);
    // Slow path: a forced renewal must not hand Alice's session Bob's.
    await expect(running.requestSecret({ force: true })).rejects.toMatchObject(
      PIN_ERROR,
    );
    await expect(running.requestSecret()).rejects.toMatchObject(PIN_ERROR);
    expect(gatewayKeysSince(requests)).toEqual([]);
    expectBobsCredentialIntact();
    expect(credentialOf(ALICE)).toHaveLength(1);
  });

  it("never renews into Bob's credential after the gateway rejects Alice's during activation", async () => {
    await login(open(), ALICE);
    const [aliceCredential] = credentialOf(ALICE);
    // The gateway now rejects Alice's credential (HTTP 401).
    services.state.credentials.get(aliceCredential?.secret).revoked = true;
    const running = open({
      onPhase: async (phase: string) => {
        if (phase === "credential-rejected") await login(open(), BOB);
      },
    });
    await expect(running.activate()).rejects.toMatchObject(PIN_ERROR);
    expectBobsCredentialIntact();
    expect(credentialOf(ALICE)).toHaveLength(1);
  });

  it("scenario A: a launch that resolved Alice before Bob signed in never discards his credential or acquires hers", async () => {
    await login(open(), ALICE);
    selectModel("acme/general");
    const running = open({
      onPhase: async (phase: string) => {
        if (phase === "identity-resolved") await login(open(), BOB);
      },
    });
    await expect(running.activate()).rejects.toMatchObject(PIN_ERROR);
    expectBobsCredentialIntact();
    // No credential was acquired for Alice with her still-valid token, and
    // the state is still bound to Bob.
    expect(credentialOf(ALICE)).toHaveLength(1);
    expect(open().readPrincipalBinding()).toMatchObject({
      subject: BOB.subject,
    });
    const bob = await open().activate();
    expect(bob.identity?.subject).toBe(BOB.subject);
    expect(bob.credential.ref?.credentialId).toBe(credentialOf(BOB)[0]?.id);
  });

  it("a launch waits while a sign-in holds the credential lock, then stops for the new user (real locks)", async () => {
    await login(open(), ALICE);
    const held = gate();
    const locked = gate();
    const signingIn = login(
      open({
        onPhase: async (phase: string) => {
          if (phase === "login-locked") {
            locked.open();
            await held.wait;
          }
        },
      }),
      BOB,
    );
    await locked.wait;
    const resolved = gate();
    let finished = false;
    const launching = open({
      onPhase: (phase: string) => {
        if (phase === "identity-resolved") resolved.open();
      },
    })
      .activate()
      .finally(() => {
        finished = true;
      });
    // The launch read Alice's identity (the sign-in has changed nothing yet)
    // and now waits for the credential lock.
    await resolved.wait;
    await settle();
    expect(finished).toBe(false);
    held.open();
    await signingIn;
    await expect(launching).rejects.toMatchObject(PIN_ERROR);
    expectBobsCredentialIntact();
    expect(credentialOf(ALICE)).toHaveLength(1);
  });

  it("two sign-ins run one after the other (real locks)", async () => {
    await login(open(), ALICE);
    const held = gate();
    const cleared = gate();
    const first = login(
      open({
        onPhase: async (phase: string) => {
          if (phase === "credential-cleared") {
            cleared.open();
            await held.wait;
          }
        },
      }),
      BOB,
    );
    await cleared.wait;
    // Alice signs in again from another terminal while Bob's sign-in is
    // halfway: hers waits for his to finish, then replaces it.
    let secondDone = false;
    const second = login(open(), ALICE).finally(() => {
      secondDone = true;
    });
    await settle(300);
    expect(secondDone).toBe(false);
    held.open();
    await first;
    await second;
    expect(open().readIdentityMetadata()?.subject).toBe(ALICE.subject);
    const metadata = JSON.parse(readFileSync(credentialFile(), "utf8"));
    expect(metadata.principal).toMatchObject({ subject: ALICE.subject });
    expect(metadata.credential_id).toBe(credentialOf(ALICE).at(-1)?.id);
    // Bob's credential and tokens were cleared by the second sign-in.
    expect(await residue(store, secretsOf(BOB))).toEqual([]);
    const alice = await open().activate();
    expect(alice.identity?.subject).toBe(ALICE.subject);
  });

  it("scenario B: a sign-in waits for an identity refresh in progress, then replaces the refreshed session (real locks)", async () => {
    services.knobs.accessTokenTtl = 30;
    await login(open(), ALICE);
    const running = open();
    const provider = await running.identityProvider();
    if (!provider?.refresh) throw new Error("no refresh");
    const refresh = provider.refresh.bind(provider);
    const refreshing = gate();
    const release = gate();
    provider.refresh = async (session) => {
      refreshing.open();
      await release.wait;
      return refresh(session);
    };
    const launching = running.activate();
    await refreshing.wait;
    // Alice's refresh holds the identity lock: Bob's sign-in clears the
    // credential and then waits for it, and never stores beside it.
    let signedIn = false;
    const signingIn = login(open(), BOB).finally(() => {
      signedIn = true;
    });
    await settle(300);
    expect(signedIn).toBe(false);
    expect(open().readIdentityMetadata()?.subject).toBe(ALICE.subject);
    release.open();
    await signingIn;
    await expect(launching).rejects.toMatchObject(PIN_ERROR);
    // The session file is Bob's; nothing of Alice's, her refreshed tokens
    // included, is left anywhere.
    expect(open().readIdentityMetadata()?.subject).toBe(BOB.subject);
    expect(await residue(store, secretsOf(ALICE))).toEqual([]);
    const bob = await open().activate();
    expect(bob.identity?.subject).toBe(BOB.subject);
  });

  it("a refresh never spends another principal's refresh token", async () => {
    services.knobs.accessTokenTtl = 30;
    await login(open(), ALICE);
    const running = open();
    // Hold the identity lock, as a concurrent sign-in would, while the
    // running session has read Alice's expiring session.
    const read = gate();
    const inner = store.inner;
    const originalGet = inner.get.bind(inner);
    inner.get = async (ref: string) => {
      const value = await originalGet(ref);
      if (ref.includes(":identity#")) read.open();
      return value;
    };
    const locked = gate();
    const unlock = gate();
    const holding = withFileLock(running.paths.identity, async () => {
      locked.open();
      await unlock.wait;
      // Meanwhile Bob's session replaces Alice's on disk.
      as(BOB);
      const bobSession = await (await running.identityProvider())?.login({
        openUrl: (url) => void services.approve(url),
      });
      if (!bobSession) throw new Error("no session");
      await store.put("piship:acmecode:identity#9", identitySecret(bobSession));
      writeFileSync(
        identityFile(),
        JSON.stringify(
          identityMetadata(bobSession, "piship:acmecode:identity#9"),
        ),
      );
    });
    await locked.wait;
    // Started outside the held lock: the refresh waits for it.
    const refreshing = running
      .currentIdentity({ required: true })
      .catch((error: unknown) => error);
    await read.wait;
    inner.get = originalGet;
    unlock.open();
    await holding;
    const bobRefreshTokens = [...services.state.refreshTokens]
      .filter(([, entry]) => entry.subject === BOB.subject)
      .map(([token]) => token);
    expect(bobRefreshTokens.length).toBeGreaterThan(0);
    expect(await refreshing).toMatchObject({
      code: "IDENTITY_INVALID",
      message: "Another identity signed in; run login again",
    });
    // Bob's refresh token was not used (the fixture rotates on use).
    for (const token of bobRefreshTokens)
      expect(services.state.refreshTokens.has(token)).toBe(true);
    expect(open().readIdentityMetadata()?.subject).toBe(BOB.subject);
  });

  it("stops a login at every crash point without leaving Alice's credential usable by Bob", async () => {
    for (const phase of [
      "revoked",
      "secret-deleted",
      "credential-cleared",
      "principal-bound",
      "identity-cleared",
      "identity-stored",
    ]) {
      rmSync(stateDir(), { recursive: true, force: true });
      store = new FlakyStore();
      await login(open(), ALICE);
      selectModel("acme/general");
      const aliceSecrets = secretsOf(ALICE);
      const [aliceCredential] = credentialOf(ALICE);
      const crashing = open({
        onPhase: (reached: string) => {
          if (reached === phase) throw new Error(`simulated crash ${phase}`);
        },
      });
      await expect(login(crashing, BOB)).rejects.toThrow(
        `simulated crash ${phase}`,
      );
      // Whoever the stored identity is, no launch pairs Bob with Alice's
      // credential. (A crash before Bob's identity is stored leaves Alice
      // signed in, and her launch may use her own credential.)
      const requests = services.state.requests.length;
      const onDisk = open().readIdentityMetadata()?.subject;
      // The broker's entitlement follows the person the fixture serves.
      if (onDisk === ALICE.subject) as(ALICE);
      const launched = await open()
        .activate()
        .catch((error: unknown) => error);
      if (onDisk === BOB.subject)
        expect(launched, phase).toMatchObject({
          identity: { subject: BOB.subject },
        });
      if (onDisk === undefined)
        expect(launched, phase).toMatchObject({ code: "IDENTITY_REQUIRED" });
      if (onDisk !== ALICE.subject)
        expect(gatewayKeysSince(requests), phase).not.toContain(
          aliceCredential?.secret,
        );
      else
        expect(launched, phase).toMatchObject({
          identity: { subject: ALICE.subject },
        });
      // Bob signs in again: nothing of Alice's is left, her model
      // selection included.
      await login(open(), BOB);
      const bob = await open().activate();
      expect(bob.identity?.subject, phase).toBe(BOB.subject);
      expect(bob.config.allowedModels).toEqual(BOB.models);
      expect(
        readPreferences(preferencesFile()).values.model,
        phase,
      ).toBeUndefined();
      expect(await residue(store, aliceSecrets), phase).toEqual([]);
    }
  });
});

describe("sign-out and unusable identity state (fixtures)", () => {
  it("a failed identity deletion at logout leaves no usable session, and the next command finishes it once the store works", async () => {
    const store = new FlakyStore();
    const open = () => DistributionAccess.open(options(store));
    await login(open(), ALICE);
    const aliceSecrets = secretsOf(ALICE);
    store.failDeletes = /:identity#/;
    const problems = await open().logout();
    // The current generation and the next one (a crash may have left it).
    expect(problems).toEqual([
      expect.stringMatching(
        /^identity secret piship:acmecode:identity#1: .*the session is signed out and never used/,
      ),
      expect.stringMatching(/^identity secret piship:acmecode:identity#2: /),
    ]);
    for (const problem of problems)
      expect(problem).not.toContain("demo-at-not-a-real-one");
    const marker = JSON.parse(readFileSync(identityFile(), "utf8"));
    expect(marker).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: expect.arrayContaining(["piship:acmecode:identity#1"]),
    });
    for (const value of [ALICE.subject, ALICE.email, services.issuer])
      expect(JSON.stringify(marker)).not.toContain(value);
    // A launch does not work on it, and neither does a request.
    const requests = services.state.requests.length;
    await expect(open().activate()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    await expect(open().requestSecret()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    expect(services.state.requests.length).toBe(requests);
    expect((await open().status()).identity).toBeNull();
    // The store works again: the next command deletes the tokens and the
    // user is signed out.
    store.failDeletes = null;
    await expect(open().activate()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: "You are not signed in",
    });
    expect(existsSync(identityFile())).toBe(false);
    expect(store.refs()).toEqual([]);
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("an unreadable session of Alice whose tokens cannot be deleted fails closed, stays tracked, and is cleared before Bob signs in", async () => {
    const store = new FlakyStore();
    const open = () => DistributionAccess.open(options(store));
    await login(open(), ALICE);
    const aliceSecrets = secretsOf(ALICE);
    // An incompatible (say, newer) version of Alice's session metadata.
    const metadata = JSON.parse(readFileSync(identityFile(), "utf8"));
    writeFileSync(
      identityFile(),
      JSON.stringify({ ...metadata, schema: "piship-identity-metadata/v9" }),
    );
    store.failDeletes = /:identity#/;
    await expect(open().activate()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    expect(JSON.parse(readFileSync(identityFile(), "utf8"))).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: expect.arrayContaining(["piship:acmecode:identity#1"]),
    });
    // Bob cannot sign in over it while the store fails...
    await expect(login(open(), BOB)).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    // ...and once it works, Alice's token bundle is deleted first.
    store.failDeletes = null;
    await login(open(), BOB);
    expect(open().readIdentityMetadata()?.subject).toBe(BOB.subject);
    expect(await residue(store, aliceSecrets)).toEqual([]);
  });

  it("keeps a replaced identity token bundle that cannot be deleted tracked, reports it, and deletes it at logout", async () => {
    const store = new FlakyStore();
    const open = () => DistributionAccess.open(options(store));
    services.knobs.accessTokenTtl = 30;
    await login(open(), ALICE);
    store.failDeletes = /:identity#1$/;
    services.knobs.accessTokenTtl = 3600;
    const activated = await open().activate();
    expect(activated.notices).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          "A replaced identity token bundle could not be deleted from the secret store (piship:acmecode:identity#1",
        ),
      ]),
    );
    const metadata = JSON.parse(readFileSync(identityFile(), "utf8"));
    expect(metadata).toMatchObject({
      secretRef: "piship:acmecode:identity#2",
      orphans: ["piship:acmecode:identity#1"],
    });
    store.failDeletes = null;
    expect(await open().logout()).toEqual([]);
    expect(store.refs()).toEqual([]);
  });

  it("clears Alice's model selection when Bob signs in on state she left under a release without a principal binding", async () => {
    const store = new MemorySecretStore();
    const open = () => DistributionAccess.open(options(store));
    await login(open(), ALICE);
    selectModel("acme/general");
    // Alice signs out under v0.6, which kept no principal binding.
    expect(await open().logout()).toEqual([]);
    rmSync(join(stateDir(), "identity", "principal.json"));
    events.length = 0;
    await login(open(), BOB);
    expect(readPreferences(preferencesFile()).values.model).toBeUndefined();
    expect(open().readPrincipalBinding()).toMatchObject({
      subject: BOB.subject,
    });
    expect((await open().activate()).selectedModel).toBe("acme/coder");
    // Nobody is known to have been replaced, so no principal change is
    // reported, but the selection of an unknown user is not kept.
    expect(
      events.find((event) => event.event === "identity.login")?.detail,
    ).not.toHaveProperty("principalChange");
  });

  it("keeps the model selection of a user still signed in when an older release left no principal binding", async () => {
    const store = new MemorySecretStore();
    const open = () => DistributionAccess.open(options(store));
    await login(open(), ALICE);
    selectModel("acme/general");
    rmSync(join(stateDir(), "identity", "principal.json"));
    expect((await open().activate()).selectedModel).toBe("acme/general");
    expect(open().readPrincipalBinding()).toMatchObject({
      subject: ALICE.subject,
    });
  });

  it("status never shows another principal's credential as usable", async () => {
    const store = new MemorySecretStore();
    const open = () => DistributionAccess.open(options(store));
    await login(open(), ALICE);
    const aliceMetadata = readFileSync(credentialFile(), "utf8");
    const [aliceCredential] = credentialOf(ALICE);
    await login(open(), BOB);
    expect((await open().status()).credential.state).toBe("valid");
    // Alice's metadata put back under Bob's identity.
    writeFileSync(credentialFile(), aliceMetadata);
    const status = await open().status();
    expect(status.identity?.subject).toBe(BOB.subject);
    expect(status.credential).toMatchObject({
      state: "absent",
      metadata: null,
      notice: expect.stringContaining("not issued to the signed-in identity"),
    });
    expect(status.refs).toBeNull();
    expect(JSON.stringify(status)).not.toContain(aliceCredential?.id);
  });
});
