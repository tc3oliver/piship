// The stored sandbox credential: persistence, validation, the origin rule,
// principal binding and the no-residue rule across user switches, logout,
// purge, update and rollback, and what may never contain the secret.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PiShipError,
  type PrincipalKey,
  type SecretStore,
  SecretValue,
} from "@piship/contracts";
import {
  type CredentialEvent,
  MemorySecretStore,
  metadataSecretRefs,
  SANDBOX_CREDENTIAL_METADATA_SCHEMA,
} from "@piship/credentials";
import {
  type AccessManifest,
  type Manifest,
  readManifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  type AccessEvent,
  type AccessPhase,
  DistributionAccess,
  SandboxCredential,
  type SandboxCredentialOptions,
} from "./access/index.js";
import { purgeDistributionState } from "./install/purge.js";
import { checkStateMigration, STATE_SCHEMAS } from "./migration.js";
import { clearCredentials, snapshotState } from "./update/state.js";

const demo = readManifest(
  fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;
const ID = demo.app.id;

// Obvious fakes: never a real key or token.
const SECRET = "fake-sandbox-key-SENTINEL-0001";
const SECRET_2 = "fake-sandbox-key-SENTINEL-0002";
const ENDPOINT = "https://sandbox-api.test.invalid:8443/v1";
const ROUTER = "https://sandbox-router.test.invalid/";
const ALICE_KEY: PrincipalKey = {
  issuer: "https://idp.test.invalid",
  subject: "alice-0001",
};
const BOB_KEY: PrincipalKey = {
  issuer: "https://idp.test.invalid",
  subject: "bob-0002",
};

/** Wraps a store so tests can count reads and make deletions fail. */
class SpyStore implements SecretStore {
  readonly kind = "memory";
  readonly description = "test store";
  failDeletes: RegExp | null = null;
  /** Called before each deletion, to observe the state around it. */
  onDelete: ((ref: string) => void) | null = null;
  readonly gets: string[] = [];
  constructor(readonly inner = new MemorySecretStore()) {}
  put(ref: string, value: SecretValue) {
    return this.inner.put(ref, value);
  }
  /** Reads of a secret that is there; a deletion's confirmation reads nothing. */
  async get(ref: string) {
    const value = await this.inner.get(ref);
    if (value) this.gets.push(ref);
    return value;
  }
  async delete(ref: string) {
    this.onDelete?.(ref);
    if (this.failDeletes?.test(ref)) throw new Error("the keyring is locked");
    return this.inner.delete(ref);
  }
  refs() {
    return this.inner.refs();
  }
  sandboxRefs() {
    return this.refs().filter((ref) => ref.includes(":sandbox#"));
  }
}

let temp: string;
let store: SpyStore;
let events: CredentialEvent[];
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-sandbox-credential-"));
  store = new SpyStore();
  events = [];
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

const stateDir = () => join(temp, "state");
const metadataFile = () =>
  join(stateDir(), "credentials-metadata", "sandbox.json");
const readMetadata = () =>
  JSON.parse(readFileSync(metadataFile(), "utf8")) as Record<string, unknown>;

function slot(
  principal: PrincipalKey | null,
  extra: Partial<SandboxCredentialOptions> = {},
): SandboxCredential {
  return new SandboxCredential({
    distributionId: ID,
    command: demo.app.command,
    stateDir: stateDir(),
    provider: "e2b-compatible",
    secretStore: store,
    principal,
    targets: [ENDPOINT],
    onEvent: (event) => events.push(event),
    ...extra,
  });
}

const enter = (value: string) => async () => value;

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    return error instanceof PiShipError ? error.code : String(error);
  }
  return "resolved";
}

/** Every file under `directory` whose text contains one of `values`. */
function scan(directory: string, values: readonly string[]): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    if (!existsSync(path)) return;
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) visit(child);
      else {
        const text = readFileSync(child, "latin1");
        for (const value of values)
          if (text.includes(value)) hits.push(`${child}: ${value}`);
      }
    }
  };
  visit(directory);
  return hits;
}

describe("sandbox login: persistence and validation", () => {
  it("stores the secret under piship:<id>:sandbox#1 with metadata that never holds it", async () => {
    const saved = await slot(ALICE_KEY, {
      targets: [ENDPOINT, ROUTER],
      provider: "kubernetes-agent-sandbox",
    }).save(enter(SECRET));
    expect(saved).toEqual({ kind: "bearer", store: "memory (test store)" });
    expect(store.sandboxRefs()).toEqual([`piship:${ID}:sandbox#1`]);
    expect((await store.inner.get(`piship:${ID}:sandbox#1`))?.reveal()).toBe(
      SECRET,
    );
    const metadata = readMetadata();
    expect(metadata).toMatchObject({
      schema: SANDBOX_CREDENTIAL_METADATA_SCHEMA,
      source: "stored",
      kind: "bearer",
      credential_ref: `piship:${ID}:sandbox#1`,
      generation: 1,
      principal: ALICE_KEY,
      origins: [
        "https://sandbox-api.test.invalid:8443",
        "https://sandbox-router.test.invalid",
      ],
    });
    expect(typeof metadata.acquired_at).toBe("string");
    expect(readFileSync(metadataFile(), "utf8")).not.toContain(SECRET);
    if (process.platform !== "win32") {
      expect(statSync(metadataFile()).mode & 0o777).toBe(0o600);
      expect(
        statSync(join(stateDir(), "credentials-metadata")).mode & 0o777,
      ).toBe(0o700);
    }
    const firstId = metadata.credential_id;
    expect(firstId).toMatch(/^[0-9a-f-]{36}$/);
    // A new login replaces it: the old one is deleted, confirmed, first.
    await slot(ALICE_KEY).save(enter(SECRET_2));
    expect(store.sandboxRefs()).toEqual([`piship:${ID}:sandbox#1`]);
    expect((await store.inner.get(`piship:${ID}:sandbox#1`))?.reveal()).toBe(
      SECRET_2,
    );
    expect(readMetadata()).toMatchObject({
      generation: 1,
      kind: "api_key",
      origins: ["https://sandbox-api.test.invalid:8443"],
    });
    expect(readMetadata().credential_id).not.toBe(firstId);
  });

  it.each([
    ["too short", "short12"],
    ["a space", "fake key with spaces"],
    ["a CR", "fake-key\r-0001"],
    ["a LF", "fake-key\n-0001"],
    ["a NUL", "fake-key\u0000-0001"],
    ["a non-ASCII character", "fake-key-é-0001"],
    ["more than 4096 characters", "x".repeat(4097)],
    ["nothing", ""],
  ])("rejects a secret with %s and stores nothing", async (_name, value) => {
    await slot(ALICE_KEY).save(enter(SECRET));
    await expect(slot(ALICE_KEY).save(enter(value))).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
    });
    // The previous credential is untouched.
    expect(store.sandboxRefs()).toEqual([`piship:${ID}:sandbox#1`]);
    expect(readMetadata().generation).toBe(1);
  });

  it("accepts exactly 4096 characters and trims surrounding whitespace", async () => {
    await slot(null).save(enter(` ${"k".repeat(4096)}\n`));
    const value = await store.inner.get(`piship:${ID}:sandbox#1`);
    expect(value?.reveal()).toBe("k".repeat(4096));
  });

  it("refuses to store without an http(s) endpoint to bind it to", async () => {
    for (const targets of [[], ["file:///tmp/x"], ["not a url"]])
      await expect(
        slot(ALICE_KEY, { targets }).save(enter(SECRET)),
      ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(existsSync(metadataFile())).toBe(false);
    expect(store.sandboxRefs()).toEqual([]);
  });
});

describe("sandbox credential: origin rule", () => {
  it("refuses another origin before the secret is read", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    store.gets.length = 0;
    for (const other of [
      "https://attacker.test.invalid:8443/v1",
      "http://sandbox-api.test.invalid:8443/v1",
      "https://sandbox-api.test.invalid/v1",
    ]) {
      const error = await slot(ALICE_KEY, { targets: [other] })
        .access()
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
      expect(String((error as Error).message)).not.toContain("attacker");
    }
    expect(store.gets).toEqual([]);
    // The same origin with another path is the same origin.
    const allowed = await slot(ALICE_KEY, {
      targets: ["https://sandbox-api.test.invalid:8443/other"],
    }).access();
    expect((await allowed.secret()).reveal()).toBe(SECRET);
    expect(allowed.origins).toEqual(["https://sandbox-api.test.invalid:8443"]);
  });

  it("refuses a Kubernetes router it was not stored for", async () => {
    await slot(ALICE_KEY, { provider: "kubernetes-agent-sandbox" }).save(
      enter(SECRET),
    );
    store.gets.length = 0;
    await expect(
      slot(ALICE_KEY, { targets: [ENDPOINT, ROUTER] }).access(),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(store.gets).toEqual([]);
  });
});

describe("sandbox credential: use", () => {
  it("serves the secret per request and follows a new login of the same principal", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    const active = await slot(ALICE_KEY).access();
    expect(active).toMatchObject({ source: "stored", kind: "api_key" });
    const first = await active.secret();
    expect(first).toBeInstanceOf(SecretValue);
    expect(first.reveal()).toBe(SECRET);
    await slot(ALICE_KEY).save(enter(SECRET_2));
    expect((await active.secret()).reveal()).toBe(SECRET_2);
  });

  it("stops a running session, deleting nothing, when another principal's credential appears", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    const active = await slot(ALICE_KEY).access();
    await slot(BOB_KEY).save(enter(SECRET_2));
    await expect(active.secret()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    // Bob's credential is his, and stays.
    expect(readMetadata().principal).toEqual(BOB_KEY);
    expect(store.sandboxRefs()).toEqual([`piship:${ID}:sandbox#1`]);
  });

  it("records a rejection: status shows it and the next launch asks for sandbox login", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    const active = await slot(ALICE_KEY).access();
    await active.secret();
    await active.rejected();
    expect(typeof readMetadata().rejected_at).toBe("string");
    expect(slot(ALICE_KEY).status()).toMatchObject({
      state: "rejected",
      kind: "api_key",
      boundToPrincipal: true,
      originMatches: true,
    });
    await expect(active.secret()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    const error = await slot(ALICE_KEY)
      .access()
      .catch((caught: PiShipError) => caught);
    expect(error).toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect((error as PiShipError).userAction).toMatch(/sandbox login/);
    // A new login clears the rejection.
    await slot(ALICE_KEY).save(enter(SECRET_2));
    expect(slot(ALICE_KEY).status().state).toBe("valid");
  });

  it("reports status without the value, the reference, or the origins", async () => {
    expect(slot(ALICE_KEY).status()).toEqual({
      state: "absent",
      source: "stored",
      store: "memory (test store)",
    });
    await slot(ALICE_KEY).save(enter(SECRET));
    const statuses = [
      slot(ALICE_KEY).status(),
      slot(BOB_KEY).status(),
      slot(ALICE_KEY, { targets: ["https://elsewhere.test.invalid"] }).status(),
    ];
    expect(statuses.map((status) => status.state)).toEqual([
      "valid",
      "principal-mismatch",
      "origin-mismatch",
    ]);
    const text = JSON.stringify(statuses);
    for (const value of [SECRET, "sandbox#", "sandbox-api.test.invalid"])
      expect(text).not.toContain(value);
    // Status never deletes.
    expect(store.sandboxRefs()).toHaveLength(1);
  });

  it("refuses a missing secret and clears its metadata", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    await store.inner.delete(`piship:${ID}:sandbox#1`);
    await expect(slot(ALICE_KEY).access()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    expect(existsSync(metadataFile())).toBe(false);
    await expect(slot(ALICE_KEY).access()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
  });
});

describe("sandbox credential: principal binding", () => {
  it("deletes another principal's credential at use and never serves it", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    store.gets.length = 0;
    const error = await slot(BOB_KEY)
      .access()
      .catch((caught: PiShipError) => caught);
    expect(error).toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect((error as PiShipError).message).toMatch(/another user/);
    expect(store.gets).toEqual([]);
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
    expect(events.at(-1)).toMatchObject({
      event: "credential.revoke",
      detail: { purpose: "sandbox", reason: "principal-change" },
    });
  });

  it("fails closed when another principal's credential cannot be deleted", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    store.failDeletes = /sandbox#/;
    await expect(slot(BOB_KEY).access()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    // A discarded marker keeps the reference tracked; nobody can use it.
    expect(readMetadata().schema).toBe("piship-credential-discarded/v1");
    for (const principal of [ALICE_KEY, BOB_KEY])
      expect(await code(slot(principal).access())).toBe(
        "SECRET_STORE_UNAVAILABLE",
      );
    store.failDeletes = null;
    expect(await code(slot(ALICE_KEY).access())).toBe("SANDBOX_UNAVAILABLE");
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
  });

  it("works without identity, and discards a null-bound credential once an identity is configured", async () => {
    await slot(null).save(enter(SECRET));
    expect(readMetadata()).not.toHaveProperty("principal");
    expect((await (await slot(null).access()).secret()).reveal()).toBe(SECRET);
    await expect(slot(ALICE_KEY).access()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    expect(store.sandboxRefs()).toEqual([]);
    expect(events.at(-1)?.detail).toMatchObject({ reason: "unbound" });
    // And the other way round: a principal's credential is not anonymous.
    await slot(ALICE_KEY).save(enter(SECRET));
    await expect(slot(null).access()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    expect(store.sandboxRefs()).toEqual([]);
  });
});

describe("sandbox credential: every deletion path", () => {
  /** Metadata with an orphan, and a pending next generation in the store. */
  async function withResidue(principal: PrincipalKey | null) {
    await slot(principal).save(enter(SECRET));
    // A crash after a secret was written that never reached metadata.
    await store.inner.put(
      `piship:${ID}:sandbox#2`,
      new SecretValue("fake-pending-SENTINEL-3"),
    );
    // An orphan whose deletion failed earlier.
    await store.inner.put(
      `piship:${ID}:sandbox#7`,
      new SecretValue("fake-orphan-SENTINEL-1"),
    );
    writeFileSync(
      metadataFile(),
      JSON.stringify({
        ...readMetadata(),
        orphans: [`piship:${ID}:sandbox#7`],
      }),
    );
    expect(store.sandboxRefs()).toHaveLength(3);
  }

  it("metadataSecretRefs names every sandbox generation and never a runtime one", () => {
    const refs = metadataSecretRefs(
      {
        schema: SANDBOX_CREDENTIAL_METADATA_SCHEMA,
        credential_ref: `piship:${ID}:sandbox#2`,
        generation: 2,
        orphans: [`piship:${ID}:sandbox#1`, `piship:other:sandbox#1`],
      },
      ID,
    );
    expect(refs).toEqual([
      `piship:${ID}:sandbox#1`,
      `piship:${ID}:sandbox#2`,
      `piship:${ID}:sandbox#3`,
    ]);
  });

  it("sandbox logout deletes the secret, orphans, and the pending generation", async () => {
    await withResidue(ALICE_KEY);
    expect(await slot(null).clear()).toEqual([]);
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
    expect(events.at(-1)).toMatchObject({
      event: "credential.revoke",
      detail: {
        purpose: "sandbox",
        source: "stored",
        reason: "logout",
        revocation: "unsupported",
      },
    });
  });

  it("purge finds the sandbox references", async () => {
    const home = join(temp, "home");
    const saved = {
      state: process.env.PISHIP_STATE_HOME,
      install: process.env.PISHIP_INSTALL_HOME,
    };
    process.env.PISHIP_STATE_HOME = home;
    process.env.PISHIP_INSTALL_HOME = join(temp, "install");
    try {
      const state = join(home, ID);
      mkdirSync(state, { recursive: true });
      const inState = new SandboxCredential({
        distributionId: ID,
        command: demo.app.command,
        stateDir: state,
        provider: "e2b-compatible",
        secretStore: store,
        principal: ALICE_KEY,
        targets: [ENDPOINT],
      });
      await inState.save(enter(SECRET));
      await store.inner.put(
        `piship:${ID}:sandbox#2`,
        new SecretValue("fake-pending-SENTINEL-2"),
      );
      const result = await purgeDistributionState(ID, { secretStore: store });
      expect(result.deletedSecrets).toEqual([
        `piship:${ID}:sandbox#1`,
        `piship:${ID}:sandbox#2`,
      ]);
      expect(store.sandboxRefs()).toEqual([]);
      expect(existsSync(state)).toBe(false);
    } finally {
      for (const [key, value] of [
        ["PISHIP_STATE_HOME", saved.state],
        ["PISHIP_INSTALL_HOME", saved.install],
      ] as const)
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
    }
  });

  it("update and rollback to a release without the schema key clear it, and no snapshot holds it", async () => {
    await withResidue(ALICE_KEY);
    // A lock written before the key existed.
    const { sandboxCredential: _absent, ...older } = STATE_SCHEMAS;
    const report = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "0.87.1", schemas: older },
      { version: "1.1.0", pi: "0.87.1" },
    );
    expect(
      report.items.find((item) => item.name === "sandbox credential metadata"),
    ).toMatchObject({ action: "clear-and-reacquire", verdict: "safe" });
    const snapshot = snapshotState(stateDir(), "1.1.0", "1.0.0", new Date());
    const notices = await clearCredentials(stateDir(), ID, report, {
      secretStore: store,
    });
    expect(notices.join("\n")).toMatch(/sandbox credential metadata/);
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
    // The snapshot lists it as excluded and holds no copy.
    const manifest = JSON.parse(
      readFileSync(join(snapshot as string, "snapshot.json"), "utf8"),
    ) as { excluded: string[]; files: string[] };
    expect(manifest.excluded).toContain("credentials-metadata/sandbox.json");
    expect(manifest.files).not.toContain("credentials-metadata/sandbox.json");
    // A→B→A: nothing anywhere can bring Alice's secret back.
    expect(
      scan(stateDir(), [
        SECRET,
        SECRET_2,
        "fake-orphan-SENTINEL-1",
        "fake-pending-SENTINEL-3",
        "sandbox#",
      ]),
    ).toEqual([]);
    expect(await code(slot(ALICE_KEY).access())).toBe("SANDBOX_UNAVAILABLE");
  });

  it("a switch that cannot delete a sandbox secret stops before activation", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    const { sandboxCredential: _absent, ...older } = STATE_SCHEMAS;
    const report = checkStateMigration(
      stateDir(),
      { version: "1.0.0", pi: "0.87.1", schemas: older },
      { version: "1.1.0", pi: "0.87.1" },
    );
    store.failDeletes = /sandbox#/;
    await expect(
      clearCredentials(stateDir(), ID, report, { secretStore: store }),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(existsSync(metadataFile())).toBe(true);
  });
});

describe("sandbox credential: events and leakage", () => {
  it("audits acquire and revoke with purpose sandbox, never the secret, origin, or endpoint", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    await slot(ALICE_KEY).save(enter(SECRET_2));
    await slot(null).clear();
    expect(events.map((event) => event.event)).toEqual([
      "credential.acquire",
      "credential.revoke",
      "credential.acquire",
      "credential.revoke",
    ]);
    expect(events[0]?.detail).toEqual({
      purpose: "sandbox",
      source: "stored",
      kind: "api_key",
      generation: 1,
      // Random, per stored secret; never derived from it.
      credentialId: expect.stringMatching(/^[0-9a-f-]{36}$/),
      expiresAt: null,
    });
    expect(events[1]?.detail).toMatchObject({
      purpose: "sandbox",
      reason: "replace",
      generation: 1,
    });
    const text = JSON.stringify(events);
    for (const value of [SECRET, SECRET_2, "test.invalid", "8443", "sandbox#"])
      expect(text).not.toContain(value);
  });

  it("scrubs a revealed secret from later errors, such as a 401 body that echoes it", async () => {
    await slot(ALICE_KEY).save(enter(SECRET));
    const active = await slot(ALICE_KEY).access();
    await active.secret();
    const error = new PiShipError(
      "SANDBOX_UNAVAILABLE",
      `creating the sandbox failed: HTTP 401: {"message":"invalid key ${SECRET}"}`,
    );
    expect(error.message).not.toContain(SECRET);
    expect(JSON.stringify(error)).not.toContain(SECRET);
  });
});

// ------------------------------------------------ user switching (fixtures)

type Services = Awaited<ReturnType<typeof startLocalServices>>;

describe("sandbox credential across user switches (fixtures)", () => {
  let services: Services;
  let accessEvents: AccessEvent[];
  beforeEach(async () => {
    services = await startLocalServices();
    accessEvents = [];
  });
  afterEach(async () => {
    await services.close();
  });

  const options = (
    extra: Partial<Parameters<typeof DistributionAccess.open>[0]> = {},
  ): Parameters<typeof DistributionAccess.open>[0] => ({
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
    } as AccessManifest,
    stateDir: stateDir(),
    distributionDir: temp,
    env: services.env(),
    secretStore: store,
    onEvent: (event) => accessEvents.push(event),
    ...extra,
  });

  async function login(
    subject: string,
    extra: Partial<Parameters<typeof DistributionAccess.open>[0]> = {},
  ) {
    services.knobs.subject = subject;
    services.knobs.entitledModels = ["acme/coder"];
    const distribution = DistributionAccess.open(options(extra));
    await distribution.login({
      openUrl: (url) => void services.approve(url),
    });
    return distribution;
  }

  const identitySubject = () =>
    (
      JSON.parse(
        readFileSync(join(stateDir(), "identity", "session.json"), "utf8"),
      ) as { subject: string }
    ).subject;

  it("login as another principal deletes the sandbox credential before the new identity is stored", async () => {
    const alice = await login("alice-0001");
    const aliceKey = alice.readIdentityMetadata();
    expect(aliceKey?.subject).toBe("alice-0001");
    await slot({ issuer: aliceKey?.issuer ?? "", subject: "alice-0001" }).save(
      enter(SECRET),
    );
    expect(store.sandboxRefs()).toHaveLength(1);
    const seen: string[] = [];
    await login("bob-0002", {
      onPhase: (phase: AccessPhase) => {
        if (phase === "sandbox-credential-cleared")
          seen.push(
            `${store.sandboxRefs().length} ${existsSync(metadataFile())} ${identitySubject()}`,
          );
      },
    });
    // At that point Alice's sandbox credential was gone and Alice was
    // still the stored identity.
    expect(seen).toEqual(["0 false alice-0001"]);
    expect(identitySubject()).toBe("bob-0002");
    expect(
      accessEvents.some(
        (event) =>
          event.event === "credential.revoke" &&
          event.detail.purpose === "sandbox" &&
          event.detail.reason === "principal-change",
      ),
    ).toBe(true);
  });

  it("a crash between the two steps leaves no usable sandbox credential of the previous user", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    await slot({ issuer, subject: "alice-0001" }).save(enter(SECRET));
    await expect(
      login("bob-0002", {
        onPhase: (phase: AccessPhase) => {
          if (phase === "sandbox-credential-cleared") throw new Error("crash");
        },
      }),
    ).rejects.toThrow("crash");
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
    // A crash before the step: Bob is not stored, and Alice's credential
    // is never served to Bob; his launch deletes it.
    await login("alice-0001");
    await slot({ issuer, subject: "alice-0001" }).save(enter(SECRET));
    await expect(
      login("bob-0002", {
        onPhase: (phase: AccessPhase) => {
          if (phase === "credential-cleared") throw new Error("crash");
        },
      }),
    ).rejects.toThrow("crash");
    expect(identitySubject()).toBe("alice-0001");
    await expect(
      slot({ issuer, subject: "bob-0002" }).access(),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(store.sandboxRefs()).toEqual([]);
  });

  it("a failed deletion fails the login before the new identity is stored", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    await slot({ issuer, subject: "alice-0001" }).save(enter(SECRET));
    store.failDeletes = /sandbox#/;
    await expect(login("bob-0002")).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    expect(identitySubject()).toBe("alice-0001");
    // Tracked by a discarded marker, usable by nobody.
    expect(readMetadata().schema).toBe("piship-credential-discarded/v1");
    expect(await code(slot({ issuer, subject: "alice-0001" }).access())).toBe(
      "SECRET_STORE_UNAVAILABLE",
    );
    store.failDeletes = null;
    await login("bob-0002");
    expect(identitySubject()).toBe("bob-0002");
    expect(store.sandboxRefs()).toEqual([]);
  });

  it("a login of the same principal keeps the sandbox credential; logout deletes it", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    await slot({ issuer, subject: "alice-0001" }).save(enter(SECRET));
    const again = await login("alice-0001");
    expect(store.sandboxRefs()).toHaveLength(1);
    expect(await again.logout()).toEqual([]);
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
    // After the identity is signed out.
    expect(accessEvents.at(-1)).toMatchObject({
      event: "credential.revoke",
      detail: { purpose: "sandbox", reason: "logout" },
    });
  });

  it("a session of a user who is no longer signed in deletes nothing of the new user's", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    const aliceKey = { issuer, subject: "alice-0001" };
    const bob = await login("bob-0002");
    const bobKey = { issuer, subject: "bob-0002" };
    await slot(bobKey, { signedIn: await bob.signedInGuard(bobKey) }).save(
      enter(SECRET_2),
    );
    // Alice's process still runs: her launch builds a sandbox backend now.
    const stale = slot(aliceKey, {
      signedIn: await alice.signedInGuard(aliceKey),
    });
    expect(await code(stale.access())).toBe("IDENTITY_REQUIRED");
    expect(readMetadata().principal).toEqual(bobKey);
    expect(store.sandboxRefs()).toEqual([`piship:${ID}:sandbox#1`]);
    // Bob's own launch uses it.
    const active = await slot(bobKey, {
      signedIn: await bob.signedInGuard(bobKey),
    }).access();
    expect((await active.secret()).reveal()).toBe(SECRET_2);
  });

  it("sandbox login stores nothing for a user who signed out while it waited for the secret", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    const aliceKey = { issuer, subject: "alice-0001" };
    const entering = slot(aliceKey, {
      signedIn: await alice.signedInGuard(aliceKey),
    });
    await alice.logout();
    expect(await code(entering.save(enter(SECRET)))).toBe("IDENTITY_REQUIRED");
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
    // Nor after another user signed in meanwhile.
    const again = await login("alice-0001");
    const waiting = slot(aliceKey, {
      signedIn: await again.signedInGuard(aliceKey),
    });
    await login("bob-0002");
    expect(await code(waiting.save(enter(SECRET)))).toBe("IDENTITY_REQUIRED");
    expect(store.sandboxRefs()).toEqual([]);
  });

  it("a sandbox login of the previous user that lands during another user's login is cleared once that identity is stored", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    const aliceKey = { issuer, subject: "alice-0001" };
    const pending = slot(aliceKey, {
      signedIn: await alice.signedInGuard(aliceKey),
    });
    // Between Bob's clear of the sandbox credential and his identity write,
    // Alice's `sandbox login` finishes: she is still the stored user.
    await login("bob-0002", {
      onPhase: async (phase: AccessPhase) => {
        if (phase === "sandbox-credential-cleared")
          await pending.save(enter(SECRET));
      },
    });
    expect(identitySubject()).toBe("bob-0002");
    expect(store.sandboxRefs()).toEqual([]);
    expect(existsSync(metadataFile())).toBe(false);
  });

  it("logout deletes the sandbox credential after the identity, so a login that checked first is cleared too", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    await slot({ issuer, subject: "alice-0001" }).save(enter(SECRET));
    const identityFile = join(stateDir(), "identity", "session.json");
    const identityWhenDeleted: boolean[] = [];
    store.onDelete = (ref) => {
      if (ref.includes(":sandbox#"))
        identityWhenDeleted.push(existsSync(identityFile));
    };
    expect(await alice.logout()).toEqual([]);
    // Every generation it may hold is deleted, and none while the identity
    // is still stored.
    expect(identityWhenDeleted.length).toBeGreaterThan(0);
    expect(identityWhenDeleted).not.toContain(true);
    expect(store.sandboxRefs()).toEqual([]);
  });

  it("logout reports a sandbox secret it cannot delete and keeps it tracked", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    await slot({ issuer, subject: "alice-0001" }).save(enter(SECRET));
    store.failDeletes = /sandbox#/;
    const problems = await alice.logout();
    expect(problems.join("\n")).toMatch(/^sandbox credential: delete/m);
    expect(readMetadata().schema).toBe("piship-credential-discarded/v1");
  });

  it("puts Alice's metadata back under Bob: it is discarded, not used", async () => {
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    await slot({ issuer, subject: "alice-0001" }).save(enter(SECRET));
    const planted = readFileSync(metadataFile(), "utf8");
    await login("bob-0002");
    // Her metadata and secret put back behind Bob's session.
    mkdirSync(join(stateDir(), "credentials-metadata"), { recursive: true });
    writeFileSync(metadataFile(), planted);
    await store.inner.put(`piship:${ID}:sandbox#1`, new SecretValue(SECRET));
    store.gets.length = 0;
    await expect(
      slot({ issuer, subject: "bob-0002" }).access(),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(store.gets).toEqual([]);
    expect(store.sandboxRefs()).toEqual([]);
  });

  it("leaves no sandbox secret anywhere in the state directory", async () => {
    const spy = vi.fn();
    const alice = await login("alice-0001");
    const issuer = alice.readIdentityMetadata()?.issuer ?? "";
    await slot({ issuer, subject: "alice-0001" }, { onEvent: spy }).save(
      enter(SECRET),
    );
    snapshotState(stateDir(), "1.0.0", "1.1.0", new Date());
    await (await slot({ issuer, subject: "alice-0001" }).access()).secret();
    await login("bob-0002");
    await alice.logout();
    expect(scan(stateDir(), [SECRET])).toEqual([]);
    expect(JSON.stringify(accessEvents)).not.toContain(SECRET);
    expect(JSON.stringify(spy.mock.calls)).not.toContain(SECRET);
  });
});
