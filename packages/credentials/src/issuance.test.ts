// Durable idempotency of credential issuance: the key of an acquire or
// renewal is recorded before it is sent and reused until the request is
// resolved, across a lost answer, a failed attempt, and a process restart.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import {
  type CredentialProvider,
  type IdentitySession,
  type PiShipError,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CREDENTIAL_ISSUANCE_SCHEMA,
  type CredentialEvent,
  CredentialManager,
  createSecretStore,
  HttpBrokerCredentialProvider,
  ISSUANCE_RETENTION_MS,
  MemorySecretStore,
} from "./index.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-issuance-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

const ctx = { distributionId: "acmecode" };
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ISSUER = "https://idp.example.test";
const ENDPOINT = "https://broker.example.test/v1/credential";
const targetOf = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const BROKER_TARGET = targetOf(`http-broker ${ENDPOINT}`);

function session(subject: string): IdentitySession {
  return {
    subject,
    issuer: ISSUER,
    accessToken: new SecretValue(`fake-identity-token-${subject}-0001`),
  };
}

/**
 * What the broker does with one request, in order. `drop-after-create`
 * issues (or replays) and then loses the answer (a connection reset);
 * `unavailable` answers 500 before anything is issued; `hang` never lets
 * the request reach the broker, so the client times out; `refused` fails
 * the connection before sending.
 */
type Step =
  | "ok"
  | "drop-after-create"
  | "unavailable"
  | "hang"
  | "refused"
  | "denied"
  | "conflict"
  | "malformed";

/**
 * A broker that honors Idempotency-Key per principal, as the contract
 * requires, and counts every credential it issued. `forget()` is a broker
 * restart that loses its idempotency records.
 */
class FakeBroker {
  readonly issued: string[] = [];
  /** The key of every request that reached the broker. */
  readonly keys: (string | null)[] = [];
  /** The pending issuance file's key at the moment each request was sent. */
  readonly recordedAtSend: (string | null)[] = [];
  readonly plan: Step[] = [];
  readonly #records = new Map<string, { secret: string; id: string }>();
  constructor(readonly issuancePath?: string) {}
  forget(): void {
    this.#records.clear();
  }
  readonly fetch = async (
    _url: string | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const step = this.plan.shift() ?? "ok";
    const headers = new Headers(init?.headers);
    const key = headers.get("idempotency-key");
    if (this.issuancePath)
      this.recordedAtSend.push(
        existsSync(this.issuancePath)
          ? JSON.parse(readFileSync(this.issuancePath, "utf8")).idempotency_key
          : null,
      );
    if (step === "refused")
      throw new TypeError("fetch failed", {
        cause: { code: "ECONNREFUSED" },
      });
    if (step === "hang")
      return new Promise((_resolve, reject) => {
        const signal = init?.signal;
        signal?.addEventListener("abort", () => reject(signal.reason));
      });
    this.keys.push(key);
    if (step === "unavailable")
      return new Response("{}", {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    if (step === "denied") return new Response("{}", { status: 403 });
    if (step === "conflict") return new Response("{}", { status: 422 });
    const token = headers.get("authorization") ?? "";
    const principal = token.replace(/^Bearer fake-identity-token-/, "");
    const record = `${principal}\n${key}`;
    let issued = key === null ? undefined : this.#records.get(record);
    if (!issued) {
      const n = this.issued.length + 1;
      issued = { secret: `sk-fake-broker-issued-${n}-value`, id: `vk_${n}` };
      this.issued.push(issued.secret);
      if (key !== null) this.#records.set(record, issued);
    }
    if (step === "drop-after-create")
      throw new TypeError("fetch failed", { cause: { code: "ECONNRESET" } });
    if (step === "malformed")
      return new Response("not json", {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    return Response.json({
      credential_type: "api_key",
      credential: issued.secret,
      credential_id: issued.id,
      expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    });
  };
}

const metadataPath = () => join(temp, "credentials-metadata", "inference.json");
const issuancePath = () =>
  join(temp, "credentials-metadata", "pending-issuance.json");
const pending = () =>
  existsSync(issuancePath())
    ? (JSON.parse(readFileSync(issuancePath(), "utf8")) as {
        idempotency_key: string;
        principal?: { issuer: string; subject: string };
        renews?: { credential_ref: string };
        created_at: string;
      })
    : null;

function brokerManager(
  broker: FakeBroker,
  extra: {
    store?: MemorySecretStore | ReturnType<typeof createSecretStore>;
    now?: () => number;
    timeoutMs?: number;
    events?: CredentialEvent[];
    onPhase?: (phase: string) => void;
    endpoint?: string;
  } = {},
): CredentialManager {
  return new CredentialManager({
    distributionId: "acmecode",
    provider: new HttpBrokerCredentialProvider({
      endpoint: extra.endpoint ?? ENDPOINT,
      fetch: broker.fetch,
      ...(extra.timeoutMs ? { timeoutMs: extra.timeoutMs } : {}),
    }),
    store: extra.store ?? new MemorySecretStore(),
    metadataPath: metadataPath(),
    beforeExpirySeconds: 300,
    ...(extra.now ? { now: extra.now } : {}),
    ...(extra.events ? { onEvent: (event) => extra.events?.push(event) } : {}),
    ...(extra.onPhase ? { onPhase: extra.onPhase } : {}),
  });
}

const failure = (promise: Promise<unknown>) =>
  promise.then(
    () => {
      throw new Error("expected a failure");
    },
    (error: unknown) => error as PiShipError,
  );

describe("durable credential issuance", () => {
  const alice = session("alice");
  const bob = session("bob");

  it("repeats the key of an acquire whose answer was lost, and commits the one credential the broker issued", async () => {
    const broker = new FakeBroker(issuancePath());
    broker.plan.push("drop-after-create");
    const credentials = brokerManager(broker);
    const error = await failure(
      credentials.ensure(alice, ctx, { allowAcquire: true }),
    );
    expect(error.sanitizedDetail).toMatchObject({
      reason: "unreachable",
      outcome: "unknown",
    });
    const key = String(error.sanitizedDetail?.idempotencyKey);
    expect(key).toMatch(UUID);
    // The key was on disk before the request left.
    expect(broker.recordedAtSend).toEqual([key]);
    expect(pending()?.idempotency_key).toBe(key);
    expect(credentials.pendingIssuance()).toMatchObject({
      idempotencyKey: key,
      renewal: false,
    });
    // A plain retry, with no key from the caller, repeats it.
    const active = await credentials.ensure(alice, ctx, {
      allowAcquire: true,
    });
    expect(broker.keys).toEqual([key, key]);
    expect(broker.issued).toHaveLength(1);
    expect(active.secret?.reveal()).toBe(broker.issued[0]);
    expect(active.ref?.credentialId).toBe("vk_1");
    // Committing the credential resolves the request.
    expect(pending()).toBeNull();
    expect(credentials.pendingIssuance()).toBeNull();
  });

  it("repeats the key after a restart between the broker issuing and the commit", async () => {
    const broker = new FakeBroker();
    const store = () =>
      createSecretStore({
        provider: "file",
        fileDirectory: join(temp, "secrets"),
      });
    // The broker issues and answers; the process stops after writing the
    // secret and before committing metadata, as a crash would.
    const first = brokerManager(broker, {
      store: store(),
      onPhase: (phase) => {
        if (phase === "secret-written") throw new Error("process killed");
      },
    });
    await expect(
      first.ensure(alice, ctx, { allowAcquire: true }),
    ).rejects.toThrow("process killed");
    const key = pending()?.idempotency_key;
    expect(key).toMatch(UUID);
    // A new process reads the state from disk and repeats the key.
    const second = brokerManager(broker, { store: store() });
    const active = await second.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys).toEqual([key, key]);
    expect(broker.issued).toHaveLength(1);
    expect(active.secret?.reveal()).toBe(broker.issued[0]);
    expect(pending()).toBeNull();
  });

  it("keeps one lost-answer issuance across backward and forward clock steps and restart", async () => {
    let now = Date.now();
    const broker = new FakeBroker(issuancePath());
    broker.plan.push("drop-after-create");
    const first = brokerManager(broker, { now: () => now });
    await failure(first.ensure(alice, ctx, { allowAcquire: true }));
    const key = pending()?.idempotency_key;
    expect(broker.issued).toHaveLength(1);
    now -= 2 * 60 * 60_000;
    broker.plan.push("drop-after-create");
    const restarted = brokerManager(broker, { now: () => now });
    await failure(restarted.ensure(alice, ctx, { allowAcquire: true }));
    expect(broker.keys).toEqual([key, key]);
    expect(broker.issued).toHaveLength(1);
    now += ISSUANCE_RETENTION_MS + 3 * 60 * 60_000;
    const error = await failure(
      brokerManager(broker, { now: () => now }).ensure(alice, ctx, {
        allowAcquire: true,
      }),
    );
    expect(error.message).toMatch(/reconcile/);
    expect(pending()?.idempotency_key).toBe(key);
    expect(broker.keys).toEqual([key, key]);
    expect(broker.issued).toHaveLength(1);
  });

  it("repeats the key after a 5xx before anything was issued", async () => {
    const broker = new FakeBroker();
    broker.plan.push("unavailable");
    const credentials = brokerManager(broker);
    const error = await failure(
      credentials.ensure(alice, ctx, { allowAcquire: true }),
    );
    expect(error).toMatchObject({
      retryable: true,
      sanitizedDetail: { reason: "unavailable", status: 500 },
    });
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys).toHaveLength(2);
    expect(broker.keys[1]).toBe(broker.keys[0]);
    expect(broker.issued).toHaveLength(1);
  });

  it.each([
    ["a timeout before the request reached the broker", "hang" as const],
    ["a connection refused before sending", "refused" as const],
  ])("repeats the key after %s", async (_name, step) => {
    const broker = new FakeBroker(issuancePath());
    broker.plan.push(step);
    const credentials = brokerManager(broker, { timeoutMs: 100 });
    const error = await failure(
      credentials.ensure(alice, ctx, { allowAcquire: true }),
    );
    const key = String(error.sanitizedDetail?.idempotencyKey);
    expect(broker.keys).toEqual([]);
    expect(broker.recordedAtSend).toEqual([key]);
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys).toEqual([key]);
    expect(broker.issued).toHaveLength(1);
  });

  it("converges concurrent callers on one key through the credential lock", async () => {
    const broker = new FakeBroker();
    broker.plan.push("drop-after-create");
    const store = new MemorySecretStore();
    // Two managers over the same files: two processes of one distribution.
    const one = brokerManager(broker, { store });
    const two = brokerManager(broker, { store });
    const results = await Promise.allSettled([
      one.ensure(alice, ctx, { allowAcquire: true }),
      two.ensure(alice, ctx, { allowAcquire: true }),
      one.ensure(alice, ctx, { allowAcquire: true }),
    ]);
    expect(results.map((result) => result.status)).toEqual([
      "rejected",
      "fulfilled",
      "fulfilled",
    ]);
    expect(broker.keys).toHaveLength(2);
    expect(broker.keys[1]).toBe(broker.keys[0]);
    expect(broker.issued).toHaveLength(1);
    const secrets = results.flatMap((result) =>
      result.status === "fulfilled" ? [result.value.secret?.reveal()] : [],
    );
    expect(secrets).toEqual([broker.issued[0], broker.issued[0]]);
  });

  it("gives a later, independent renewal a new key", async () => {
    const broker = new FakeBroker(issuancePath());
    const credentials = brokerManager(broker);
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    await credentials.ensure(alice, ctx, {
      allowAcquire: false,
      forceRefresh: true,
    });
    expect(broker.keys).toHaveLength(2);
    expect(broker.keys[1]).not.toBe(broker.keys[0]);
    expect(broker.issued).toHaveLength(2);
    // A renewal records the credential it replaces.
    broker.plan.push("drop-after-create");
    await failure(
      credentials.ensure(alice, ctx, {
        allowAcquire: false,
        forceRefresh: true,
      }),
    );
    expect(pending()).toMatchObject({
      renews: { credential_ref: "piship:acmecode:inference#2" },
    });
    await credentials.ensure(alice, ctx, {
      allowAcquire: false,
      forceRefresh: true,
    });
    expect(broker.keys[3]).toBe(broker.keys[2]);
    expect(broker.issued).toHaveLength(3);
    expect(pending()).toBeNull();
  });

  it("fails closed when an unresolved key may be past broker retention", async () => {
    let now = Date.now();
    const broker = new FakeBroker();
    broker.plan.push("drop-after-create");
    const credentials = brokerManager(broker, { now: () => now });
    await failure(credentials.ensure(alice, ctx, { allowAcquire: true }));
    const first = broker.keys[0];
    // Within the retention the key is still repeated...
    now += ISSUANCE_RETENTION_MS - 1000;
    broker.plan.push("drop-after-create");
    await failure(credentials.ensure(alice, ctx, { allowAcquire: true }));
    expect(broker.keys[1]).toBe(first);
    expect(broker.issued).toHaveLength(1);
    // A forward clock jump or true expiry cannot justify a new issuance.
    now += 2000;
    const error = await failure(
      credentials.ensure(alice, ctx, { allowAcquire: true }),
    );
    expect(error.message).toMatch(/reconcile/);
    expect(broker.keys).toHaveLength(2);
    expect(broker.issued).toHaveLength(1);
    expect(pending()?.idempotency_key).toBe(first);

    // A broker that forgot its records (a restart without a durable store)
    // answers a repeated key with a new credential: PiShip repeats the key,
    // and only a broker that keeps its records makes that exactly once.
    await credentials.logout(ctx);
    broker.plan.push("drop-after-create");
    await failure(credentials.ensure(alice, ctx, { allowAcquire: true }));
    broker.forget();
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys[3]).toBe(broker.keys[2]);
    expect(broker.issued).toHaveLength(3);
  });

  it("starts a new key after the broker's final answer to it", async () => {
    for (const step of ["denied", "conflict", "malformed"] as const) {
      const broker = new FakeBroker();
      broker.plan.push(step);
      const credentials = brokerManager(broker);
      const error = await failure(
        credentials.ensure(alice, ctx, { allowAcquire: true }),
      );
      expect(error.retryable).toBe(false);
      expect(pending()).toBeNull();
      await credentials.ensure(alice, ctx, { allowAcquire: true });
      expect(broker.keys[1]).not.toBe(broker.keys[0]);
      await credentials.logout(ctx);
    }
  });

  it("leaves no pending key after a change of principal or a logout, and keeps one across a sign-in of the same principal", async () => {
    const broker = new FakeBroker();
    const credentials = brokerManager(broker);
    // Another principal never repeats alice's key.
    broker.plan.push("drop-after-create");
    await failure(credentials.ensure(alice, ctx, { allowAcquire: true }));
    const aliceKey = broker.keys[0];
    expect(pending()?.principal).toEqual({ issuer: ISSUER, subject: "alice" });
    await credentials.ensure(bob, ctx, { allowAcquire: true });
    expect(broker.keys[1]).not.toBe(aliceKey);
    expect(pending()).toBeNull();

    // A sign-in of the same principal keeps the key, another's drops it.
    await credentials.logout(ctx);
    broker.plan.push("drop-after-create");
    await failure(credentials.ensure(alice, ctx, { allowAcquire: true }));
    const again = broker.keys[2];
    await credentials.logout(ctx, {
      reason: "replace",
      keepIssuanceFor: { issuer: ISSUER, subject: "alice" },
    });
    expect(pending()?.idempotency_key).toBe(again);
    await credentials.logout(ctx, {
      reason: "replace",
      keepIssuanceFor: { issuer: ISSUER, subject: "bob" },
    });
    expect(pending()).toBeNull();

    // A logout always drops it, with or without a stored credential.
    broker.plan.push("drop-after-create");
    await failure(credentials.ensure(alice, ctx, { allowAcquire: true }));
    expect(pending()).not.toBeNull();
    expect(credentials.hasStoredCredential()).toBe(false);
    expect(await credentials.logout(ctx)).toEqual([]);
    expect(pending()).toBeNull();
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    expect(pending()).toBeNull();
    await credentials.logout(ctx);
    expect(existsSync(issuancePath())).toBe(false);
  });

  it("drops a key whose credential was committed by a process that stopped before removing it", async () => {
    const broker = new FakeBroker();
    const store = new MemorySecretStore();
    const crashing = brokerManager(broker, {
      store,
      onPhase: (phase) => {
        if (phase === "metadata-written") throw new Error("process killed");
      },
    });
    await expect(
      crashing.ensure(alice, ctx, { allowAcquire: true }),
    ).rejects.toThrow("process killed");
    const stale = pending()?.idempotency_key;
    expect(stale).toBe(broker.keys[0]);
    // The next process uses the committed credential and drops the key.
    const next = brokerManager(broker, { store });
    const active = await next.ensure(alice, ctx, { allowAcquire: false });
    expect(active.secret?.reveal()).toBe(broker.issued[0]);
    expect(pending()).toBeNull();
    // A later renewal never repeats it.
    await next.ensure(alice, ctx, { allowAcquire: false, forceRefresh: true });
    expect(broker.keys[1]).not.toBe(stale);
    expect(broker.issued).toHaveLength(2);

    // The same when the next command is a sign-in, which clears the stored
    // credential before it acquires: the key is judged before that.
    const again = brokerManager(broker, {
      store,
      onPhase: (phase) => {
        if (phase === "metadata-written") throw new Error("process killed");
      },
    });
    await expect(
      again.ensure(alice, ctx, { allowAcquire: false, forceRefresh: true }),
    ).rejects.toThrow("process killed");
    const committed = pending()?.idempotency_key;
    expect(committed).toBe(broker.keys[2]);
    await next.logout(ctx, {
      reason: "replace",
      keepIssuanceFor: { issuer: ISSUER, subject: "alice" },
    });
    expect(pending()).toBeNull();
    await next.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys[3]).not.toBe(committed);
  });

  it("never sends a pending key to another broker endpoint", async () => {
    const broker = new FakeBroker();
    broker.plan.push("drop-after-create");
    await failure(
      brokerManager(broker).ensure(alice, ctx, { allowAcquire: true }),
    );
    const key = broker.keys[0];
    // An update moved the broker: the key is dropped, not sent there.
    const moved = brokerManager(broker, {
      endpoint: "https://broker-2.example.test/v1/credential",
    });
    await moved.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys[1]).not.toBe(key);
    expect(pending()).toBeNull();
    // An adapter's destination is what the manager is told decides it.
    const adapter = (target: string) =>
      new CredentialManager({
        distributionId: "acmecode",
        provider: {
          mode: "adapter",
          requiresIdentity: true,
          acquire: (identity, keyed) =>
            new HttpBrokerCredentialProvider({
              endpoint: ENDPOINT,
              fetch: broker.fetch,
            }).acquire(identity, keyed),
        },
        store: new MemorySecretStore(),
        metadataPath: join(temp, "adapter", "inference.json"),
        beforeExpirySeconds: 300,
        issuanceTarget: target,
      });
    broker.plan.push("drop-after-create");
    await failure(
      adapter("adapter one").ensure(alice, ctx, { allowAcquire: true }),
    );
    const adapterKey = broker.keys[2];
    await adapter("adapter one").ensure(bob, ctx, { allowAcquire: true });
    expect(broker.keys[3]).not.toBe(adapterKey);
    await adapter("adapter one").logout(ctx);
    broker.plan.push("drop-after-create");
    await failure(
      adapter("adapter one").ensure(alice, ctx, { allowAcquire: true }),
    );
    await adapter("adapter two").ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys[5]).not.toBe(broker.keys[4]);
  });

  it("never repeats another request's key for a rejection renewal or an entitlement re-read", async () => {
    const broker = new FakeBroker();
    const credentials = brokerManager(broker);
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    // An entitlement re-read whose answer was lost...
    broker.plan.push("drop-after-create");
    await failure(
      credentials.ensure(alice, ctx, {
        allowAcquire: false,
        forceRefresh: "entitlement",
      }),
    );
    const reread = broker.keys[1];
    expect(pending()).toMatchObject({ request: "entitlement" });
    // ...is not what a renewal after a gateway rejection repeats: a new key,
    // and that renewal's own retry repeats it.
    broker.plan.push("drop-after-create");
    await failure(
      credentials.ensure(alice, ctx, {
        allowAcquire: false,
        forceRefresh: true,
      }),
    );
    const rejected = broker.keys[2];
    expect(rejected).not.toBe(reread);
    expect(pending()).toMatchObject({ request: "rejected" });
    // Nor does an entitlement re-read repeat the rejection renewal's key.
    broker.plan.push("drop-after-create");
    await failure(
      credentials.ensure(alice, ctx, {
        allowAcquire: false,
        forceRefresh: "entitlement",
      }),
    );
    expect(broker.keys[3]).not.toBe(rejected);
    // A retry of the same kind of request repeats its key.
    await credentials.ensure(alice, ctx, {
      allowAcquire: false,
      forceRefresh: "entitlement",
    });
    expect(broker.keys[4]).toBe(broker.keys[3]);
    expect(pending()).toBeNull();
  });

  it("keeps a pending key over a different key the caller passes", async () => {
    const broker = new FakeBroker();
    broker.plan.push("drop-after-create");
    const credentials = brokerManager(broker);
    await failure(credentials.ensure(alice, ctx, { allowAcquire: true }));
    const key = broker.keys[0];
    // An older key from an earlier failure would lose the one that may
    // already have issued a credential.
    await credentials.ensure(
      alice,
      { ...ctx, idempotencyKey: "older-caller-key-0001" },
      { allowAcquire: true },
    );
    expect(broker.keys).toEqual([key, key]);
    expect(broker.issued).toHaveLength(1);
    // Without a pending key, the caller's key is used and recorded.
    await credentials.logout(ctx);
    broker.plan.push("drop-after-create");
    await failure(
      credentials.ensure(
        alice,
        { ...ctx, idempotencyKey: "caller-key-0002" },
        { allowAcquire: true },
      ),
    );
    expect(broker.keys[2]).toBe("caller-key-0002");
    expect(pending()?.idempotency_key).toBe("caller-key-0002");
  });

  it("sends nothing when the key cannot be recorded", async () => {
    const broker = new FakeBroker();
    // A file where the record's directory goes: the write cannot complete.
    writeFileSync(join(temp, "not-a-directory"), "");
    const credentials = new CredentialManager({
      distributionId: "acmecode",
      provider: new HttpBrokerCredentialProvider({
        endpoint: "https://broker.example.test/v1/credential",
        fetch: broker.fetch,
      }),
      store: new MemorySecretStore(),
      metadataPath: metadataPath(),
      issuancePath: join(temp, "not-a-directory", "pending-issuance.json"),
      beforeExpirySeconds: 300,
    });
    const error = await failure(
      credentials.ensure(alice, ctx, { allowAcquire: true }),
    );
    expect(error).toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      sanitizedDetail: { outcome: "not-sent" },
    });
    expect(broker.keys).toEqual([]);
    expect(credentials.status().state).toBe("absent");
  });

  it("drops a record that is damaged, from another mode, or from the future", async () => {
    const broker = new FakeBroker();
    const credentials = brokerManager(broker);
    const write = (value: unknown) => {
      mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
      writeFileSync(
        issuancePath(),
        typeof value === "string" ? value : JSON.stringify(value),
      );
    };
    const base = {
      schema: CREDENTIAL_ISSUANCE_SCHEMA,
      idempotency_key: "kept-key-0001",
      mode: "http-broker",
      request: "acquire",
      target: BROKER_TARGET,
      principal: { issuer: ISSUER, subject: "alice" },
      created_at: new Date().toISOString(),
    };
    for (const damaged of [
      "{not json",
      { ...base, schema: "piship-credential-issuance/v9" },
      { ...base, mode: "adapter" },
      { ...base, idempotency_key: "has space" },
      { ...base, request: "other" },
      // Recorded for another broker endpoint, or before endpoints were
      // recorded: never sent to this one.
      { ...base, target: targetOf("http-broker https://other.example.test/") },
      { ...base, target: undefined },
    ]) {
      write(damaged);
      await credentials.ensure(alice, ctx, { allowAcquire: true });
      expect(broker.keys.at(-1)).not.toBe("kept-key-0001");
      expect(broker.keys.at(-1)).toMatch(UUID);
      await credentials.logout(ctx);
    }
    // A backward clock correction leaves an unresolved key intact.
    write({
      ...base,
      created_at: new Date(Date.now() + 3_600_000).toISOString(),
    });
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys.at(-1)).toBe("kept-key-0001");
    await credentials.logout(ctx);
    // A valid record is repeated as it is.
    write(base);
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    expect(broker.keys.at(-1)).toBe("kept-key-0001");
  });

  it("records only a random, non-secret key: never a token or a credential", async () => {
    const broker = new FakeBroker();
    broker.plan.push("drop-after-create");
    const events: CredentialEvent[] = [];
    const credentials = brokerManager(broker, { events });
    const error = await failure(
      credentials.ensure(alice, ctx, { allowAcquire: true }),
    );
    const text = readFileSync(issuancePath(), "utf8");
    const record = JSON.parse(text);
    expect(Object.keys(record).sort()).toEqual([
      "created_at",
      "idempotency_key",
      "mode",
      "principal",
      "request",
      "schema",
      "target",
    ]);
    expect(record.idempotency_key).toMatch(UUID);
    // The destination only as a hash of the endpoint.
    expect(record.target).toBe(BROKER_TARGET);
    if (process.platform !== "win32")
      expect(statSync(issuancePath()).mode & 0o777).toBe(0o600);
    const token = alice.accessToken?.reveal() ?? "";
    for (const secret of [token, ...broker.issued])
      expect(text).not.toContain(secret);
    expect(record.idempotency_key).not.toContain("alice");
    // The error carries the key as an identifier, nothing more.
    const rendered = inspect(error, { depth: 10, showHidden: true });
    for (const secret of [token, ...broker.issued])
      expect(rendered).not.toContain(secret);
    await credentials.ensure(alice, ctx, { allowAcquire: true });
    // The audit event names the request by its key, and says it was repeated.
    expect(events.at(-1)).toMatchObject({
      event: "credential.acquire",
      detail: { idempotencyKey: record.idempotency_key, resumed: true },
    });
    expect(JSON.stringify(events)).not.toContain(broker.issued[0]);
    expect(JSON.stringify(events)).not.toContain(token);
  });

  it("records nothing for a user-owned secret or a sandbox credential", async () => {
    const local: CredentialProvider = {
      mode: "local-secret",
      requiresIdentity: false,
      acquire: async () => ({
        kind: "api_key",
        secret: new SecretValue("sk-local-user-secret-0001"),
      }),
    };
    const manager = new CredentialManager({
      distributionId: "acmecode",
      provider: local,
      store: new MemorySecretStore(),
      metadataPath: metadataPath(),
      beforeExpirySeconds: 300,
    });
    await manager.ensure(null, ctx, { allowAcquire: true });
    expect(existsSync(issuancePath())).toBe(false);
    expect(manager.pendingIssuance()).toBeNull();
  });
});

describe("a PiShip process killed mid-acquire", () => {
  let server: Server;
  let url: string;
  const issued: string[] = [];
  const keys: string[] = [];
  const records = new Map<string, string>();
  let onIssued: (() => void) | undefined;
  beforeEach(async () => {
    issued.length = 0;
    keys.length = 0;
    records.clear();
    server = createServer((req, res) => {
      const key = String(req.headers["idempotency-key"]);
      keys.push(key);
      let secret = records.get(key);
      if (!secret) {
        secret = `sk-fake-broker-issued-${issued.length + 1}-value`;
        issued.push(secret);
        records.set(key, secret);
      }
      req.resume();
      const answer = () =>
        res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            credential_type: "api_key",
            credential: secret,
            credential_id: `vk_${issued.indexOf(secret) + 1}`,
          }),
        );
      // The first request is issued and never answered: the parent kills
      // the client process instead.
      if (onIssued) {
        const kill = onIssued;
        onIssued = undefined;
        kill();
      } else answer();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    url = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}/v1/credential`;
  });
  afterEach(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  it("repeats the recorded key in the next process, so the broker issues once", async () => {
    const dist = (name: string) =>
      new URL(`../../${name}/dist/index.js`, import.meta.url).href;
    const script = join(temp, "acquire.mjs");
    writeFileSync(
      script,
      `import { CredentialManager, HttpBrokerCredentialProvider, MemorySecretStore } from ${JSON.stringify(dist("credentials"))};
import { SecretValue } from ${JSON.stringify(dist("contracts"))};
const [url, metadataPath] = process.argv.slice(2);
const manager = new CredentialManager({
  distributionId: "acmecode",
  provider: new HttpBrokerCredentialProvider({ endpoint: url, fetch: globalThis.fetch }),
  store: new MemorySecretStore(),
  metadataPath,
  beforeExpirySeconds: 300,
});
await manager.ensure(
  { subject: "alice", issuer: ${JSON.stringify(ISSUER)}, accessToken: new SecretValue("fake-identity-token-alice-0001") },
  { distributionId: "acmecode" },
  { allowAcquire: true },
);
`,
    );
    const child = spawn(process.execPath, [script, url, metadataPath()], {
      stdio: "ignore",
    });
    const exited = new Promise<{
      code: number | null;
      signal: NodeJS.Signals | null;
    }>((resolve) =>
      child.on("exit", (code, signal) => resolve({ code, signal })),
    );
    onIssued = () => child.kill("SIGKILL");
    // Killed, not a clean exit (Windows reports an exit code instead).
    const { code, signal } = await exited;
    expect(signal === "SIGKILL" || code !== 0).toBe(true);
    expect(issued).toHaveLength(1);
    const key = pending()?.idempotency_key;
    expect(key).toBe(keys[0]);
    expect(existsSync(metadataPath())).toBe(false);

    const next = new CredentialManager({
      distributionId: "acmecode",
      provider: new HttpBrokerCredentialProvider({
        endpoint: url,
        fetch: globalThis.fetch,
      }),
      store: new MemorySecretStore(),
      metadataPath: metadataPath(),
      beforeExpirySeconds: 300,
      // The killed process left its lock: take it over without the
      // production wait.
      lockTiming: { heartbeatMs: 50, staleMs: 300, waitMs: 5_000 },
    });
    const active = await next.ensure(session("alice"), ctx, {
      allowAcquire: true,
    });
    expect(keys).toEqual([key, key]);
    expect(issued).toHaveLength(1);
    expect(active.secret?.reveal()).toBe(issued[0]);
    expect(pending()).toBeNull();
  });
});
