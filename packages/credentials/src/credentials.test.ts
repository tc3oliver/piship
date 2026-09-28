import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type IdentitySession,
  type RuntimeCredential,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  type CommandRunner,
  CREDENTIAL_METADATA_SCHEMA,
  CredentialManager,
  HttpBrokerCredentialProvider,
  LocalSecretCredentialProvider,
  MacKeychainSecretStore,
  MemorySecretStore,
  NoCredentialProvider,
  PiNativeCredentialProvider,
  RestrictedFileSecretStore,
  SecretServiceSecretStore,
  WindowsCredentialSecretStore,
  createSecretStore,
} from "./index.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-credentials-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});
const ctx = { distributionId: "acmecode" };

function recordingRunner(
  responses: Record<
    string,
    { status: number; stdout?: string; stderr?: string }
  >,
) {
  const calls: { command: string; args: readonly string[]; stdin: string }[] =
    [];
  const runner: CommandRunner = (command, args, stdin) => {
    calls.push({ command, args, stdin: stdin ?? "" });
    const key = Object.keys(responses).find((item) =>
      [command, ...args, stdin ?? ""].join(" ").includes(item),
    );
    const response = key ? responses[key] : { status: 0 };
    return {
      status: response?.status ?? 0,
      stdout: response?.stdout ?? "",
      stderr: response?.stderr ?? "",
    };
  };
  return { calls, runner };
}

describe("platform secret stores", () => {
  const secret = new SecretValue("sk-platform-secret-value");
  const encoded = Buffer.from(secret.reveal()).toString("base64url");
  it.each([
    [
      "macOS Keychain",
      (run: CommandRunner) => new MacKeychainSecretStore(run),
      `find-generic-password`,
    ],
    [
      "Secret Service",
      (run: CommandRunner) => new SecretServiceSecretStore(run),
      "lookup",
    ],
    [
      "Windows Credential Manager",
      (run: CommandRunner) => new WindowsCredentialSecretStore(run),
      "get",
    ],
  ])(
    "%s never places the secret in process arguments",
    async (_name, create, lookup) => {
      const { calls, runner } = recordingRunner({
        [lookup]: { status: 0, stdout: encoded },
      });
      const store = create(runner);
      await store.put("piship:acmecode:inference#1", secret);
      expect((await store.get("piship:acmecode:inference#1"))?.reveal()).toBe(
        secret.reveal(),
      );
      await store.delete("piship:acmecode:inference#1");
      for (const call of calls) {
        expect(call.args.join(" ")).not.toContain(secret.reveal());
        expect(call.args.join(" ")).not.toContain(encoded);
      }
      const writes = calls.filter(
        (call) =>
          call.stdin.includes(encoded) ||
          call.stdin.includes(Buffer.from(encoded).toString("hex")),
      );
      expect(writes).toHaveLength(1);
    },
  );
  it("splits large macOS Keychain values into parts and removes stale parts", async () => {
    // A stateful fake of `security`: interactive add/delete lines on stdin,
    // find/delete through arguments.
    const items = new Map<string, string>();
    const calls: { args: readonly string[]; stdin: string }[] = [];
    const run: CommandRunner = (_command, args, stdin) => {
      calls.push({ args, stdin: stdin ?? "" });
      const account = (list: readonly string[]) =>
        list[list.indexOf("-a") + 1] ?? "";
      if (args[0] === "-i") {
        for (const line of (stdin ?? "").trim().split("\n")) {
          const words = line.split(" ");
          if (words[0] === "add-generic-password")
            items.set(
              account(words),
              Buffer.from(words[words.indexOf("-X") + 1] ?? "", "hex").toString(
                "utf8",
              ),
            );
          else if (!items.delete(account(words)))
            return { status: 0, stdout: "", stderr: "error: not found" };
        }
        return { status: 0, stdout: "", stderr: "" };
      }
      const value = items.get(account(args));
      if (args[0] === "find-generic-password")
        return value === undefined
          ? { status: 44, stdout: "", stderr: "" }
          : { status: 0, stdout: `${value}\n`, stderr: "" };
      return items.delete(account(args))
        ? { status: 0, stdout: "", stderr: "" }
        : { status: 44, stdout: "", stderr: "" };
    };
    const store = new MacKeychainSecretStore(run);
    const ref = "piship:acmecode:identity";
    const large = new SecretValue(`{"idToken":"${"x".repeat(6000)}"}`);
    await store.put(ref, large);
    expect([...items.keys()].sort()).toEqual(
      [
        ref,
        ...[0, 1, 2, 3, 4, 5, 6, 7].map((index) => `${ref}+${index}`),
      ].sort(),
    );
    for (const line of calls.at(-1)?.stdin.trim().split("\n") ?? [])
      expect(line.length).toBeLessThan(4096);
    expect((await store.get(ref))?.reveal()).toBe(large.reveal());
    await store.put(ref, secret);
    expect([...items.keys()]).toEqual([ref]);
    expect((await store.get(ref))?.reveal()).toBe(secret.reveal());
    await store.put(ref, large);
    items.delete(`${ref}+3`);
    await expect(store.get(ref)).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    await store.delete(ref);
    expect([...items.keys()]).toEqual([]);
    for (const call of calls)
      expect(call.args.join(" ")).not.toContain("xxxxxxxx");
  });
  it("reports an unavailable platform store instead of degrading to a file", async () => {
    const { runner } = recordingRunner({
      store: { status: 1, stderr: "Cannot autolaunch D-Bus without X11" },
    });
    const store = createSecretStore({
      provider: "system",
      fileDirectory: join(temp, "secrets"),
      platform: "linux",
      run: runner,
    });
    await expect(
      store.put("piship:x:inference#1", secret),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(() => readdirSync(join(temp, "secrets"))).toThrow();
    expect(
      createSecretStore({
        provider: "system",
        fileDirectory: temp,
        platform: "darwin",
      }).kind,
    ).toBe("macos-keychain");
    expect(
      createSecretStore({
        provider: "system",
        fileDirectory: temp,
        platform: "win32",
      }).kind,
    ).toBe("windows-credential-manager");
  });
  it("uses owner-only files with atomic replacement for the explicit file fallback", async () => {
    const store = new RestrictedFileSecretStore(join(temp, "secrets"));
    await store.put("piship:x:inference#1", secret);
    await store.put(
      "piship:x:inference#1",
      new SecretValue("sk-replacement-value"),
    );
    expect((await store.get("piship:x:inference#1"))?.reveal()).toBe(
      "sk-replacement-value",
    );
    const files = readdirSync(join(temp, "secrets"));
    expect(files).toHaveLength(1);
    expect(files[0]).not.toContain("inference");
    if (process.platform !== "win32") {
      expect(statSync(join(temp, "secrets")).mode & 0o777).toBe(0o700);
      expect(statSync(join(temp, "secrets", files[0] ?? "")).mode & 0o777).toBe(
        0o600,
      );
    }
    await store.delete("piship:x:inference#1");
    expect(await store.get("piship:x:inference#1")).toBeNull();
    await expect(store.put("../escape", secret)).rejects.toMatchObject({
      code: "CONFIG_INVALID",
    });
  });
});

describe("http-broker credential provider", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  let identity: IdentitySession;
  beforeEach(async () => {
    services = await startLocalServices();
    const token = `demo-at-test-${Date.now()}`;
    services.state.accessTokens.set(token, {
      subject: "demo-user-1",
      expires: Math.floor(Date.now() / 1000) + 600,
    });
    identity = {
      subject: "demo-user-1",
      issuer: services.issuer,
      accessToken: new SecretValue(token),
    };
  });
  afterEach(() => services.close());
  const broker = (extra: Record<string, unknown> = {}) =>
    new HttpBrokerCredentialProvider({
      endpoint: services.brokerUrl,
      revokeEndpoint: services.revokeUrl,
      expectedBaseUrl: services.gatewayUrl,
      fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
      ...extra,
    });

  it("acquires a scoped credential with the identity token and revokes it", async () => {
    const credential = await broker().acquire(identity, ctx);
    expect(credential).toMatchObject({
      kind: "api_key",
      credentialId: "vk_demo_1",
      metadata: { models: ["acme/coder", "acme/general"] },
    });
    expect(credential.expiresAt?.getTime()).toBeGreaterThan(Date.now());
    const request = services.state.requests.find(
      (item: { path: string }) => item.path === "/broker/v1/llm-credential",
    );
    expect(request.authorization).toBe(
      `Bearer ${identity.accessToken?.reveal()}`,
    );
    await broker().revoke(credential, ctx);
    expect(services.state.revokedCredentials).toEqual(["vk_demo_1"]);
  });
  it.each([
    [{ brokerStatus: 403 }, "CREDENTIAL_ACQUIRE_FAILED", false],
    [{ brokerStatus: 429 }, "CREDENTIAL_ACQUIRE_FAILED", true],
    [{ brokerStatus: 503 }, "CREDENTIAL_ACQUIRE_FAILED", true],
    [
      { brokerBaseUrl: "https://undeclared.example/v1" },
      "CREDENTIAL_ACQUIRE_FAILED",
      false,
    ],
    [{ credentialTtl: -10 }, "CREDENTIAL_EXPIRED", false],
  ])("classifies broker failure %j", async (knobs, code, retryable) => {
    Object.assign(services.knobs, knobs);
    await expect(broker().acquire(identity, ctx)).rejects.toMatchObject({
      code,
      retryable,
    });
  });
  it("reports an unreachable broker as a retryable acquisition failure", async () => {
    const provider = broker();
    await services.close();
    await expect(provider.acquire(identity, ctx)).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    services = await startLocalServices();
  });

  it("maps a rejected identity to IDENTITY_EXPIRED and requires an identity", async () => {
    const stale = {
      ...identity,
      accessToken: new SecretValue("demo-at-unknown-token"),
    };
    await expect(broker().acquire(stale, ctx)).rejects.toMatchObject({
      code: "IDENTITY_EXPIRED",
    });
    await expect(broker().acquire(null, ctx)).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
  });
  it("never echoes the broker response in errors", async () => {
    const leaky = broker({
      fetch: async () =>
        new Response(
          JSON.stringify({
            credential_type: "unknown",
            credential: "sk-leaked-secret-123",
          }),
          { status: 200 },
        ),
    });
    const error = await leaky
      .acquire(identity, ctx)
      .catch((caught: Error) => caught);
    expect(String((error as Error).message)).not.toContain(
      "sk-leaked-secret-123",
    );
  });
});

function fakeProvider(
  options: {
    expiresInSeconds?: number;
    failRefresh?: boolean;
    revoked?: string[];
  } = {},
) {
  let count = 0;
  return {
    mode: "http-broker" as const,
    requiresIdentity: false,
    acquired: () => count,
    async acquire(): Promise<RuntimeCredential> {
      count += 1;
      return {
        kind: "api_key",
        secret: new SecretValue(`sk-generation-${count}-secret`),
        credentialId: `vk_${count}`,
        ...(options.expiresInSeconds === undefined
          ? {}
          : {
              expiresAt: new Date(Date.now() + options.expiresInSeconds * 1000),
            }),
        metadata: { models: ["acme/coder"] },
      };
    },
    async refresh(): Promise<RuntimeCredential> {
      if (options.failRefresh) throw new Error("broker unavailable");
      return this.acquire();
    },
    async revoke(credential: RuntimeCredential) {
      options.revoked?.push(credential.credentialId ?? "");
    },
  };
}

describe("credential lifecycle", () => {
  function manager(
    provider: ReturnType<typeof fakeProvider>,
    extra: Record<string, unknown> = {},
    store = new MemorySecretStore(),
  ) {
    return {
      store,
      manager: new CredentialManager({
        distributionId: "acmecode",
        provider,
        store,
        metadataPath: join(temp, "credentials-metadata", "inference.json"),
        beforeExpirySeconds: 300,
        ...extra,
      }),
    };
  }
  const metadataText = () =>
    readFileSync(join(temp, "credentials-metadata", "inference.json"), "utf8");

  it("acquires once, stores only references in metadata, and reuses a valid credential", async () => {
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const { manager: credentials, store } = manager(provider);
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    const first = await credentials.ensure(null, ctx, { allowAcquire: true });
    expect(first.secret?.reveal()).toBe("sk-generation-1-secret");
    expect(metadataText()).not.toContain("sk-generation");
    expect(JSON.parse(metadataText())).toMatchObject({
      schema: CREDENTIAL_METADATA_SCHEMA,
      credential_ref: "piship:acmecode:inference#1",
      credential_id: "vk_1",
    });
    const again = await credentials.ensure(null, ctx, { allowAcquire: false });
    expect(again.secret?.reveal()).toBe("sk-generation-1-secret");
    expect(provider.acquired()).toBe(1);
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
  });
  it("refreshes before expiry and atomically replaces the secret generation", async () => {
    const provider = fakeProvider({ expiresInSeconds: 120 });
    const { manager: credentials, store } = manager(provider);
    await credentials.ensure(null, ctx, { allowAcquire: true });
    expect(credentials.status().state).toBe("expiring");
    const refreshed = await credentials.ensure(null, ctx, {
      allowAcquire: false,
    });
    expect(refreshed.secret?.reveal()).toBe("sk-generation-2-secret");
    expect(store.refs()).toEqual(["piship:acmecode:inference#2"]);
    expect(JSON.parse(metadataText()).generation).toBe(2);
  });
  it("keeps the previous complete credential when a crash interrupts replacement", async () => {
    const provider = fakeProvider({ expiresInSeconds: 120 });
    const store = new MemorySecretStore();
    const crashing = manager(
      provider,
      {
        onPhase: (phase: string) => {
          if (phase === "secret-written" && provider.acquired() === 2)
            throw new Error("simulated crash");
        },
      },
      store,
    ).manager;
    await crashing.ensure(null, ctx, { allowAcquire: true });
    const before = metadataText();
    await expect(
      crashing.ensure(null, ctx, { allowAcquire: false }),
    ).resolves.toMatchObject({
      notices: [expect.stringContaining("refresh failed")],
    });
    expect(metadataText()).toBe(before);
    const recovered = manager(provider, {}, store).manager;
    const retry = await recovered.ensure(null, ctx, { allowAcquire: false });
    expect(retry.secret?.reveal()).toBe("sk-generation-3-secret");
    await recovered.logout(ctx);
    expect(store.refs()).toEqual([]);
  });
  it("fails closed when an expired credential cannot be renewed and continues while still valid", async () => {
    const expired = fakeProvider({ expiresInSeconds: 1, failRefresh: true });
    let now = Date.now();
    const { manager: credentials } = manager(expired, { now: () => now });
    await credentials.ensure(null, ctx, { allowAcquire: true });
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: false }),
    ).resolves.toMatchObject({
      notices: [
        expect.stringContaining("continuing with the current credential"),
      ],
    });
    now += 5_000;
    expect(credentials.status().state).toBe("expired");
    const error = await credentials
      .ensure(null, ctx, { allowAcquire: false })
      .catch((caught: Error) => caught);
    expect(error).toMatchObject({ code: "CREDENTIAL_EXPIRED" });
    expect(String(error)).not.toContain("sk-generation");
  });
  it("forces re-acquisition after a gateway rejection", async () => {
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const { manager: credentials } = manager(provider);
    await credentials.ensure(null, ctx, { allowAcquire: true });
    const forced = await credentials.ensure(null, ctx, {
      allowAcquire: false,
      forceRefresh: true,
    });
    expect(forced.secret?.reveal()).toBe("sk-generation-2-secret");
  });
  it("clears incompatible metadata and orphaned references instead of resurrecting secrets", async () => {
    const provider = fakeProvider();
    const { manager: credentials, store } = manager(provider);
    await store.put(
      "piship:acmecode:inference#7",
      new SecretValue("sk-old-snapshot-secret"),
    );
    await credentials.ensure(null, ctx, { allowAcquire: true });
    writeFileSync(
      join(temp, "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v0",
        credential_ref: "piship:acmecode:inference#7",
      }),
    );
    expect(credentials.status()).toMatchObject({
      state: "absent",
      notice: expect.stringContaining("incompatible"),
    });
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    const fresh = await credentials.ensure(null, ctx, { allowAcquire: true });
    expect(fresh.secret?.reveal()).not.toBe("sk-old-snapshot-secret");
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
  });
  it("deletes every secret referenced by metadata whose secret is missing", async () => {
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const { manager: credentials, store } = manager(provider);
    for (const generation of [5, 6])
      await store.put(
        `piship:acmecode:inference#${generation}`,
        new SecretValue(`sk-stale-generation-${generation}`),
      );
    await store.put("piship:other:inference#1", new SecretValue("sk-other-1"));
    await credentials.ensure(null, ctx, { allowAcquire: true });
    const metadata = JSON.parse(metadataText());
    writeFileSync(
      join(temp, "credentials-metadata", "inference.json"),
      JSON.stringify({
        ...metadata,
        credential_ref: "piship:acmecode:inference#7",
        generation: 7,
        orphans: [
          "piship:acmecode:inference#5",
          "piship:acmecode:inference#6",
          "piship:other:inference#1",
        ],
      }),
    );
    await store.delete("piship:acmecode:inference#1");
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    expect(store.refs()).toEqual(["piship:other:inference#1"]);
  });
  it("shares one refresh between concurrent callers and processes", async () => {
    const revoked: string[] = [];
    const provider = fakeProvider({ expiresInSeconds: 120, revoked });
    const store = new MemorySecretStore();
    const first = manager(provider, {}, store).manager;
    const second = manager(provider, {}, store).manager;
    await first.ensure(null, ctx, { allowAcquire: true });
    const results = await Promise.all([
      first.ensure(null, ctx, { allowAcquire: false }),
      first.ensure(null, ctx, { allowAcquire: false }),
      second.ensure(null, ctx, { allowAcquire: false }),
    ]);
    // The first caller refreshes (generation 2, still expiring); each later
    // caller refreshes the generation it finds, never two at once.
    expect(results.map((result) => result.secret?.reveal())).toEqual([
      "sk-generation-2-secret",
      "sk-generation-3-secret",
      "sk-generation-4-secret",
    ]);
    expect(store.refs()).toEqual(["piship:acmecode:inference#4"]);
    expect(JSON.parse(metadataText())).toMatchObject({
      credential_ref: "piship:acmecode:inference#4",
      credential_id: "vk_4",
    });
  });
  it("renews once when concurrent callers report the same rejection", async () => {
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const store = new MemorySecretStore();
    const first = manager(provider, {}, store).manager;
    const second = manager(provider, {}, store).manager;
    await first.ensure(null, ctx, { allowAcquire: true });
    const forced = await Promise.all([
      first.ensure(null, ctx, { allowAcquire: false, forceRefresh: true }),
      second.ensure(null, ctx, { allowAcquire: false, forceRefresh: true }),
    ]);
    // Both callers saw the rejected generation; one renewal satisfies both.
    expect(provider.acquired()).toBe(2);
    expect(forced.map((result) => result.secret?.reveal())).toEqual([
      "sk-generation-2-secret",
      "sk-generation-2-secret",
    ]);
    expect(store.refs()).toEqual(["piship:acmecode:inference#2"]);
    // A rejection reported for an already replaced generation is ignored.
    const stale = manager(provider, {}, store).manager;
    await Promise.all([
      first.ensure(null, ctx, { allowAcquire: false, forceRefresh: true }),
      stale.markRejected(),
    ]);
    expect(provider.acquired()).toBe(3);
    expect(first.status().state).toBe("valid");
  });
  it("waits for another process's lock and breaks an abandoned one", async () => {
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const { manager: credentials } = manager(provider);
    await credentials.ensure(null, ctx, { allowAcquire: true });
    const lock = join(temp, "credentials-metadata", "inference.json.lock");
    writeFileSync(lock, "");
    let settled = false;
    const waiting = credentials
      .ensure(null, ctx, { allowAcquire: false })
      .then((result) => {
        settled = true;
        return result;
      });
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(settled).toBe(false);
    rmSync(lock);
    await expect(waiting).resolves.toMatchObject({
      secret: expect.anything(),
    });
    writeFileSync(lock, "");
    const old = new Date(Date.now() - 10 * 60_000);
    utimesSync(lock, old, old);
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: false }),
    ).resolves.toMatchObject({ secret: expect.anything() });
    expect(existsSync(lock)).toBe(false);
  });
  it("revokes, then clears secrets and metadata on logout", async () => {
    const revoked: string[] = [];
    const provider = fakeProvider({ expiresInSeconds: 3600, revoked });
    const { manager: credentials, store } = manager(provider);
    await credentials.ensure(null, ctx, { allowAcquire: true });
    expect(await credentials.logout(ctx)).toEqual([]);
    expect(revoked).toEqual(["vk_1"]);
    expect(store.refs()).toEqual([]);
    expect(credentials.status().state).toBe("absent");
  });
  it("stores a user-owned local secret from interactive input only", async () => {
    const store = new MemorySecretStore();
    const credentials = new CredentialManager({
      distributionId: "mypi",
      provider: new LocalSecretCredentialProvider(),
      store,
      metadataPath: join(temp, "local.json"),
      beforeExpirySeconds: 300,
    });
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: true }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    const active = await credentials.ensure(
      null,
      { ...ctx, readSecret: async () => "sk-personal-key-000\n" },
      { allowAcquire: true },
    );
    expect(active.secret?.reveal()).toBe("sk-personal-key-000");
    expect(readFileSync(join(temp, "local.json"), "utf8")).not.toContain(
      "sk-personal",
    );
    await expect(
      credentials.ensure(
        null,
        { ...ctx, readSecret: async () => "short" },
        { allowAcquire: true, forceRefresh: true },
      ),
    ).rejects.toThrow("malformed");
    // A user-owned secret cannot be renewed, so a rejection is not persisted.
    expect(credentials.renewable).toBe(false);
    await credentials.markRejected();
    expect(credentials.status().state).toBe("valid");
  });
  it.each([
    ["pi-native", new PiNativeCredentialProvider()],
    ["none", new NoCredentialProvider()],
  ])("%s stores nothing and delegates explicitly", async (mode, provider) => {
    const credentials = new CredentialManager({
      distributionId: "mypi",
      provider,
      store: null,
      metadataPath: join(temp, `${mode}.json`),
      beforeExpirySeconds: 300,
    });
    const active = await credentials.ensure(null, ctx, { allowAcquire: false });
    expect(active).toMatchObject({ secret: null, ref: { mode } });
    expect(credentials.status().state).toBe("delegated");
    expect(readdirSync(temp)).toEqual([]);
  });
});

describe("gateway rejection", () => {
  it("persists a rejection so a later process renews before reuse", async () => {
    const store = new MemorySecretStore();
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const make = () =>
      new CredentialManager({
        distributionId: "acmecode",
        provider,
        store,
        metadataPath: join(temp, "credentials-metadata", "inference.json"),
        beforeExpirySeconds: 300,
      });
    const first = make();
    await first.ensure(null, ctx, { allowAcquire: true });
    await first.markRejected();
    const later = make();
    expect(later.status().state).toBe("rejected");
    const renewed = await later.ensure(null, ctx, { allowAcquire: false });
    expect(renewed.secret?.reveal()).toBe("sk-generation-2-secret");
    expect(later.status().state).toBe("valid");
  });
});
