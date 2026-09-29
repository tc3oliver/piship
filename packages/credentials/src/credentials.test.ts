import {
  existsSync,
  mkdirSync,
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
import { inspect } from "node:util";
import {
  type CredentialProvider,
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type IdentitySession,
  PiShipError,
  type RuntimeCredential,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  type CommandRunner,
  CREDENTIAL_METADATA_SCHEMA,
  type CredentialEvent,
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
  metadataSecretRefs,
  toSecretValue,
  withFileLock,
} from "./index.js";
import { touchHeldLocks } from "./lock-heartbeat.js";

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
        // Secret Service parts are found by their `parent`; none exist here.
        "lookup service piship parent": { status: 1 },
        [lookup]: { status: 0, stdout: encoded },
      });
      const store = create(runner);
      await store.put("piship:acmecode:inference#1", secret);
      expect((await store.get("piship:acmecode:inference#1"))?.reveal()).toBe(
        secret.reveal(),
      );
      // This double keeps answering the lookup after the delete, which the
      // Secret Service store's verified delete reports; only the arguments of
      // the calls matter here.
      await store.delete("piship:acmecode:inference#1").catch(() => undefined);
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
    [{ brokerStatus: 403 }, "CREDENTIAL_DENIED", false],
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

describe("http-broker failure and retry contract", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  let identity: IdentitySession;
  let issued: RuntimeCredential;
  // Planted in every failure answer, so an echoed body is caught.
  const BODY_SENTINEL = "sk-body-sentinel-0123456789";
  beforeEach(async () => {
    services = await startLocalServices();
    const token = `demo-at-contract-${Date.now()}`;
    services.state.accessTokens.set(token, {
      subject: "demo-user-1",
      expires: Math.floor(Date.now() / 1000) + 600,
    });
    identity = {
      subject: "demo-user-1",
      issuer: services.issuer,
      accessToken: new SecretValue(token),
    };
    issued = await broker().acquire(identity, ctx);
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
  const failure = (promise: Promise<unknown>) =>
    promise.then(
      () => {
        throw new Error("expected a failure");
      },
      (error: unknown) => error as PiShipError,
    );
  /** No secret in the message, action, detail, cause, or any rendering. */
  function expectNoSecret(error: unknown): void {
    const renderings = [
      String(error),
      JSON.stringify(error),
      inspect(error, { depth: 10, showHidden: true }),
      String((error as { cause?: unknown }).cause ?? ""),
    ].join("\n");
    for (const secret of [
      identity.accessToken?.reveal() ?? "missing",
      issued.secret.reveal(),
      BODY_SENTINEL,
    ])
      expect(renderings).not.toContain(secret);
  }
  const call = {
    acquire: (provider: HttpBrokerCredentialProvider, context = ctx) =>
      provider.acquire(identity, context),
    revoke: (provider: HttpBrokerCredentialProvider, context = ctx) =>
      provider.revoke(issued, context),
  } as const;
  const inThirtySeconds = () => new Date(Date.now() + 30_000);

  describe("header values and answer bodies", () => {
    const real = createManagedFetch(DEFAULT_NETWORK_POLICY);
    /** The fixture's real answer, to replay with one field changed. */
    async function realAnswer(): Promise<Record<string, unknown>> {
      let captured = "";
      await broker({
        fetch: async (url: string | URL, init?: RequestInit) => {
          const response = await real(url, init);
          captured = await response.clone().text();
          return response;
        },
      }).acquire(identity, ctx);
      return JSON.parse(captured) as Record<string, unknown>;
    }
    const json = (body: unknown) =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    it("reports a transport failure by code, never by the error's own message", async () => {
      const token = identity.accessToken?.reveal() ?? "";
      const error = await failure(
        call.acquire(
          broker({
            fetch: async () => {
              throw new TypeError(
                `Invalid value "${token}" for header "authorization"`,
              );
            },
          }),
        ),
      );
      expect(error).toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
        retryable: true,
      });
      expectNoSecret(error);
      // The message stays out even for a value the redaction does not know.
      expect(String(error)).not.toContain("Invalid value");
    });

    it("refuses an access token or stored credential that would break a header", async () => {
      const never = async (): Promise<Response> => {
        throw new Error("no request may be sent");
      };
      for (const control of ["\r", "\n", "\0"]) {
        const bad = {
          ...identity,
          accessToken: new SecretValue(`demo-at${control}injected`),
        };
        await expect(
          broker({ fetch: never }).acquire(bad, ctx),
        ).rejects.toMatchObject({ code: "IDENTITY_INVALID" });
        await expect(
          broker({ fetch: never }).revoke(
            { ...issued, secret: new SecretValue(`sk-issued${control}xx`) },
            ctx,
          ),
        ).rejects.toMatchObject({
          code: "CREDENTIAL_REVOKED",
          sanitizedDetail: { reason: "contract" },
        });
      }
    });

    it("refuses a credential from the broker that would break a header", async () => {
      const answer = await realAnswer();
      await expect(
        broker({ fetch: async () => json(answer) }).acquire(identity, ctx),
      ).resolves.toBeDefined();
      for (const control of ["\r", "\n", "\0"]) {
        const error = await failure(
          call.acquire(
            broker({
              fetch: async () =>
                json({ ...answer, credential: `sk-live${control}injected` }),
            }),
          ),
        );
        expect(error).toMatchObject({
          code: "CREDENTIAL_ACQUIRE_FAILED",
          sanitizedDetail: { reason: "contract" },
        });
      }
    });

    it("refuses an answer body larger than the broker contract allows", async () => {
      const answer = await realAnswer();
      const error = await failure(
        call.acquire(
          broker({
            fetch: async () =>
              json({ ...answer, padding: "x".repeat(200 * 1024) }),
          }),
        ),
      );
      expect(error).toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
        sanitizedDetail: { reason: "contract" },
      });
    });

    it("decides a 403 from the status without reading its body", async () => {
      // A body that never ends: reading it would turn the 403 into a timeout.
      const stalled = new ReadableStream<Uint8Array>({ start() {} });
      const error = await failure(
        call.acquire(
          broker({
            timeoutMs: 200,
            fetch: async () => new Response(stalled, { status: 403 }),
          }),
        ),
      );
      expect(error).toMatchObject({
        code: "CREDENTIAL_DENIED",
        sanitizedDetail: { reason: "denied" },
      });
    });
  });

  // One row per §7.1 status class, for acquire (knob prefix `broker`) and
  // revoke (knob prefix `revoke`). A 401 and 404 on revoke mean the
  // credential is already invalid there, so they count as revoked.
  const statusRows = [
    // [operation, fault, code, retryable, reason, retryAfterMs]
    ["acquire", { status: 401 }, "IDENTITY_EXPIRED", false, "authentication"],
    ["acquire", { status: 403 }, "CREDENTIAL_DENIED", false, "denied"],
    [
      "acquire",
      { status: 429, retryAfter: 7 },
      "CREDENTIAL_ACQUIRE_FAILED",
      true,
      "rate-limited",
      7_000,
    ],
    [
      "acquire",
      { status: 429, retryAfter: "date" },
      "CREDENTIAL_ACQUIRE_FAILED",
      true,
      "rate-limited",
      "date",
    ],
    [
      "acquire",
      { status: 503, retryAfter: 5 },
      "CREDENTIAL_ACQUIRE_FAILED",
      true,
      "unavailable",
      5_000,
    ],
    [
      "acquire",
      { status: 502, body: `<html><body>${BODY_SENTINEL}</body></html>` },
      "CREDENTIAL_ACQUIRE_FAILED",
      true,
      "unavailable",
    ],
    [
      "acquire",
      { status: 400, retryAfter: 9 },
      "CREDENTIAL_ACQUIRE_FAILED",
      false,
      "rejected",
    ],
    [
      "acquire",
      { status: 200, body: `<html>${BODY_SENTINEL}</html>` },
      "CREDENTIAL_ACQUIRE_FAILED",
      false,
      "contract",
    ],
    ["revoke", { status: 403 }, "CREDENTIAL_DENIED", false, "denied"],
    [
      "revoke",
      { status: 429, retryAfter: 7 },
      "CREDENTIAL_REVOKED",
      true,
      "rate-limited",
      7_000,
    ],
    [
      "revoke",
      { status: 429, retryAfter: "date" },
      "CREDENTIAL_REVOKED",
      true,
      "rate-limited",
      "date",
    ],
    [
      "revoke",
      { status: 503, retryAfter: 5 },
      "CREDENTIAL_REVOKED",
      true,
      "unavailable",
      5_000,
    ],
    [
      "revoke",
      { status: 502, body: `<html><body>${BODY_SENTINEL}</body></html>` },
      "CREDENTIAL_REVOKED",
      true,
      "unavailable",
    ],
    ["revoke", { status: 400 }, "CREDENTIAL_REVOKED", false, "rejected"],
  ] as const;
  it.each(statusRows)(
    "%s: maps %j to %s (retryable %s, %s)",
    async (operation, fault, code, retryable, reason, wait?: unknown) => {
      const knobs = services.knobs as Record<string, unknown[]>;
      knobs[`${operation === "acquire" ? "broker" : "revoke"}Faults`]?.push({
        body: { error: "failure", credential: BODY_SENTINEL },
        ...fault,
        ...(fault.retryAfter === "date"
          ? { retryAfter: inThirtySeconds() }
          : {}),
      });
      const error = await failure(call[operation](broker()));
      expect(error).toBeInstanceOf(PiShipError);
      expect(error).toMatchObject({
        code,
        retryable,
        component: "credential",
        sanitizedDetail: { operation, reason, status: fault.status },
      });
      if (wait === "date") {
        // An HTTP-date is whole seconds, so allow for rounding and elapsed time.
        expect(error.retryAfterMs).toBeGreaterThan(20_000);
        expect(error.retryAfterMs).toBeLessThanOrEqual(30_000);
      } else expect(error.retryAfterMs).toBe(wait);
      expectNoSecret(error);
    },
  );

  it.each([401, 404])(
    "revoke: treats %i as already revoked",
    async (status) => {
      services.knobs.revokeFaults.push({ status });
      await expect(broker().revoke(issued, ctx)).resolves.toBeUndefined();
    },
  );

  it.each(["acquire", "revoke"] as const)(
    "%s: times out retryably, bounded by timeoutMs",
    async (operation) => {
      Object.assign(services.knobs, {
        [`${operation === "acquire" ? "broker" : "revoke"}TimeoutMs`]: 5_000,
      });
      const started = Date.now();
      const error = await failure(call[operation](broker({ timeoutMs: 100 })));
      expect(Date.now() - started).toBeLessThan(2_000);
      expect(error).toMatchObject({
        code:
          operation === "acquire"
            ? "CREDENTIAL_ACQUIRE_FAILED"
            : "CREDENTIAL_REVOKED",
        retryable: true,
        sanitizedDetail: { operation, reason: "timeout" },
        message: expect.stringContaining("did not respond in time"),
      });
      expectNoSecret(error);
    },
  );

  // Regression: a caller signal used to replace the timeout, so a request
  // with a signal that never fired could hang forever.
  it.each(["acquire", "revoke"] as const)(
    "%s: keeps the timeout when the caller also passes a signal",
    async (operation) => {
      Object.assign(services.knobs, {
        [`${operation === "acquire" ? "broker" : "revoke"}TimeoutMs`]: 5_000,
      });
      const quiet = new AbortController();
      const started = Date.now();
      const error = await failure(
        call[operation](broker({ timeoutMs: 100 }), {
          ...ctx,
          signal: quiet.signal,
        }),
      );
      expect(Date.now() - started).toBeLessThan(2_000);
      expect(quiet.signal.aborted).toBe(false);
      expect(error).toMatchObject({
        retryable: true,
        sanitizedDetail: { operation, reason: "timeout" },
      });
      expectNoSecret(error);
    },
  );

  it.each(["acquire", "revoke"] as const)(
    "%s: reports a caller cancellation as cancelled, not retryable",
    async (operation) => {
      Object.assign(services.knobs, {
        [`${operation === "acquire" ? "broker" : "revoke"}TimeoutMs`]: 5_000,
      });
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 50);
      const error = await failure(
        call[operation](broker(), { ...ctx, signal: controller.signal }),
      );
      expect(error).toMatchObject({
        code:
          operation === "acquire"
            ? "CREDENTIAL_ACQUIRE_FAILED"
            : "CREDENTIAL_REVOKED",
        retryable: false,
        sanitizedDetail: { operation, reason: "cancelled" },
        message: expect.stringContaining("cancelled"),
      });
      expectNoSecret(error);
      // A signal that is already aborted never reaches the broker.
      const before = services.state.requests.length;
      const early = await failure(
        call[operation](broker(), { ...ctx, signal: AbortSignal.abort() }),
      );
      expect(early).toMatchObject({
        retryable: false,
        sanitizedDetail: { reason: "cancelled" },
      });
      expect(services.state.requests.length).toBe(before);
    },
  );

  it.each(["acquire", "revoke"] as const)(
    "%s: reports an unreachable broker as a retryable transport failure",
    async (operation) => {
      const provider = broker();
      await services.close();
      const error = await failure(call[operation](provider));
      expect(error).toMatchObject({
        retryable: true,
        sanitizedDetail: { operation, reason: "unreachable" },
      });
      expectNoSecret(error);
      services = await startLocalServices();
    },
  );

  // Regression: revoke used to call fetch directly, so a transport failure
  // escaped as an uncoded error.
  it("routes revoke through the broker transport", async () => {
    const error = await failure(
      broker({
        fetch: async () => {
          throw new TypeError("fetch failed");
        },
      }).revoke(issued, ctx),
    );
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({
      code: "CREDENTIAL_REVOKED",
      retryable: true,
      sanitizedDetail: { operation: "revoke", reason: "unreachable" },
    });
    expectNoSecret(error);
  });

  // Invalid configuration is not a transient failure: a network or TLS
  // policy refusal keeps its own code and is never marked retryable.
  it.each(["acquire", "revoke"] as const)(
    "%s: keeps network and TLS policy refusals",
    async (operation) => {
      for (const code of ["NETWORK_DENIED", "TLS_POLICY_VIOLATION"] as const) {
        const error = await failure(
          call[operation](
            broker({
              fetch: async () => {
                throw new PiShipError(code, "refused by policy");
              },
            }),
          ),
        );
        expect(error).toMatchObject({ code, retryable: false });
        expectNoSecret(error);
      }
    },
  );
});

function fakeProvider(
  options: {
    expiresInSeconds?: number;
    failRefresh?: boolean;
    refreshError?: Error;
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
      if (options.refreshError) throw options.refreshError;
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
  it("does not keep using a credential whose early renewal the broker denied", async () => {
    const denied = new PiShipError(
      "CREDENTIAL_DENIED",
      "The credential broker denied the request",
      { component: "credential" },
    );
    const provider = fakeProvider({
      expiresInSeconds: 1,
      refreshError: denied,
    });
    const { manager: credentials } = manager(provider);
    await credentials.ensure(null, ctx, { allowAcquire: true });
    // Still valid, inside the renewal window: an outage would continue.
    expect(credentials.status().state).toBe("expiring");
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_DENIED", retryable: false });
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
  it("never breaks a fresh lock; it fails retryably after the wait", async () => {
    const path = join(temp, "held.json");
    const lock = `${path}.lock`;
    writeFileSync(lock, "");
    // Another live holder keeps the lock fresh.
    const holder = setInterval(() => {
      const now = new Date();
      utimesSync(lock, now, now);
    }, 20);
    let ran = false;
    try {
      const error = await withFileLock(
        path,
        async () => {
          ran = true;
        },
        { staleMs: 150, waitMs: 400 },
      ).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(PiShipError);
      expect(error).toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
        retryable: true,
      });
      expect((error as Error).message).toMatch(
        /Another process is still updating held\.json/,
      );
    } finally {
      clearInterval(holder);
    }
    expect(ran).toBe(false);
    expect(existsSync(lock)).toBe(true);
  });
  it("breaks a stale lock without leaving files and releases only its own lock", async () => {
    const path = join(temp, "stale.json");
    const lock = `${path}.lock`;
    writeFileSync(lock, "crashed-holder");
    const old = new Date(Date.now() - 10 * 60_000);
    utimesSync(lock, old, old);
    await withFileLock(path, async () => {
      expect(readFileSync(lock, "utf8")).not.toBe("crashed-holder");
      // Blocking secret-store commands touch the held lock first.
      utimesSync(lock, old, old);
      touchHeldLocks();
      expect(Date.now() - statSync(lock).mtimeMs).toBeLessThan(10_000);
      // Another process took the lock over; it is not ours to remove.
      writeFileSync(lock, "another-holder");
    });
    expect(readFileSync(lock, "utf8")).toBe("another-holder");
    expect(readdirSync(temp).filter((name) => name.endsWith(".stale"))).toEqual(
      [],
    );
  });
  it("keeps its own lock fresh while a long task runs", async () => {
    const path = join(temp, "long.json");
    const order: string[] = [];
    const timing = { heartbeatMs: 20, staleMs: 150, waitMs: 2_000 };
    const first = withFileLock(
      path,
      async () => {
        order.push("first:start");
        await new Promise((resolve) => setTimeout(resolve, 500));
        order.push("first:end");
      },
      timing,
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    await withFileLock(
      path,
      async () => {
        order.push("second");
      },
      timing,
    );
    await first;
    expect(order).toEqual(["first:start", "first:end", "second"]);
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

describe("credential lifecycle events", () => {
  function eventsManager(
    provider: CredentialProvider,
    store = new MemorySecretStore(),
  ) {
    const events: CredentialEvent[] = [];
    const manager = new CredentialManager({
      distributionId: "acmecode",
      provider,
      store,
      metadataPath: join(temp, "credentials-metadata", "inference.json"),
      beforeExpirySeconds: 300,
      onEvent: (event) => events.push(event),
    });
    return { events, manager, store };
  }

  it("emits acquire only when acquired, refresh on renewal, and revoke with its outcome", async () => {
    const revoked: string[] = [];
    const provider = fakeProvider({ expiresInSeconds: 3600, revoked });
    const { events, manager: credentials } = eventsManager(provider);
    await credentials.ensure(null, ctx, { allowAcquire: true });
    // Reusing the stored credential is not an acquisition.
    await credentials.ensure(null, ctx, { allowAcquire: true });
    await credentials.ensure(null, ctx, { allowAcquire: false });
    expect(events.map((item) => item.event)).toEqual(["credential.acquire"]);
    expect(events[0]?.detail).toEqual({
      mode: "http-broker",
      kind: "api_key",
      generation: 1,
      credentialId: "vk_1",
      expiresAt: expect.any(String),
    });
    await credentials.ensure(null, ctx, {
      allowAcquire: false,
      forceRefresh: true,
    });
    expect(events.at(-1)).toMatchObject({
      event: "credential.refresh",
      detail: { reason: "rejected", generation: 2, credentialId: "vk_2" },
    });
    expect(await credentials.logout(ctx)).toEqual([]);
    expect(events.at(-1)).toEqual({
      event: "credential.revoke",
      detail: {
        mode: "http-broker",
        generation: 2,
        credentialId: "vk_2",
        reason: "logout",
        revocation: "revoked",
      },
    });
    expect(JSON.stringify(events)).not.toContain("sk-generation");
    // No credential, no revoke event.
    await credentials.logout(ctx);
    expect(events).toHaveLength(3);
  });

  it("reports expiring renewals and a missing, failing, or unsupported revocation", async () => {
    const expiring = eventsManager(fakeProvider({ expiresInSeconds: 120 }));
    await expiring.manager.ensure(null, ctx, { allowAcquire: true });
    await expiring.manager.ensure(null, ctx, { allowAcquire: false });
    expect(expiring.events.at(-1)).toMatchObject({
      event: "credential.refresh",
      detail: { reason: "expiring", generation: 2 },
    });
    rmSync(join(temp, "credentials-metadata"), { recursive: true });

    const failing = eventsManager({
      ...fakeProvider({ expiresInSeconds: 3600 }),
      async revoke() {
        throw new Error("revoke endpoint returned HTTP 503");
      },
    });
    await failing.manager.ensure(null, ctx, { allowAcquire: true });
    expect(await failing.manager.logout(ctx)).toEqual([
      "revocation: revoke endpoint returned HTTP 503",
    ]);
    expect(failing.events.at(-1)?.detail).toMatchObject({
      revocation: "failed",
    });
    // Local clearing still happened.
    expect(failing.store.refs()).toEqual([]);

    const noRevoke: Partial<ReturnType<typeof fakeProvider>> = fakeProvider({
      expiresInSeconds: 3600,
    });
    delete noRevoke.revoke;
    const unsupported = eventsManager(noRevoke as CredentialProvider);
    await unsupported.manager.ensure(null, ctx, { allowAcquire: true });
    expect(unsupported.manager.revocable).toBe(false);
    await unsupported.manager.logout(ctx);
    expect(unsupported.events.at(-1)?.detail).toMatchObject({
      revocation: "unsupported",
    });
    const broker = new HttpBrokerCredentialProvider({
      endpoint: "https://broker.example/v1",
      fetch: createManagedFetch(DEFAULT_NETWORK_POLICY, "test"),
    });
    expect(broker.revocable).toBe(false);
    expect(
      new HttpBrokerCredentialProvider({
        ...broker.options,
        revokeEndpoint: "https://broker.example/v1/revoke",
      }).revocable,
    ).toBe(true);
  });

  it("revokes without clearing for lifecycle callers", async () => {
    const revoked: string[] = [];
    const {
      events,
      manager: credentials,
      store,
    } = eventsManager(fakeProvider({ expiresInSeconds: 3600, revoked }));
    expect(await credentials.revoke(ctx, "lifecycle")).toEqual({
      outcome: "absent",
    });
    await credentials.ensure(null, ctx, { allowAcquire: true });
    expect(await credentials.revoke(ctx, "lifecycle")).toEqual({
      outcome: "revoked",
    });
    expect(revoked).toEqual(["vk_1"]);
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
    expect(events.at(-1)?.detail).toMatchObject({
      reason: "lifecycle",
      revocation: "revoked",
    });
  });

  it("keeps a specific failure code when a forced renewal fails", async () => {
    let failure: Error = new Error("unused");
    const provider = {
      ...fakeProvider({ expiresInSeconds: 3600 }),
      async refresh(): Promise<RuntimeCredential> {
        throw failure;
      },
    };
    const { manager: credentials } = eventsManager(provider);
    await credentials.ensure(null, ctx, { allowAcquire: true });
    // Actionable codes pass through: sign in again, or fix the network policy.
    for (const code of ["IDENTITY_EXPIRED", "NETWORK_DENIED"] as const) {
      failure = new PiShipError(code, "specific failure");
      await expect(
        credentials.ensure(null, ctx, {
          allowAcquire: false,
          forceRefresh: true,
        }),
      ).rejects.toMatchObject({ code });
    }
    // A generic acquisition failure becomes CREDENTIAL_REVOKED.
    failure = new PiShipError("CREDENTIAL_ACQUIRE_FAILED", "broker 503");
    await expect(
      credentials.ensure(null, ctx, {
        allowAcquire: false,
        forceRefresh: true,
      }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REVOKED" });
    // An authorization denial is not a lost credential: it passes through.
    failure = new PiShipError("CREDENTIAL_DENIED", "denied");
    await expect(
      credentials.ensure(null, ctx, {
        allowAcquire: false,
        forceRefresh: true,
      }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_DENIED", retryable: false });
  });

  // Regression: a failed renewal used to drop retryable and retryAfterMs, so
  // a broker outage or rate limit read as "sign in again".
  it("keeps the retry contract when a renewal fails", async () => {
    let failure: unknown = new Error("unused");
    const provider = {
      ...fakeProvider({ expiresInSeconds: 60 }),
      async refresh(): Promise<RuntimeCredential> {
        throw failure;
      },
    };
    let now = Date.now();
    const credentials = new CredentialManager({
      distributionId: "acmecode",
      provider,
      store: new MemorySecretStore(),
      metadataPath: join(temp, "credentials-metadata", "inference.json"),
      beforeExpirySeconds: 300,
      now: () => now,
    });
    const first = await credentials.ensure(null, ctx, { allowAcquire: true });
    const secret = first.secret?.reveal() ?? "missing";
    const renew = (forceRefresh: boolean) =>
      credentials.ensure(null, ctx, { allowAcquire: false, forceRefresh }).then(
        () => {
          throw new Error("expected a failure");
        },
        (error: unknown) => error as PiShipError,
      );
    const limited = new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "The credential broker is rate limiting requests",
      {
        retryable: true,
        retryAfterMs: 7_000,
        sanitizedDetail: {
          operation: "acquire",
          reason: "rate-limited",
          status: 429,
        },
      },
    );
    failure = limited;
    const rejected = await renew(true);
    expect(rejected).toMatchObject({
      code: "CREDENTIAL_REVOKED",
      retryable: true,
      retryAfterMs: 7_000,
      sanitizedDetail: { reason: "rate-limited", status: 429 },
      userAction: expect.stringContaining("Try again later"),
    });
    now += 120_000;
    expect(credentials.status().state).toBe("expired");
    const expired = await renew(false);
    expect(expired).toMatchObject({
      code: "CREDENTIAL_EXPIRED",
      retryable: true,
      retryAfterMs: 7_000,
    });
    // Without a retry signal the renewal failure stays fail-closed.
    failure = new PiShipError("CREDENTIAL_ACQUIRE_FAILED", "contract");
    expect(await renew(false)).toMatchObject({
      code: "CREDENTIAL_EXPIRED",
      retryable: false,
      retryAfterMs: undefined,
      userAction: "Run the branded login command",
    });
    failure = new Error("adapter crashed");
    expect(await renew(true)).toMatchObject({
      code: "CREDENTIAL_REVOKED",
      retryable: false,
    });
    for (const error of [rejected, expired]) {
      expect(inspect(error, { depth: 10, showHidden: true })).not.toContain(
        secret,
      );
      expect(JSON.stringify(error)).not.toContain(secret);
    }
  });

  it("keeps the broker's retry contract through a real renewal", async () => {
    const services = await startLocalServices();
    try {
      const token = `demo-at-renewal-${Date.now()}`;
      services.state.accessTokens.set(token, {
        subject: "demo-user-1",
        expires: Math.floor(Date.now() / 1000) + 600,
      });
      const identity: IdentitySession = {
        subject: "demo-user-1",
        issuer: services.issuer,
        accessToken: new SecretValue(token),
      };
      const credentials = new CredentialManager({
        distributionId: "acmecode",
        provider: new HttpBrokerCredentialProvider({
          endpoint: services.brokerUrl,
          revokeEndpoint: services.revokeUrl,
          fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
        }),
        store: new MemorySecretStore(),
        metadataPath: join(temp, "renewal", "inference.json"),
        beforeExpirySeconds: 300,
      });
      const active = await credentials.ensure(identity, ctx, {
        allowAcquire: true,
      });
      services.knobs.brokerFaults.push({ status: 503, retryAfter: 11 });
      const error = await credentials
        .ensure(identity, ctx, { allowAcquire: false, forceRefresh: true })
        .catch((caught: unknown) => caught as PiShipError);
      expect(error).toMatchObject({
        code: "CREDENTIAL_REVOKED",
        retryable: true,
        retryAfterMs: 11_000,
        sanitizedDetail: {
          operation: "acquire",
          reason: "unavailable",
          status: 503,
        },
      });
      const rendered = inspect(error, { depth: 10, showHidden: true });
      expect(rendered).not.toContain(token);
      expect(rendered).not.toContain(active.secret?.reveal() ?? "missing");
    } finally {
      await services.close();
    }
  });
});

describe("secret normalization", () => {
  const adapter = (secret: unknown, extra: Record<string, unknown> = {}) =>
    ({
      mode: "adapter",
      requiresIdentity: false,
      async acquire() {
        return { kind: "api_key", secret, ...extra };
      },
    }) as unknown as CredentialProvider;
  const manager = (provider: CredentialProvider) =>
    new CredentialManager({
      distributionId: "acmecode",
      provider,
      store: new MemorySecretStore(),
      metadataPath: join(temp, "credentials-metadata", "inference.json"),
      beforeExpirySeconds: 300,
    });

  it.each([
    ["a plain string", "sk-adapter-plain-string-secret"],
    [
      "a foreign SecretValue-like object",
      { reveal: () => "sk-adapter-plain-string-secret" },
    ],
  ])(
    "re-wraps %s so the active credential never serializes the secret",
    async (_name, secret) => {
      const active = await manager(adapter(secret)).ensure(null, ctx, {
        allowAcquire: true,
      });
      expect(active.secret).toBeInstanceOf(SecretValue);
      expect(active.secret?.reveal()).toBe("sk-adapter-plain-string-secret");
      expect(JSON.stringify(active)).not.toContain("sk-adapter");
      expect(inspect(active, { depth: 10 })).not.toContain("sk-adapter");
      expect(String(active.secret)).toBe("[REDACTED]");
    },
  );

  it("rejects a credential without a usable secret, kind, or expiry", async () => {
    for (const provider of [
      adapter(undefined),
      adapter(""),
      adapter({ reveal: () => 42 }),
      adapter("sk-valid-secret-000", { kind: "password" }),
      adapter("sk-valid-secret-000", { expiresAt: "not a date" }),
    ]) {
      rmSync(join(temp, "credentials-metadata"), {
        recursive: true,
        force: true,
      });
      await expect(
        manager(provider).ensure(null, ctx, { allowAcquire: true }),
      ).rejects.toMatchObject({ code: "CREDENTIAL_ACQUIRE_FAILED" });
    }
    expect(toSecretValue("sk-direct-value")).toBeInstanceOf(SecretValue);
  });
});

describe("secret references", () => {
  it("lists every reference metadata may own, only in its own namespace", () => {
    expect(
      metadataSecretRefs(
        {
          credential_ref: "piship:acmecode:inference#4",
          generation: 4,
          orphans: [
            "piship:acmecode:inference#2",
            "piship:other:inference#1",
            "keychain:unrelated",
          ],
        },
        "acmecode",
      ),
    ).toEqual([
      "piship:acmecode:inference#2",
      "piship:acmecode:inference#4",
      "piship:acmecode:inference#5",
    ]);
    expect(
      metadataSecretRefs(
        { secretRef: "piship:acmecode:identity#3" },
        "acmecode",
      ),
    ).toEqual([
      "piship:acmecode:identity#2",
      "piship:acmecode:identity#3",
      "piship:acmecode:identity#4",
    ]);
    expect(metadataSecretRefs(null, "acmecode")).toEqual([]);
    expect(
      metadataSecretRefs({ secretRef: "piship:other:identity#1" }, "acmecode"),
    ).toEqual([]);
  });

  it("logout clears orphaned and pending generations of unreadable metadata", async () => {
    const store = new MemorySecretStore();
    for (const ref of [
      "piship:acmecode:inference#3",
      "piship:acmecode:inference#4",
      "piship:acmecode:inference#5",
      "piship:other:inference#1",
    ])
      await store.put(ref, new SecretValue(`sk-${ref.replace(/\W/g, "")}`));
    const path = join(temp, "credentials-metadata", "inference.json");
    const credentials = new CredentialManager({
      distributionId: "acmecode",
      provider: fakeProvider(),
      store,
      metadataPath: path,
      beforeExpirySeconds: 300,
    });
    mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
    writeFileSync(
      path,
      JSON.stringify({
        schema: "piship-credential-metadata/v9",
        credential_ref: "piship:acmecode:inference#4",
        generation: 4,
        orphans: ["piship:acmecode:inference#3"],
      }),
    );
    await credentials.logout(ctx);
    expect(store.refs()).toEqual(["piship:other:inference#1"]);
    expect(existsSync(path)).toBe(false);
  });
});

describe("Windows file fallback permissions", () => {
  const directory = () => join(temp, "state dir", "secrets");
  const secret = new SecretValue("sk-windows-file-secret");

  it("applies an owner-only ACL through icacls before writing", async () => {
    const { calls, runner } = recordingRunner({});
    const store = new RestrictedFileSecretStore(directory(), {
      platform: "win32",
      run: runner,
      account: "CORP\\dev user",
    });
    await store.put("piship:x:inference#1", secret);
    await store.put("piship:x:inference#2", secret);
    expect(calls).toEqual([
      {
        command: "icacls",
        args: [
          directory(),
          "/inheritance:r",
          "/grant:r",
          "CORP\\dev user:(OI)(CI)F",
        ],
        stdin: "",
      },
    ]);
    expect((await store.get("piship:x:inference#1"))?.reveal()).toBe(
      secret.reveal(),
    );
    for (const call of calls)
      expect(call.args.join(" ")).not.toContain(secret.reveal());
  });

  it("fails closed when the ACL cannot be applied or the account is unknown", async () => {
    const { runner } = recordingRunner({
      icacls: { status: 5, stderr: "Access is denied." },
    });
    const store = new RestrictedFileSecretStore(directory(), {
      platform: "win32",
      run: runner,
      account: "CORP\\dev",
    });
    const error = await store
      .put("piship:x:inference#1", secret)
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
      message: expect.stringContaining("Access is denied"),
    });
    expect(readdirSync(directory())).toEqual([]);
    const previous = process.env.USERNAME;
    delete process.env.USERNAME;
    try {
      await expect(
        new RestrictedFileSecretStore(directory(), {
          platform: "win32",
          run: recordingRunner({}).runner,
        }).put("piship:x:inference#1", secret),
      ).rejects.toMatchObject({
        code: "SECRET_STORE_UNAVAILABLE",
        message: expect.stringContaining("USERNAME"),
      });
    } finally {
      if (previous !== undefined) process.env.USERNAME = previous;
    }
  });

  it("passes the platform and runner through selection and keeps POSIX modes elsewhere", async () => {
    const { calls, runner } = recordingRunner({});
    const previous = process.env.USERNAME;
    process.env.USERNAME = "tester";
    try {
      const store = createSecretStore({
        provider: "file",
        fileDirectory: directory(),
        platform: "win32",
        run: runner,
      });
      await store.put("piship:x:inference#1", secret);
    } finally {
      if (previous === undefined) delete process.env.USERNAME;
      else process.env.USERNAME = previous;
    }
    expect(calls.map((call) => call.command)).toEqual(["icacls"]);
    if (process.platform !== "win32") {
      const posix = recordingRunner({});
      const other = new RestrictedFileSecretStore(join(temp, "posix"), {
        platform: "linux",
        run: posix.runner,
      });
      await other.put("piship:x:inference#1", secret);
      expect(posix.calls).toEqual([]);
      expect(statSync(join(temp, "posix")).mode & 0o777).toBe(0o700);
    }
  });
});
