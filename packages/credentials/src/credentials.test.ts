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
  CREDENTIAL_DISCARDED_SCHEMA,
  CREDENTIAL_METADATA_SCHEMA,
  type CredentialEvent,
  CredentialManager,
  HttpBrokerCredentialProvider,
  LocalSecretCredentialProvider,
  MacKeychainSecretStore,
  MemorySecretStore,
  NoCredentialProvider,
  PiNativeCredentialProvider,
  REVOCATION_RETRY_SCHEMA,
  readPendingRevocations,
  RestrictedFileSecretStore,
  SecretServiceSecretStore,
  WindowsCredentialSecretStore,
  createSecretStore,
  metadataSecretRefs,
  toSecretValue,
  isLockTimeout,
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
      for (const control of [
        "\r",
        "\n",
        "\0",
        "\t",
        "\x1b",
        "\x7f",
        " ",
        "é",
      ]) {
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
      for (const control of [
        "\r",
        "\n",
        "\0",
        "\t",
        "\x1b",
        "\x7f",
        " ",
        "é",
      ]) {
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

    it("refuses a credential ID outside the broker contract", async () => {
      const answer = await realAnswer();
      for (const id of ["vk_demo.1:a-b", "x".repeat(256)])
        await expect(
          broker({
            fetch: async () => json({ ...answer, credential_id: id }),
          }).acquire(identity, ctx),
        ).resolves.toMatchObject({ credentialId: id });
      for (const id of [
        "",
        "vk demo",
        "vk\n1",
        "vk/../1",
        "vk_é",
        "x".repeat(257),
        7,
      ]) {
        const error = await failure(
          call.acquire(
            broker({
              fetch: async () => json({ ...answer, credential_id: id }),
            }),
          ),
        );
        expect(error).toMatchObject({
          code: "CREDENTIAL_ACQUIRE_FAILED",
          sanitizedDetail: { reason: "contract" },
        });
      }
    });

    it("refuses a credential the broker issued for another subject, and accepts its own", async () => {
      const answer = await realAnswer();
      await expect(
        broker({
          fetch: async () => json({ ...answer, subject: identity.subject }),
        }).acquire(identity, ctx),
      ).resolves.toBeDefined();
      for (const subject of ["someone-else", 42, null]) {
        const error = await failure(
          call.acquire(
            broker({ fetch: async () => json({ ...answer, subject }) }),
          ),
        );
        expect(error, String(subject)).toMatchObject({
          code: "CREDENTIAL_ACQUIRE_FAILED",
          sanitizedDetail: { reason: "contract" },
        });
        expectNoSecret(error);
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

describe("http-broker idempotency and retry", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  let identity: IdentitySession;
  const UUID =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  /** An active access token for `subject` at the fixture identity provider. */
  function signIn(subject: string): IdentitySession {
    const token = `demo-at-${subject}-${Math.random().toString(36).slice(2)}`;
    services.state.accessTokens.set(token, {
      subject,
      expires: Math.floor(Date.now() / 1000) + 600,
    });
    return {
      subject,
      issuer: services.issuer,
      accessToken: new SecretValue(token),
    };
  }
  beforeEach(async () => {
    services = await startLocalServices({ knobs: { brokerIdempotency: true } });
    identity = signIn("demo-user-1");
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
  const manager = (provider: CredentialProvider = broker()) =>
    new CredentialManager({
      distributionId: "acmecode",
      provider,
      store: new MemorySecretStore(),
      metadataPath: join(temp, "credentials-metadata", "inference.json"),
      beforeExpirySeconds: 300,
    });
  const brokerRequests = () =>
    services.state.requests.filter(
      (item: { path: string }) => item.path === "/broker/v1/llm-credential",
    ).length;
  const failure = (promise: Promise<unknown>) =>
    promise.then(
      () => {
        throw new Error("expected a failure");
      },
      (error: unknown) => error as PiShipError,
    );
  /**
   * No identity token and no credential the broker ever issued, including
   * one whose answer was lost, appears in any rendering of the error.
   */
  function expectNoSecret(error: unknown, ...tokens: IdentitySession[]): void {
    const renderings = [
      String(error),
      JSON.stringify(error),
      inspect(error, { depth: 10, showHidden: true }),
    ].join("\n");
    for (const session of [identity, ...tokens])
      expect(renderings).not.toContain(session.accessToken?.reveal());
    for (const issued of services.state.credentials.keys())
      expect(renderings).not.toContain(issued);
  }

  it("sends one random key per logical acquire, never derived from the identity", async () => {
    const credentials = manager();
    await credentials.ensure(identity, ctx, { allowAcquire: true });
    // Reusing the stored credential sends nothing.
    await credentials.ensure(identity, ctx, { allowAcquire: false });
    await credentials.ensure(identity, ctx, {
      allowAcquire: false,
      forceRefresh: true,
    });
    const keys: string[] = services.state.idempotencyKeys;
    expect(keys).toHaveLength(2);
    for (const key of keys) {
      expect(key).toMatch(UUID);
      expect(key).not.toContain(identity.subject);
      expect(identity.accessToken?.reveal()).not.toContain(key);
    }
    expect(keys[0]).not.toBe(keys[1]);
    // A provider called directly with no key sends no header.
    await broker().acquire(identity, ctx);
    expect(services.state.idempotencyKeys).toHaveLength(2);
    expect(brokerRequests()).toBe(3);
  });

  it("does not re-issue an acquire that timed out after the broker issued a credential", async () => {
    // The broker issues the credential, then the answer never arrives.
    Object.assign(services.knobs, {
      brokerTimeoutMs: 5_000,
      brokerTimeoutServes: true,
    });
    const credentials = manager(broker({ timeoutMs: 200 }));
    const error = await failure(
      credentials.ensure(identity, ctx, { allowAcquire: true }),
    );
    expect(error).toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
      sanitizedDetail: {
        operation: "acquire",
        reason: "timeout",
        outcome: "unknown",
        idempotencyKey: expect.stringMatching(UUID),
      },
    });
    // Exactly one request left PiShip, and nothing was stored locally.
    expect(brokerRequests()).toBe(1);
    expect(services.state.credentialCount).toBe(1);
    expect(credentials.status().state).toBe("absent");
    expectNoSecret(error);

    // The caller retries the same acquire with the reported key and gets
    // the credential the broker already issued, not a second one.
    Object.assign(services.knobs, { brokerTimeoutMs: 0 });
    const key = String(error.sanitizedDetail?.idempotencyKey);
    const retried = await credentials.ensure(
      identity,
      { ...ctx, idempotencyKey: key },
      { allowAcquire: true },
    );
    expect(services.state.credentialCount).toBe(1);
    expect(retried.ref?.credentialId).toBe("vk_demo_1");
    expect(services.state.credentials.has(retried.secret?.reveal())).toBe(true);
    expect(services.state.idempotencyKeys).toEqual([key, key]);
  });

  it.each([
    [
      "a connection reset after the broker issued a credential",
      { brokerTimeoutMs: 50, brokerTimeoutServes: true },
      "unreachable",
      "unknown",
      true,
    ],
    [
      "a 503 with Retry-After",
      { brokerStatus: 503, brokerRetryAfter: 3 },
      "unavailable",
      undefined,
      true,
    ],
    [
      "a 429 with Retry-After",
      { brokerStatus: 429, brokerRetryAfter: 3 },
      "rate-limited",
      undefined,
      true,
    ],
    ["a 401", { brokerStatus: 401 }, "authentication", undefined, false],
  ])(
    "sends an acquire once after %s",
    async (_name, knobs, reason, outcome, retryable) => {
      Object.assign(services.knobs, knobs);
      const credentials = manager(broker({ timeoutMs: 5_000 }));
      const error = await failure(
        credentials.ensure(identity, ctx, { allowAcquire: true }),
      );
      expect(error).toMatchObject({
        retryable,
        sanitizedDetail: {
          operation: "acquire",
          reason,
          idempotencyKey: expect.stringMatching(UUID),
          ...(outcome ? { outcome } : {}),
        },
      });
      if (!outcome) expect(error.sanitizedDetail).not.toHaveProperty("outcome");
      expect(brokerRequests()).toBe(1);
      expectNoSecret(error);
    },
  );

  it("replays the original credential for a repeated key and the same input", async () => {
    const provider = broker();
    const keyed = { ...ctx, idempotencyKey: "retry-key-1" };
    const first = await provider.acquire(identity, keyed);
    const second = await provider.acquire(identity, keyed);
    expect(second.secret.reveal()).toBe(first.secret.reveal());
    expect(second.credentialId).toBe(first.credentialId);
    expect(services.state.credentialCount).toBe(1);
    // A renewed identity token of the same user is the same input.
    const renewed = signIn("demo-user-1");
    const third = await provider.acquire(renewed, keyed);
    expect(third.credentialId).toBe(first.credentialId);
    expect(services.state.credentialCount).toBe(1);
  });

  it("rejects a replayed key with different input as a non-retryable conflict", async () => {
    const provider = broker();
    const keyed = { ...ctx, idempotencyKey: "retry-key-2" };
    const original = await provider.acquire(identity, keyed);
    const bob = signIn("demo-user-2");
    for (const [session, context] of [
      // Another distribution, same user.
      [identity, { ...keyed, distributionId: "othercode" }],
      // Another user, same distribution: never the first user's credential.
      [bob, keyed],
    ] as const) {
      const error = await failure(provider.acquire(session, context));
      expect(error).toBeInstanceOf(PiShipError);
      expect(error).toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
        retryable: false,
        component: "credential",
        sanitizedDetail: {
          operation: "acquire",
          reason: "idempotency-conflict",
          status: 409,
          idempotencyKey: "retry-key-2",
        },
      });
      expect(inspect(error, { depth: 10, showHidden: true })).not.toContain(
        original.secret.reveal(),
      );
      expectNoSecret(error, bob);
    }
    expect(services.state.credentialCount).toBe(1);

    // Through the manager, a conflict stores nothing.
    const credentials = manager();
    await expect(
      credentials.ensure(bob, keyed, { allowAcquire: true }),
    ).rejects.toMatchObject({
      sanitizedDetail: { reason: "idempotency-conflict" },
    });
    expect(credentials.status().state).toBe("absent");
  });

  it("reads 409 and 422 as a key conflict only when the acquire sent a key", async () => {
    for (const status of [409, 422]) {
      services.knobs.brokerFaults.push({ status }, { status });
      await expect(
        broker().acquire(identity, { ...ctx, idempotencyKey: "retry-key-3" }),
      ).rejects.toMatchObject({
        retryable: false,
        sanitizedDetail: { reason: "idempotency-conflict", status },
      });
      await expect(broker().acquire(identity, ctx)).rejects.toMatchObject({
        retryable: false,
        sanitizedDetail: { reason: "rejected", status },
      });
    }
  });

  it("refuses a malformed caller key before anything is sent", async () => {
    const before = brokerRequests();
    for (const key of ["", "has space", "line\r\nbreak", "k".repeat(256)]) {
      const error = await failure(
        broker().acquire(identity, { ...ctx, idempotencyKey: key }),
      );
      expect(error).toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
        retryable: false,
        sanitizedDetail: { operation: "acquire", reason: "contract" },
      });
      expect(error.sanitizedDetail).not.toHaveProperty("idempotencyKey");
    }
    expect(brokerRequests()).toBe(before);
  });

  it("tells a request that was never sent from one whose outcome is unknown", async () => {
    const keyed = { ...ctx, idempotencyKey: "retry-key-4" };
    // Connection refused, through the managed fetch.
    const provider = broker();
    await services.close();
    await expect(provider.acquire(identity, keyed)).rejects.toMatchObject({
      retryable: true,
      sanitizedDetail: {
        reason: "unreachable",
        outcome: "not-sent",
        idempotencyKey: "retry-key-4",
      },
    });
    services = await startLocalServices({ knobs: { brokerIdempotency: true } });
    identity = signIn("demo-user-1");
    const transport = (code: string) =>
      broker({
        fetch: async () => {
          throw new TypeError("fetch failed", { cause: { code } });
        },
      }).acquire(identity, keyed);
    for (const code of ["ENOTFOUND", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT"])
      await expect(transport(code)).rejects.toMatchObject({
        sanitizedDetail: { reason: "unreachable", outcome: "not-sent" },
      });
    for (const code of ["ECONNRESET", "UND_ERR_SOCKET", "EPIPE"])
      await expect(transport(code)).rejects.toMatchObject({
        sanitizedDetail: { reason: "unreachable", outcome: "unknown" },
      });
    // Cancelled before sending, and cancelled while the broker works.
    await expect(
      broker().acquire(identity, { ...keyed, signal: AbortSignal.abort() }),
    ).rejects.toMatchObject({
      retryable: false,
      sanitizedDetail: { reason: "cancelled", outcome: "not-sent" },
    });
    services.knobs.brokerTimeoutMs = 5_000;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);
    await expect(
      broker().acquire(identity, { ...keyed, signal: controller.signal }),
    ).rejects.toMatchObject({
      retryable: false,
      sanitizedDetail: { reason: "cancelled", outcome: "unknown" },
    });
  });
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
    // A fixed clock: a slow machine must not run the credential out.
    const now = Date.now();
    const { manager: credentials } = manager(provider, { now: () => now });
    await credentials.ensure(null, ctx, { allowAcquire: true });
    // Still valid, inside the renewal window: an outage would continue.
    expect(credentials.status().state).toBe("expiring");
    await expect(
      credentials.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_DENIED", retryable: false });
  });
  it("refuses a credential ID outside the identifier alphabet, whichever provider issued it", async () => {
    for (const credentialId of [
      "key/1",
      "user@example.com",
      "a b",
      "x".repeat(257),
      "id\nline",
    ]) {
      const provider = {
        ...fakeProvider(),
        async acquire(): Promise<RuntimeCredential> {
          return {
            kind: "api_key",
            secret: new SecretValue("sk-adapter-issued-secret"),
            credentialId,
          };
        },
      };
      const { manager: credentials } = manager(provider);
      await expect(
        credentials.ensure(null, ctx, { allowAcquire: true }),
      ).rejects.toMatchObject({ code: "CREDENTIAL_ACQUIRE_FAILED" });
    }
    const ok = {
      ...fakeProvider(),
      async acquire(): Promise<RuntimeCredential> {
        return {
          kind: "api_key",
          secret: new SecretValue("sk-adapter-issued-secret"),
          credentialId: "vk_1.a:b-c",
        };
      },
    };
    await expect(
      manager(ok).manager.ensure(null, ctx, { allowAcquire: true }),
    ).resolves.toMatchObject({ ref: { credentialId: "vk_1.a:b-c" } });
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
    const { manager: credentials } = manager(provider, {
      lockTiming: { staleMs: 400, waitMs: 5_000 },
    });
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
      // Callers can tell a lock wait from any other failure.
      expect(isLockTimeout(error)).toBe(true);
      expect(
        isLockTimeout(new PiShipError("CREDENTIAL_ACQUIRE_FAILED", "x")),
      ).toBe(false);
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
    await withFileLock(
      path,
      async () => {
        expect(readFileSync(lock, "utf8")).not.toBe("crashed-holder");
        // Blocking secret-store commands touch the held lock first.
        utimesSync(lock, old, old);
        touchHeldLocks();
        expect(Date.now() - statSync(lock).mtimeMs).toBeLessThan(10_000);
        // Another process took the lock over; it is not ours to remove.
        writeFileSync(lock, "another-holder");
      },
      { staleMs: 150 },
    );
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

    // A secret store that cannot be read is a failed revocation the caller
    // sees, not a silent skip: the credential may still be live remotely.
    const unreadableStore = new MemorySecretStore();
    const unreadable = eventsManager(
      fakeProvider({ expiresInSeconds: 3600 }),
      unreadableStore,
    );
    await unreadable.manager.ensure(null, ctx, { allowAcquire: true });
    const lock = () => {
      unreadableStore.get = async () => {
        throw new PiShipError(
          "SECRET_STORE_UNAVAILABLE",
          "The keychain is locked",
        );
      };
    };
    const unlock = () => Reflect.deleteProperty(unreadableStore, "get");
    lock();
    // The deletion cannot be confirmed either: that is reported, never
    // taken as "absent", and the metadata stays as a discarded marker.
    expect(await unreadable.manager.logout(ctx)).toEqual([
      "revocation: the stored credential could not be read (SECRET_STORE_UNAVAILABLE)",
      expect.stringMatching(
        /^delete piship:acmecode:inference#1: SECRET_STORE_UNAVAILABLE/,
      ),
      expect.stringMatching(
        /^delete piship:acmecode:inference#2: SECRET_STORE_UNAVAILABLE/,
      ),
    ]);
    expect(unreadable.events.at(-1)?.detail).toMatchObject({
      revocation: "failed",
      retryPending: true,
    });
    expect(unreadable.manager.hasStoredCredential()).toBe(true);
    expect(unreadable.manager.status()).toMatchObject({ state: "absent" });
    unlock();
    await unreadable.manager.ensure(null, ctx, { allowAcquire: true });
    lock();
    await expect(
      unreadable.manager.revoke(ctx, "lifecycle"),
    ).resolves.toMatchObject({
      outcome: "failed",
      problem: expect.stringContaining("could not be read"),
    });
    rmSync(join(temp, "credentials-metadata"), { recursive: true });

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

  it("refuses a secret a request header cannot carry, before it is stored", async () => {
    for (const value of [
      "sk with space",
      "sk-tab\tvalue",
      "sk-line\nbreak",
      "sk-carriage\rreturn",
      "sk-nul\0value",
      "sk-escape\u001bvalue",
      "sk-del\u007fvalue",
      "sk-non-ascii-é",
    ]) {
      expect(() => toSecretValue(value)).toThrow(
        expect.objectContaining({
          code: "CREDENTIAL_ACQUIRE_FAILED",
          message: expect.stringContaining("only visible ASCII"),
        }),
      );
      // The message never quotes the secret.
      try {
        toSecretValue(value);
      } catch (error) {
        expect((error as Error).message).not.toContain(value);
      }
      // A secret already wrapped in SecretValue (a local key, an adapter that
      // imports the same contracts package) is held to the same rule.
      expect(() => toSecretValue(new SecretValue(value))).toThrow(
        expect.objectContaining({ code: "CREDENTIAL_ACQUIRE_FAILED" }),
      );
    }
    expect(toSecretValue("sk-~!visible_ASCII.only:0").reveal()).toBe(
      "sk-~!visible_ASCII.only:0",
    );
    const wrapped = new SecretValue("sk-wrapped-visible");
    expect(toSecretValue(wrapped)).toBe(wrapped);
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

describe("principal binding and verified deletion", () => {
  const alice = { issuer: "https://idp.example", subject: "alice" };
  const bob = { issuer: "https://idp.example", subject: "bob" };
  const path = () => join(temp, "credentials-metadata", "inference.json");
  const retryPath = () =>
    join(temp, "credentials-metadata", "revocation-retry.json");

  class FailingDeletes extends MemorySecretStore {
    fail = false;
    override async delete(ref: string): Promise<void> {
      if (this.fail)
        throw new PiShipError(
          "SECRET_STORE_UNAVAILABLE",
          "the keyring is locked (Authorization: Bearer abc.def.ghijkl)",
        );
      return super.delete(ref);
    }
  }

  function make(
    provider: CredentialProvider,
    store: MemorySecretStore = new MemorySecretStore(),
    extra: Partial<ConstructorParameters<typeof CredentialManager>[0]> = {},
  ) {
    const events: CredentialEvent[] = [];
    const manager = new CredentialManager({
      distributionId: "acmecode",
      provider,
      store,
      metadataPath: path(),
      beforeExpirySeconds: 300,
      onEvent: (event) => events.push(event),
      ...extra,
    });
    return { manager, store, events };
  }

  it("binds the credential and its entitlement to the principal and never hands them to another", async () => {
    const revoked: string[] = [];
    const { manager, store, events } = make(
      fakeProvider({ expiresInSeconds: 3600, revoked }),
    );
    await manager.ensure(alice as IdentitySession, ctx, {
      allowAcquire: true,
    });
    expect(JSON.parse(readFileSync(path(), "utf8"))).toMatchObject({
      principal: alice,
      models: ["acme/coder"],
    });
    // The same principal: email and display name are attributes.
    await expect(
      manager.ensure(
        { ...alice, email: "renamed@idp.example" } as IdentitySession,
        ctx,
        { allowAcquire: false },
      ),
    ).resolves.toMatchObject({ ref: { credentialId: "vk_1" } });
    // Another subject, or the same subject from another issuer, is another
    // principal: the credential is revoked and deleted, never returned.
    for (const other of [bob, { ...alice, issuer: "https://other.example" }]) {
      await manager.ensure(alice as IdentitySession, ctx, {
        allowAcquire: true,
      });
      const before = manager.readMetadata()?.credential_id;
      await expect(
        manager.ensure(other as IdentitySession, ctx, { allowAcquire: false }),
      ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
      expect(revoked.at(-1)).toBe(before);
      expect(store.refs()).toEqual([]);
      expect(existsSync(path())).toBe(false);
    }
    expect(
      events
        .filter((event) => event.event === "credential.revoke")
        .map((event) => event.detail.reason),
    ).toEqual(["principal-change", "principal-change"]);
  });

  it("discards a credential that is not bound to the signed-in principal, including an unbound one", async () => {
    const { manager, store, events } = make(
      fakeProvider({ expiresInSeconds: 3600 }),
    );
    // Written without identity, as credentials before principal binding were.
    await manager.ensure(null, ctx, { allowAcquire: true });
    expect(JSON.parse(readFileSync(path(), "utf8")).principal).toBeUndefined();
    const bound = await manager.ensure(alice as IdentitySession, ctx, {
      allowAcquire: true,
    });
    // Replaced as a credential of an earlier release, not reported (or
    // audited) as a change of user.
    expect(bound.notices).toEqual([
      "A credential from an earlier release was replaced",
    ]);
    expect(
      events.find((event) => event.event === "credential.revoke")?.detail,
    ).toMatchObject({ reason: "unbound" });
    expect(bound.secret?.reveal()).toBe("sk-generation-2-secret");
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
    // And the other way round: a bound credential is not used without identity.
    await expect(
      manager.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    expect(store.refs()).toEqual([]);
  });

  it("keeps using an unbound local secret while no identity is configured", async () => {
    // A personal distribution (identity.mode none) has no principal. Its
    // local secret, including one stored by a release before credentials
    // were bound (the same metadata without `principal`), stays usable.
    const store = new MemorySecretStore();
    const ref = "piship:mypi:inference#1";
    await store.put(ref, new SecretValue("sk-personal-sentinel-0001"));
    mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
    const legacy = `${JSON.stringify(
      {
        schema: CREDENTIAL_METADATA_SCHEMA,
        mode: "local-secret",
        credential_ref: ref,
        generation: 1,
        kind: "api_key",
        acquired_at: "2026-09-01T00:00:00.000Z",
      },
      null,
      2,
    )}\n`;
    writeFileSync(path(), legacy);
    const { manager, events } = make(
      new LocalSecretCredentialProvider(),
      store,
      { distributionId: "mypi" },
    );
    for (let launch = 0; launch < 2; launch++) {
      const active = await manager.ensure(null, ctx, { allowAcquire: false });
      expect(active.secret?.reveal()).toBe("sk-personal-sentinel-0001");
      expect(active.notices).toEqual([]);
    }
    expect(readFileSync(path(), "utf8")).toBe(legacy);
    expect(store.refs()).toEqual([ref]);
    expect(events).toEqual([]);
    expect(existsSync(retryPath())).toBe(false);
  });

  it("fails closed and keeps a discarded marker when another principal's secret cannot be deleted", async () => {
    const store = new FailingDeletes();
    const { manager } = make(fakeProvider({ expiresInSeconds: 3600 }), store);
    await manager.ensure(alice as IdentitySession, ctx, {
      allowAcquire: true,
    });
    store.fail = true;
    const error = await manager
      .ensure(bob as IdentitySession, ctx, { allowAcquire: true })
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(String((error as Error).message)).not.toContain("abc.def.ghijkl");
    // Alice's secret is still in the store, tracked, and unusable: no
    // release reads the marker as a credential.
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
    const marker = JSON.parse(readFileSync(path(), "utf8"));
    expect(marker).toMatchObject({
      schema: CREDENTIAL_DISCARDED_SCHEMA,
      orphans: ["piship:acmecode:inference#1", "piship:acmecode:inference#2"],
    });
    expect(marker.schema).not.toBe(CREDENTIAL_METADATA_SCHEMA);
    expect(manager.readMetadata()).toBeNull();
    expect(manager.status()).toMatchObject({
      state: "absent",
      notice: expect.stringContaining("discarded"),
    });
    // Nobody gets a credential while the deletion keeps failing, not even
    // Alice, and no new credential is acquired over the marker.
    for (const who of [alice, bob])
      await expect(
        manager.ensure(who as IdentitySession, ctx, { allowAcquire: true }),
      ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
    store.fail = false;
    const recovered = await manager.ensure(bob as IdentitySession, ctx, {
      allowAcquire: true,
    });
    expect(recovered.notices).toEqual([
      "The secrets of a discarded credential were deleted",
    ]);
    expect(recovered.secret?.reveal()).not.toBe("sk-generation-1-secret");
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
    expect((await store.get("piship:acmecode:inference#1"))?.reveal()).toBe(
      recovered.secret?.reveal(),
    );
  });

  it("never removes metadata whose secrets could not be deleted", async () => {
    const store = new FailingDeletes();
    const { manager } = make(fakeProvider({ expiresInSeconds: 3600 }), store);
    await store.put(
      "piship:acmecode:inference#7",
      new SecretValue("sk-old-snapshot-secret"),
    );
    mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
    writeFileSync(
      path(),
      JSON.stringify({
        schema: "piship-credential-metadata/v0",
        credential_ref: "piship:acmecode:inference#7",
      }),
    );
    store.fail = true;
    await expect(
      manager.ensure(null, ctx, { allowAcquire: true }),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(JSON.parse(readFileSync(path(), "utf8")).orphans).toEqual([
      "piship:acmecode:inference#7",
    ]);
    // Logout reports the failure instead of dropping the reference.
    expect(await manager.logout(ctx)).toEqual([
      expect.stringMatching(
        /^delete piship:acmecode:inference#7: SECRET_STORE_UNAVAILABLE/,
      ),
    ]);
    expect(existsSync(path())).toBe(true);
    // A store that reports success but still returns the secret has not
    // deleted it either.
    const sticky = new MemorySecretStore();
    await sticky.put(
      "piship:acmecode:inference#7",
      new SecretValue("sk-sticky-secret"),
    );
    sticky.delete = async () => {};
    expect(await make(fakeProvider(), sticky).manager.logout(ctx)).toEqual([
      "delete piship:acmecode:inference#7: still present after deletion",
    ]);
    expect(existsSync(path())).toBe(true);
    store.fail = false;
    expect(await manager.logout(ctx)).toEqual([]);
    expect(existsSync(path())).toBe(false);
    expect(store.refs()).toEqual([]);
  });

  it("records a failed revocation without the secret, re-checks it, and drops it once the credential expired", async () => {
    let now = Date.parse("2026-09-29T12:00:00Z");
    const provider: CredentialProvider = {
      mode: "http-broker",
      requiresIdentity: false,
      async acquire(): Promise<RuntimeCredential> {
        return {
          kind: "api_key",
          secret: new SecretValue("sk-pending-revocation-secret"),
          credentialId: "vk_pending",
          expiresAt: new Date(now + 3600_000),
        };
      },
      async revoke() {
        throw new Error(
          "revoke endpoint returned HTTP 503 for Bearer abc.def.ghijkl",
        );
      },
    };
    const { manager, events } = make(provider, new MemorySecretStore(), {
      now: () => now,
    });
    expect(manager.pendingRevocations()).toEqual({
      readable: true,
      count: 0,
      dropped: 0,
      oldestAgeSeconds: null,
      entries: [],
    });
    await manager.ensure(alice as IdentitySession, ctx, {
      allowAcquire: true,
    });
    const problems = await manager.logout(ctx, { reason: "replace" });
    expect(problems).toEqual([expect.stringContaining("HTTP 503")]);
    expect(problems[0]).not.toContain("abc.def.ghijkl");
    expect(events.at(-1)?.detail).toMatchObject({
      revocation: "failed",
      retryPending: true,
    });
    const text = readFileSync(retryPath(), "utf8");
    expect(text).not.toContain("sk-pending-revocation-secret");
    expect(JSON.parse(text)).toEqual({
      schema: REVOCATION_RETRY_SCHEMA,
      entries: [
        {
          credential_id: "vk_pending",
          mode: "http-broker",
          generation: 1,
          reason: "replace",
          failed_at: "2026-09-29T12:00:00.000Z",
          expires_at: "2026-09-29T13:00:00.000Z",
          checks: 0,
        },
      ],
    });
    now += 90_000;
    expect(readPendingRevocations(retryPath(), now)).toMatchObject({
      count: 1,
      oldestAgeSeconds: 90,
      entries: [{ credentialId: "vk_pending", ageSeconds: 90 }],
    });
    expect(manager.checkPendingRevocations()).toEqual([
      expect.stringContaining("Credential vk_pending could not be revoked"),
    ]);
    expect(
      JSON.parse(readFileSync(retryPath(), "utf8")).entries[0].checks,
    ).toBe(1);
    now += 3600_000;
    expect(manager.checkPendingRevocations()).toEqual([]);
    expect(existsSync(retryPath())).toBe(false);
    // An unreadable record is reported, not taken as "nothing pending".
    mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
    writeFileSync(retryPath(), "{broken");
    expect(manager.pendingRevocations().readable).toBe(false);
    expect(manager.checkPendingRevocations()).toEqual([
      "The pending revocation record is unreadable",
    ]);
  });

  it("redacts a provider message copied into a renewal failure", async () => {
    const provider = {
      ...fakeProvider({ expiresInSeconds: 1 }),
      async refresh(): Promise<RuntimeCredential> {
        throw new Error("broker said: Authorization: Bearer abc.def.ghijkl");
      },
    };
    let now = Date.now();
    const { manager } = make(provider, new MemorySecretStore(), {
      now: () => now,
    });
    await manager.ensure(null, ctx, { allowAcquire: true });
    now += 5_000;
    const error = await manager
      .ensure(null, ctx, { allowAcquire: false })
      .catch((caught: Error) => caught);
    expect(error).toMatchObject({ code: "CREDENTIAL_EXPIRED" });
    expect(error.message).toContain("could not be renewed");
    expect(error.message).not.toContain("abc.def.ghijkl");
  });

  it("keeps a replaced generation whose deletion fails tracked, reports it, and retries it at the next renewal", async () => {
    const store = new FailingDeletes();
    // Always within refresh.beforeExpiry, so every ensure renews.
    const { manager } = make(fakeProvider({ expiresInSeconds: 60 }), store);
    await manager.ensure(alice as IdentitySession, ctx, {
      allowAcquire: true,
    });
    store.fail = true;
    const renewed = await manager.ensure(alice as IdentitySession, ctx, {
      allowAcquire: true,
    });
    expect(renewed.secret?.reveal()).toBe("sk-generation-2-secret");
    expect(renewed.notices).toEqual([
      expect.stringContaining(
        "A replaced credential could not be deleted from the secret store (piship:acmecode:inference#1",
      ),
    ]);
    expect(renewed.notices[0]).not.toContain("abc.def.ghijkl");
    expect(JSON.parse(readFileSync(path(), "utf8")).orphans).toEqual([
      "piship:acmecode:inference#1",
    ]);
    expect(store.refs()).toEqual([
      "piship:acmecode:inference#1",
      "piship:acmecode:inference#2",
    ]);
    store.fail = false;
    const again = await manager.ensure(alice as IdentitySession, ctx, {
      allowAcquire: true,
    });
    expect(again.notices).toEqual([]);
    expect(store.refs()).toEqual(["piship:acmecode:inference#3"]);
    expect(JSON.parse(readFileSync(path(), "utf8")).orphans).toBeUndefined();
  });

  it("keeps at most 20 pending revocations and the count of the dropped ones", async () => {
    let issued = 0;
    const provider: CredentialProvider = {
      mode: "http-broker",
      requiresIdentity: false,
      async acquire() {
        issued += 1;
        // No expiry: such an entry never resolves on its own.
        return {
          kind: "api_key",
          secret: new SecretValue(`sk-never-expires-${issued}`),
          credentialId: `vk_never_${issued}`,
        };
      },
      async revoke() {
        throw new Error("revoke endpoint returned HTTP 503");
      },
    };
    const { manager } = make(provider);
    for (let round = 0; round < 23; round++) {
      await manager.ensure(alice as IdentitySession, ctx, {
        allowAcquire: true,
      });
      await manager.logout(ctx, { reason: "replace" });
    }
    const file = JSON.parse(readFileSync(retryPath(), "utf8"));
    expect(file.entries).toHaveLength(20);
    expect(file.dropped).toBe(3);
    // The oldest were dropped.
    expect(file.entries[0].credential_id).toBe("vk_never_4");
    expect(file.entries.at(-1).credential_id).toBe("vk_never_23");
    expect(manager.pendingRevocations()).toMatchObject({
      readable: true,
      count: 20,
      dropped: 3,
    });
    const notices = manager.checkPendingRevocations();
    expect(notices).toHaveLength(21);
    expect(notices.at(-1)).toContain("3 older credential(s)");
    expect(JSON.stringify(file)).not.toContain("sk-never-expires");
  });

  it("runs a critical section under the credential lock, reentrantly, while other callers wait", async () => {
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const { manager, store } = make(provider);
    const other = make(provider, store).manager;
    const order: string[] = [];
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: () => void = () => undefined;
    const inside = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const held = manager.exclusive(async () => {
      order.push("outer:start");
      // Credential operations inside reuse the lock instead of waiting for it.
      await manager.ensure(alice as IdentitySession, ctx, {
        allowAcquire: true,
      });
      await manager.logout(ctx, { reason: "replace" });
      await manager.ensure(alice as IdentitySession, ctx, {
        allowAcquire: true,
      });
      entered();
      await gate;
      order.push("outer:end");
    });
    await inside;
    // Another manager of the same file (another caller) waits for the lock.
    const waiting = other
      .ensure(alice as IdentitySession, ctx, { allowAcquire: false })
      .then((active) => {
        order.push("other");
        return active;
      });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(order).toEqual(["outer:start"]);
    release();
    await held;
    const active = await waiting;
    expect(order).toEqual(["outer:start", "outer:end", "other"]);
    expect(active.ref?.credentialId).toBe("vk_2");
  });

  it("checks the caller's guard under the lock before anything is read or acquired", async () => {
    const provider = fakeProvider({ expiresInSeconds: 3600 });
    const { manager } = make(provider);
    await expect(
      manager.ensure(alice as IdentitySession, ctx, {
        allowAcquire: true,
        guard: () => {
          throw new PiShipError("IDENTITY_REQUIRED", "the user changed");
        },
      }),
    ).rejects.toMatchObject({ code: "IDENTITY_REQUIRED" });
    expect(provider.acquired()).toBe(0);
    expect(existsSync(path())).toBe(false);
  });

  it("leaves a logout interrupted after the revocation or between deletions for the next one to finish", async () => {
    const revoked: string[] = [];
    const provider = fakeProvider({ expiresInSeconds: 3600, revoked });
    const store = new MemorySecretStore();
    for (const phase of ["revoked", "secret-deleted"]) {
      await make(provider, store).manager.ensure(
        alice as IdentitySession,
        ctx,
        { allowAcquire: true },
      );
      const crashing = make(provider, store, {
        onPhase: (reached) => {
          if (reached === phase) throw new Error("simulated crash");
        },
      }).manager;
      await expect(crashing.logout(ctx)).rejects.toThrow("simulated crash");
      // The metadata still names every secret, so nothing is untracked.
      const metadata = JSON.parse(readFileSync(path(), "utf8"));
      expect(metadata.schema).toBe(CREDENTIAL_METADATA_SCHEMA);
      for (const ref of store.refs())
        expect(metadataSecretRefs(metadata, "acmecode")).toContain(ref);
      expect(await make(provider, store).manager.logout(ctx)).toEqual([]);
      expect(store.refs()).toEqual([]);
      expect(existsSync(path())).toBe(false);
    }
    // Revoked before each crash; the second retry finds the secret already
    // deleted and skips the (already sent) revocation.
    expect(revoked).toEqual(["vk_1", "vk_1", "vk_2"]);
  });

  it("lists an identity marker's remaining token bundles as its references", () => {
    expect(
      metadataSecretRefs(
        {
          schema: "piship-identity-discarded/v1",
          orphans: [
            "piship:acmecode:identity#3",
            "piship:other:identity#1",
            "piship:acmecode:inference#2",
          ],
        },
        "acmecode",
      ),
    ).toEqual(["piship:acmecode:identity#3", "piship:acmecode:inference#2"]);
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
