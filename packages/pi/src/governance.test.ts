import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createAgentSession,
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  governModelRuntime,
  isCredentialRejection,
  isModelDenial,
  requestFailure,
  acceptanceFailure,
} from "./governance.js";

const model = (id: string) => ({
  id,
  name: id,
  reasoning: false,
  input: ["text" as const],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 64000,
  maxTokens: 4096,
});
function memoryCredentials() {
  const values = new Map<string, unknown>();
  return {
    read: async (id: string) => values.get(id) as never,
    list: async () => [],
    modify: async (id: string, fn: (current: never) => Promise<unknown>) => {
      const next = await fn(values.get(id) as never);
      if (next !== undefined) values.set(id, next);
      return values.get(id) as never;
    },
    delete: async (id: string) => {
      values.delete(id);
    },
  };
}

let services: Awaited<ReturnType<typeof startLocalServices>>;
let temp: string;
const saved = { ...process.env };
beforeEach(async () => {
  services = await startLocalServices({ knobs: { acceptedKeys: [] } });
  temp = mkdtempSync(join(tmpdir(), "piship-pi-governance-"));
  // Ambient personal credentials that a managed runtime must never use.
  process.env.OPENAI_API_KEY = "sk-ambient-personal-key";
  process.env.ANTHROPIC_API_KEY = "sk-ant-ambient-personal-key";
});
afterEach(async () => {
  await services.close();
  rmSync(temp, { recursive: true, force: true });
  for (const key of ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"])
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
});

async function managedSession(
  options: { keys: string[]; tools?: boolean; fail?: () => Error } = {
    keys: [],
  },
) {
  const runtime = await ModelRuntime.create({
    credentials: memoryCredentials() as never,
    modelsPath: null,
    refreshOnCreate: false,
    allowModelNetwork: false,
  });
  runtime.registerProvider("acmecode", {
    name: "AcmeCode",
    baseUrl: services.gatewayUrl,
    api: "openai-completions",
    models: [model("acme/coder"), model("acme/general")],
  });
  const issued: string[] = [];
  let calls = 0;
  const governed = governModelRuntime(runtime, {
    kind: "managed-endpoint",
    providerId: "acmecode",
    allowedModelIds: ["acme/coder"],
    command: "acme",
    apiKey: async ({ force }) => {
      calls += 1;
      if (options.fail) throw options.fail();
      const key =
        options.keys[
          force
            ? Math.min(issued.length, options.keys.length - 1)
            : Math.max(0, issued.length - 1)
        ] ??
        options.keys[0] ??
        "";
      if (force || !issued.length) issued.push(key);
      return key;
    },
  });
  const settingsManager = SettingsManager.inMemory({
    retry: { enabled: false },
  });
  const resourceLoader = new DefaultResourceLoader({
    cwd: temp,
    agentDir: temp,
    settingsManager,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    extensionFactories: [
      {
        name: "piship-governance",
        factory: (pi) => {
          pi.on("message_end", (event) => {
            if (isCredentialRejection(event.message))
              governed.markCredentialRejected();
            const message = governed.withAccessAction(event.message);
            return message
              ? { message: message as typeof event.message }
              : undefined;
          });
        },
      },
    ],
  });
  await resourceLoader.reload();
  const selected = runtime.getModel("acmecode", "acme/coder");
  const { session } = await createAgentSession({
    cwd: temp,
    agentDir: temp,
    modelRuntime: runtime,
    ...(selected ? { model: selected } : {}),
    settingsManager,
    sessionManager: SessionManager.inMemory(temp),
    resourceLoader,
    ...(options.tools === false ? { noTools: true } : {}),
  });
  return { runtime, session, governed, calls: () => calls, issued };
}
const last = (session: { messages: unknown[] }) =>
  session.messages.at(-1) as {
    stopReason?: string;
    errorMessage?: string;
    role?: string;
  };

describe("managed model governance on the pinned Pi runtime", () => {
  it("hides and refuses ambient providers even with personal API keys in the environment", async () => {
    const { runtime, session } = await managedSession({
      keys: ["sk-local-owner-key"],
    });
    expect(
      runtime
        .getAvailableSnapshot()
        .map((item) => `${item.provider}/${item.id}`),
    ).toEqual(["acmecode/acme/coder"]);
    expect((await runtime.getAvailable()).map((item) => item.id)).toEqual([
      "acme/coder",
    ]);
    expect(await runtime.checkAuth("openai")).toBeUndefined();
    expect(await runtime.getAuth("anthropic")).toBeUndefined();
    expect(runtime.getModels("openai")).toEqual([]);
    expect(runtime.getModel("acmecode", "acme/general")).toBeUndefined();
    const selected = runtime.getModel("acmecode", "acme/coder");
    expect(selected).toBeDefined();
    if (!selected) return;
    const ambient = {
      ...selected,
      provider: "openai",
      id: "gpt-4o",
      baseUrl: "https://api.openai.com/v1",
    };
    await expect(session.setModel(ambient)).rejects.toThrow("No API key");
    expect(() =>
      runtime.streamSimple(ambient, { messages: [] } as never),
    ).toThrow("not allowed");
    const unlisted = { ...selected, id: "acme/general" };
    expect(() =>
      runtime.streamSimple(unlisted, { messages: [] } as never),
    ).toThrow("not allowed");
    await expect(
      runtime.login("openai", "api_key", {} as never),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    await expect(
      runtime.setRuntimeApiKey("openai", "sk-user-supplied"),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    session.dispose();
  });

  it("streams text through the managed endpoint with only the managed credential", async () => {
    const credential = "sk-managed-credential-1";
    services.knobs.acceptedKeys = [credential];
    const { session } = await managedSession({ keys: [credential] });
    const deltas: string[] = [];
    session.subscribe((event) => {
      if (
        event.type === "message_update" &&
        event.assistantMessageEvent.type === "text_delta"
      )
        deltas.push(event.assistantMessageEvent.delta);
    });
    await session.prompt("hello");
    expect(session.getLastAssistantText()).toBe("Hello from acme/coder.");
    expect(deltas.length).toBeGreaterThan(1);
    const requests = services.state.requests.filter((item: { path: string }) =>
      item.path.endsWith("/chat/completions"),
    );
    expect(
      requests.map((item: { authorization: string }) => item.authorization),
    ).toEqual([`Bearer ${credential}`]);
    expect(JSON.stringify(services.state.requests)).not.toContain("sk-ambient");
    expect(JSON.parse(requests[0].body).model).toBe("acme/coder");
    session.dispose();
  });

  it("round-trips a tool call and its result through Pi", async () => {
    services.knobs.acceptedKeys = ["sk-managed-credential-1"];
    services.knobs.gatewayMode = "tool";
    const { session } = await managedSession({
      keys: ["sk-managed-credential-1"],
    });
    await session.prompt("read the manifest");
    const roles = session.messages.map(
      (message) => (message as { role: string }).role,
    );
    expect(roles).toContain("toolResult");
    expect(session.getLastAssistantText()).toMatch(/^Tool result received:/);
    session.dispose();
  });

  it("re-acquires the credential after a gateway 401 and succeeds on the next request", async () => {
    services.knobs.acceptedKeys = ["sk-rotated-credential-2"];
    const { session, issued } = await managedSession({
      keys: ["sk-revoked-credential-1", "sk-rotated-credential-2"],
    });
    await session.prompt("first");
    expect(last(session)).toMatchObject({ stopReason: "error" });
    await session.prompt("second");
    expect(session.getLastAssistantText()).toBe("Hello from acme/coder.");
    expect(issued).toEqual([
      "sk-revoked-credential-1",
      "sk-rotated-credential-2",
    ]);
    session.dispose();
  });

  it("offers no upstream provider login on /login, only where to sign in", async () => {
    const { runtime, session } = await managedSession({ keys: ["sk-1"] });
    // Pi's /login picker lists `getProviders()` and starts the login of the
    // chosen provider's method; a method without `login` is shown as
    // configured outside Pi, under its name.
    const providers = runtime.getProviders();
    expect(providers.map((provider) => provider.id)).toEqual(["acmecode"]);
    expect(providers[0]?.auth.oauth).toBeUndefined();
    expect(providers[0]?.auth.apiKey?.login).toBeUndefined();
    expect(providers[0]?.auth.apiKey?.name).toBe(
      "AcmeCode sign-in (run acme login in a terminal)",
    );
    session.dispose();
  });

  it.each([
    [
      "an expired refresh token",
      new PiShipError(
        "IDENTITY_EXPIRED",
        "Identity refresh failed: token endpoint returned invalid_grant",
        { component: "identity", userAction: "Run login again" },
      ),
      "Identity refresh failed: token endpoint returned invalid_grant\nAction: In a terminal, run acme login again",
    ],
    [
      "a changed principal",
      new PiShipError(
        "IDENTITY_REQUIRED",
        "The signed-in user changed; restart the session",
        {
          component: "identity",
          userAction: "Start acme again to continue as the signed-in user",
        },
      ),
      "The signed-in user changed; restart the session\nAction: Start acme again to continue as the signed-in user",
    ],
    [
      "a missing credential",
      new PiShipError("CREDENTIAL_REQUIRED", "No runtime credential"),
      "No runtime credential\nAction: In a terminal, run acme login",
    ],
  ])(
    "shows the PiShip action for %s mid-session",
    async (_name, error, text) => {
      const { session } = await managedSession({
        keys: [],
        fail: () => error,
      });
      await session.prompt("hello");
      expect(last(session)).toMatchObject({
        stopReason: "error",
        errorMessage: text,
      });
      session.dispose();
    },
  );

  it("does not attach an access action to an ordinary failure", async () => {
    services.knobs.acceptedKeys = ["sk-managed-credential-1"];
    services.knobs.gatewayMode = "malformed";
    const { session } = await managedSession({
      keys: ["sk-managed-credential-1"],
    });
    await session.prompt("hello");
    expect(last(session)?.errorMessage).not.toContain("Action:");
    session.dispose();
  });

  it("shows the PiShip action after a gateway 401", async () => {
    services.knobs.acceptedKeys = [];
    const { session } = await managedSession({ keys: ["sk-revoked-1"] });
    await session.prompt("hello");
    expect(last(session)?.errorMessage).toMatch(
      /\nAction: Send the message again; if it fails again, run acme login in a terminal$/,
    );
    session.dispose();
  });

  it.each([
    ["malformed", { gatewayMode: "malformed" }],
    ["rate limited", { gatewayStatus: 429 }],
    ["gateway outage", { gatewayStatus: 503 }],
  ])("surfaces %s responses as a visible error", async (_name, knobs) => {
    services.knobs.acceptedKeys = ["sk-managed-credential-1"];
    Object.assign(services.knobs, knobs);
    const { session } = await managedSession({
      keys: ["sk-managed-credential-1"],
    });
    await session.prompt("hello");
    expect(last(session)?.stopReason).toBe("error");
    expect(last(session)?.errorMessage).toBeTruthy();
    session.dispose();
  });

  it("cancels an in-flight streamed request", async () => {
    services.knobs.acceptedKeys = ["sk-managed-credential-1"];
    services.knobs.gatewayDelayMs = 400;
    const { session } = await managedSession({
      keys: ["sk-managed-credential-1"],
    });
    session.subscribe((event) => {
      if (
        event.type === "message_update" &&
        event.assistantMessageEvent.type === "text_delta"
      )
        void session.abort();
    });
    await session.prompt("hello");
    expect(last(session)?.stopReason).toBe("aborted");
    session.dispose();
  });
});

describe("personal Pi-native governance", () => {
  it("narrows Pi's own catalog to the owner allowlist", async () => {
    const runtime = await ModelRuntime.create({
      authPath: join(temp, "auth.json"),
      modelsPath: join(temp, "models.json"),
      refreshOnCreate: false,
    });
    const allowed = runtime.getModels("openai")[0];
    const other = runtime.getModels("anthropic")[0];
    expect(allowed && other).toBeDefined();
    if (!allowed || !other) return;
    governModelRuntime(runtime, {
      kind: "pi-native",
      allowedModelKeys: [`openai/${allowed.id}`],
    });
    expect(
      runtime
        .getAvailableSnapshot()
        .every((item) => item.provider === "openai" && item.id === allowed.id),
    ).toBe(true);
    expect(await runtime.checkAuth("anthropic")).toBeUndefined();
    expect(runtime.getModel("anthropic", other.id)).toBeUndefined();
    expect(() =>
      runtime.streamSimple(other, { messages: [] } as never),
    ).toThrow("not allowed");
  });
  it("allows no model when a restricting policy leaves an empty allowlist", async () => {
    const runtime = await ModelRuntime.create({
      authPath: join(temp, "auth.json"),
      modelsPath: join(temp, "models.json"),
      refreshOnCreate: false,
    });
    const other = runtime.getModels("anthropic")[0];
    expect(other).toBeDefined();
    if (!other) return;
    governModelRuntime(runtime, {
      kind: "pi-native",
      allowedModelKeys: [],
      restricted: true,
    });
    expect(runtime.getAvailableSnapshot()).toEqual([]);
    expect(runtime.getModel("anthropic", other.id)).toBeUndefined();
    expect(() =>
      runtime.streamSimple(other, { messages: [] } as never),
    ).toThrow("not allowed");
  });
  it("refuses every request while the policy reports a required control down, before any I/O", async () => {
    const runtime = await ModelRuntime.create({
      credentials: memoryCredentials() as never,
      modelsPath: null,
      refreshOnCreate: false,
      allowModelNetwork: false,
    });
    runtime.registerProvider("acmecode", {
      name: "AcmeCode",
      baseUrl: services.gatewayUrl,
      api: "openai-completions",
      models: [model("acme/coder")],
    });
    let down = true;
    let keyRequests = 0;
    governModelRuntime(
      runtime,
      {
        kind: "managed-endpoint",
        providerId: "acmecode",
        allowedModelIds: ["acme/coder"],
        apiKey: async () => {
          keyRequests += 1;
          return "sk-gate";
        },
      },
      {
        allows: () => true,
        available: () => {
          if (down)
            throw new PiShipError(
              "AUDIT_UNAVAILABLE",
              "Audit is unavailable: required sink company is failing",
            );
        },
      },
    );
    const coder = runtime.getModel("acmecode", "acme/coder");
    expect(coder).toBeDefined();
    if (!coder) return;
    for (const call of ["stream", "streamSimple", "complete", "completeSimple"])
      expect(() =>
        (runtime as unknown as Record<string, (...args: unknown[]) => unknown>)[
          call
        ]?.(coder, { messages: [] }),
      ).toThrow(/AUDIT_UNAVAILABLE|Audit is unavailable/);
    expect(keyRequests).toBe(0);
    // Recovered: the same request is no longer refused by the gate.
    down = false;
    expect(() =>
      runtime.streamSimple(coder, { messages: [] } as never),
    ).not.toThrow(/Audit is unavailable/);
  });
  it("recognizes a gateway model denial, and not a credential rejection or an ordinary failure", () => {
    const failed = (errorMessage: string) => ({
      role: "assistant",
      stopReason: "error",
      errorMessage,
    });
    expect(isModelDenial(failed('403 {"error":{"message":"denied"}}'))).toBe(
      true,
    );
    expect(isModelDenial(failed("Forbidden"))).toBe(true);
    expect(isModelDenial(failed("401 Unauthorized"))).toBe(false);
    expect(isModelDenial(failed("429 rate limited"))).toBe(false);
    expect(isModelDenial(failed("connection reset (code 4030)"))).toBe(false);
    expect(
      isModelDenial({
        role: "assistant",
        stopReason: "stop",
        errorMessage: "403",
      }),
    ).toBe(false);
    expect(isModelDenial(undefined)).toBe(false);
  });
  it("does not take a model provider's 401 or 403 relayed by the gateway as the user's", () => {
    // Pi's messages for LiteLLM v1.103.0's answers
    // (tests/enterprise-reference/gateway-evidence.test.ts).
    const failed = (errorMessage: string) => ({
      role: "assistant",
      stopReason: "error",
      errorMessage,
    });
    const upstream401 = failed(
      '401: {"message":"litellm.AuthenticationError: AuthenticationError: OpenAIException - Incorrect API key provided.. Received Model Group=acme/coder","type":"authentication_error","param":null,"code":"401"}',
    );
    const upstream403 = failed(
      '403: {"message":"litellm.APIError: APIError: OpenAIException - Mock upstream denies this request.. Received Model Group=acme/coder","type":"permission_error","param":null,"code":"403"}',
    );
    expect(isCredentialRejection(upstream401)).toBe(false);
    expect(isModelDenial(upstream401)).toBe(false);
    expect(isCredentialRejection(upstream403)).toBe(false);
    expect(isModelDenial(upstream403)).toBe(false);
    // The gateway's own refusals keep their meaning.
    for (const type of ["auth_error", "token_not_found_in_db", "expired_key"])
      expect(
        isCredentialRejection(
          failed(
            `401: {"message":"Authentication Error, ...","type":"${type}","param":"None","code":"401"}`,
          ),
        ),
      ).toBe(true);
    expect(
      isModelDenial(
        failed(
          `403: {"message":"The requested model 'acme/general' is not available for this API key","type":"key_model_access_denied","param":"model","code":"403"}`,
        ),
      ),
    ).toBe(true);
    expect(requestFailure(upstream401)).toMatchObject({
      status: 401,
      body: { type: "authentication_error" },
    });
    expect(
      requestFailure(failed("Stream ended without finish_reason")),
    ).toEqual({ message: "Stream ended without finish_reason" });
  });
  it("reports a failed acceptance request with the code of the gateway's status", () => {
    const failed = (errorMessage: string) => ({
      role: "assistant",
      stopReason: "error",
      errorMessage,
    });
    const code = (errorMessage: string) =>
      acceptanceFailure(failed(errorMessage));
    expect(
      code(
        '503: {"message":"litellm.ServiceUnavailableError: ...","type":"internal_server_error","param":null,"code":"503"}',
      ),
    ).toMatchObject({ code: "GATEWAY_UNREACHABLE", retryable: true });
    expect(
      code(
        '429: {"message":"litellm.RateLimitError: ...","type":"throttling_error","param":null,"code":"429"}',
      ),
    ).toMatchObject({ code: "GATEWAY_RATE_LIMITED", retryable: true });
    expect(
      code(
        '401: {"message":"Authentication Error, Key is blocked.","type":"auth_error","param":"None","code":"401"}',
      ).code,
    ).toBe("CREDENTIAL_REVOKED");
    expect(
      code(
        '401: {"message":"litellm.AuthenticationError: ...","type":"authentication_error","param":null,"code":"401"}',
      ),
    ).toMatchObject({ code: "GATEWAY_UNREACHABLE", retryable: false });
    expect(
      code(
        `403: {"message":"The requested model 'acme/general' is not available for this API key","type":"key_model_access_denied","param":"model","code":"403"}`,
      ).code,
    ).toBe("MODEL_DENIED");
    // A stream cut after it started carries no status: a protocol error.
    const cut = code(
      "litellm.APIConnectionError: APIConnectionError: OpenAIException - Response payload is not completed",
    );
    expect(cut).toMatchObject({
      code: "GATEWAY_PROTOCOL_ERROR",
      retryable: false,
    });
    expect(cut.message).toBe(
      "The acceptance model request failed: litellm.APIConnectionError: APIConnectionError: OpenAIException - Response payload is not completed",
    );
    expect(
      acceptanceFailure({ role: "assistant", stopReason: "aborted" }).code,
    ).toBe("GATEWAY_PROTOCOL_ERROR");
  });
});
