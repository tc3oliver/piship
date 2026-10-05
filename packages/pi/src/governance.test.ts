import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  acceptanceFailure,
  governModelRuntime,
  isCredentialRejection,
  isModelDenial,
  type ModelPolicy,
  PI_VIRTUAL_MODEL_API,
  requestFailure,
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
  options: {
    keys: string[];
    tools?: boolean;
    fail?: () => Error;
    baseUrl?: string;
  } = {
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
    baseUrl: options.baseUrl ?? services.gatewayUrl,
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
    ...(options.tools === false ? { noTools: "all" as const } : {}),
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
        selects: () => true,
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
    // Pi sets "aborted" only when the caller's signal aborted the request.
    expect(
      acceptanceFailure({
        role: "assistant",
        stopReason: "aborted",
        errorMessage: "Request was aborted",
      }),
    ).toMatchObject({ code: "REQUEST_CANCELLED", retryable: false });
  });
});

describe("acceptance request failures without a status (#85)", () => {
  let hanging: Server | undefined;
  afterEach(async () => {
    const server = hanging;
    hanging = undefined;
    if (!server) return;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  // A gateway that accepts the connection and never answers.
  async function hangingGateway(): Promise<string> {
    const server = createServer(() => {});
    hanging = server;
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`;
  }
  // A loopback port with nothing listening: the connection is refused.
  async function closedPort(): Promise<string> {
    const server = createServer();
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const { port } = server.address() as AddressInfo;
    await new Promise((resolve) => server.close(resolve));
    return `http://127.0.0.1:${port}/v1`;
  }

  it("reports a refused connection as an unreachable gateway with its system code", async () => {
    const { session } = await managedSession({
      keys: ["sk-managed-credential-1"],
      baseUrl: await closedPort(),
    });
    await session.prompt("hello");
    const message = session.messages.at(-1);
    expect(requestFailure(message)?.status).toBeUndefined();
    const error = acceptanceFailure(message);
    expect(error).toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
      sanitizedDetail: { transport: "ECONNREFUSED" },
    });
    expect(error.message).toMatch(/\(ECONNREFUSED\)$/);
    session.dispose();
  });

  it("reports a request that ran past its deadline as an unreachable gateway", async () => {
    const { runtime } = await managedSession({
      keys: ["sk-managed-credential-1"],
      baseUrl: await hangingGateway(),
    });
    const selected = runtime.getModel("acmecode", "acme/coder");
    if (!selected) throw new Error("no model");
    const message = await runtime
      .streamSimple(
        selected,
        { messages: [{ role: "user", content: "hi", timestamp: 0 }] },
        { timeoutMs: 200, maxRetries: 0 },
      )
      .result();
    expect(message.stopReason).toBe("error");
    expect(acceptanceFailure(message)).toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
      sanitizedDetail: { transport: "timeout" },
    });
  });

  it("reports a request the caller aborted as cancelled, not a protocol error", async () => {
    const baseUrl = await hangingGateway();
    const { session } = await managedSession({
      keys: ["sk-managed-credential-1"],
      baseUrl,
    });
    hanging?.once("request", () => void session.abort());
    await session.prompt("hello");
    const message = session.messages.at(-1);
    expect(message).toMatchObject({ stopReason: "aborted" });
    expect(acceptanceFailure(message)).toMatchObject({
      code: "REQUEST_CANCELLED",
      retryable: false,
    });
    session.dispose();
  });
});

describe("model.select and model.dispatch", () => {
  async function routed(
    options: {
      /** Ids model.select denies. */
      selectDeny?: string[];
      /** Ids model.dispatch denies; without it, dispatch falls back to select. */
      dispatchDeny?: string[];
      routes?: string[];
      available?: () => void;
      onDenied?: ModelPolicy["denied"];
    } = {},
  ) {
    const runtime = await ModelRuntime.create({
      credentials: memoryCredentials() as never,
      modelsPath: null,
      refreshOnCreate: false,
      allowModelNetwork: false,
    });
    const cost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
    runtime.registerProvider("acmecode", {
      name: "AcmeCode",
      baseUrl: services.gatewayUrl,
      api: "openai-completions",
      models: [
        model("acme/coder"),
        model("acme/general"),
        model("acme/other"),
        {
          id: "acme/classify",
          name: "Classify",
          type: "classifier",
          api: "llama-cpp-classify",
          input: ["text"],
          cost,
          contextWindow: 4096,
        },
        {
          id: "acme/image",
          name: "Image",
          type: "image",
          api: "openrouter-images",
          input: ["text"],
          output: ["image"],
          cost,
        },
      ],
    });
    const events: string[] = [];
    let keyRequests = 0;
    const policy: ModelPolicy = {
      selects: (_provider, id) => !options.selectDeny?.includes(id),
      ...(options.dispatchDeny
        ? {
            dispatches: (_provider: string, id: string) =>
              !options.dispatchDeny?.includes(id),
          }
        : {}),
      denied: (action, provider, id, detail) => {
        events.push(
          `${action} ${provider}/${id}${detail?.reason ? ` (${detail.reason})` : ""}`,
        );
        options.onDenied?.(action, provider, id, detail);
      },
      dispatched: (dispatch) =>
        events.push(
          `dispatch ${dispatch.selected} -> ${dispatch.dispatched} by ${dispatch.router}`,
        ),
      ...(options.available ? { available: options.available } : {}),
    };
    const physicalIds = [
      "acme/coder",
      "acme/general",
      "acme/other",
      "acme/classify",
      "acme/image",
    ];
    const governed = governModelRuntime(
      runtime,
      {
        kind: "managed-endpoint",
        providerId: "acmecode",
        allowedModelIds: [...physicalIds, "acme/auto"],
        dispatchModelIds: physicalIds,
        apiKey: async () => {
          keyRequests += 1;
          return "sk-routed";
        },
      },
      policy,
      [
        {
          provider: "acmecode",
          id: "acme/auto",
          routes: (options.routes ?? ["acme/coder"]).map((id) => ({
            provider: "acmecode",
            id,
          })),
          router: "./extensions/router.ts",
        },
      ],
    );
    let target = "acme/coder";
    governed.withRegistrationWindow(() =>
      runtime.registerVirtualModel({
        provider: "acmecode",
        id: "acme/auto",
        name: "Auto",
        route: () => ({
          model: { ...model(target), provider: "acmecode" } as never,
          thinkingLevel: "off",
        }),
      }),
    );
    // Listed unless model.select denies it.
    const auto = runtime.getModel("acmecode", "acme/auto") ?? {
      ...model("acme/auto"),
      provider: "acmecode",
      api: PI_VIRTUAL_MODEL_API,
      baseUrl: "",
    };
    return {
      runtime,
      governed,
      auto,
      events,
      keyRequests: () => keyRequests,
      routeTo: (id: string) => {
        target = id;
      },
      resolve: () =>
        runtime.resolveModel(auto, [], {
          reason: "direct",
          thinkingLevel: "off",
        }),
    };
  }
  const physical = (id: string, extra: Record<string, unknown> = {}) => ({
    ...model(id),
    provider: "acmecode",
    api: "openai-completions",
    baseUrl: services.gatewayUrl,
    ...extra,
  });
  const classifier = () =>
    physical("acme/classify", {
      api: "llama-cpp-classify",
      type: "classifier",
    });
  const stream = (runtime: ModelRuntime, target: unknown) =>
    runtime.streamSimple(target as never, { messages: [] } as never);

  it("refuses a physical request that model.select or model.dispatch denies", async () => {
    const select = await routed({ selectDeny: ["acme/general"] });
    expect(() => stream(select.runtime, physical("acme/general"))).toThrow(
      "not allowed",
    );
    // Selection is refused first; dispatch is not consulted.
    expect(select.events).toEqual(["model.select acmecode/acme/general"]);
    const dispatch = await routed({ dispatchDeny: ["acme/general"] });
    expect(() => stream(dispatch.runtime, physical("acme/general"))).toThrow(
      "not allowed",
    );
    expect(dispatch.events).toEqual(["model.dispatch acmecode/acme/general"]);
    expect(select.keyRequests() + dispatch.keyRequests()).toBe(0);
  });

  it("routes to a model the session cannot select, and only through the route", async () => {
    const { runtime, governed, events, resolve } = await routed({
      selectDeny: ["acme/coder"],
      dispatchDeny: [],
    });
    expect(governed.isSelectable("acmecode", "acme/coder")).toBe(false);
    expect(runtime.getModel("acmecode", "acme/coder")).toBeUndefined();
    expect((await runtime.getAvailable()).map((item) => item.id)).not.toContain(
      "acme/coder",
    );
    const route = await resolve();
    expect(route.model.id).toBe("acme/coder");
    expect(events).toEqual([
      "dispatch acmecode/acme/auto -> acmecode/acme/coder by ./extensions/router.ts",
    ]);
    // The routed request has a credential and passes the guard.
    expect(await runtime.getAuth(route.model)).toMatchObject({
      auth: { apiKey: "sk-routed" },
    });
    expect(() => stream(runtime, route.model)).not.toThrow();
    // The same model, not routed: model.select is still required.
    expect(() => stream(runtime, physical("acme/coder"))).toThrow(
      "not allowed",
    );
    expect(() => stream(runtime, { ...route.model })).toThrow("not allowed");
  });

  it("freezes the routed copy, so it cannot become another model", async () => {
    const { runtime, resolve } = await routed({
      selectDeny: ["acme/coder"],
      dispatchDeny: [],
    });
    const route = await resolve();
    expect(Object.isFrozen(route.model)).toBe(true);
    expect(() => {
      (route.model as { id: string }).id = "acme/general";
    }).toThrow();
    expect(() => stream(runtime, route.model)).not.toThrow();
  });

  it("Pi-native: routes when the allowlist narrows to the virtual model, and once through a rebased copy", async () => {
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
      apiKey: "sk-native",
      models: [model("acme/coder"), model("acme/general")],
    });
    // A provider whose credential carries its own base URL; Pi then sends
    // the request on a copy of the model with that URL.
    const rebasedUrl = `${services.gatewayUrl}/`;
    runtime.getAuth = (async () => ({
      auth: { apiKey: "sk-native", baseUrl: rebasedUrl },
      source: "test",
    })) as never;
    const events: string[] = [];
    const governed = governModelRuntime(
      runtime,
      {
        kind: "pi-native",
        // An enforced virtual model: the only selectable model.
        allowedModelKeys: ["acmecode/acme/auto"],
        restricted: true,
        dispatchModelKeys: ["acmecode/acme/auto", "acmecode/acme/coder"],
      },
      {
        selects: () => true,
        denied: (action, provider, id) =>
          events.push(`${action} ${provider}/${id}`),
      },
      [
        {
          provider: "acmecode",
          id: "acme/auto",
          routes: [{ provider: "acmecode", id: "acme/coder" }],
          router: "./extensions/router.ts",
        },
      ],
    );
    governed.withRegistrationWindow(() =>
      runtime.registerVirtualModel({
        provider: "acmecode",
        id: "acme/auto",
        name: "Auto",
        route: () => ({
          model: { ...model("acme/coder"), provider: "acmecode" } as never,
          thinkingLevel: "off",
        }),
      }),
    );
    const auto = runtime.getModel("acmecode", "acme/auto");
    if (!auto) throw new Error("virtual model not selectable");
    expect(governed.isSelectable("acmecode", "acme/coder")).toBe(false);
    const route = await runtime.resolveModel(auto, [], {
      reason: "direct",
      thinkingLevel: "off",
    });
    // The main path: Pi streams the routed model and looks its credential
    // up inside the request. That lookup leaves no claim behind, so a copy
    // with the base URL right after is an unrouted request.
    await stream(runtime, route.model).result();
    expect(() =>
      stream(runtime, { ...route.model, baseUrl: rebasedUrl }),
    ).toThrow("not allowed");
    // Pi's own lookup before it sends a rebased copy of the next routed
    // request opens the claim.
    const next = await runtime.resolveModel(auto, [], {
      reason: "direct",
      thinkingLevel: "off",
    });
    const auth = await runtime.getAuth(next.model);
    expect(auth?.auth.baseUrl).toBe(rebasedUrl);
    const rebased = { ...next.model, baseUrl: rebasedUrl };
    await stream(runtime, rebased).result();
    // The mark is claimed once: another copy is an unrouted request.
    expect(() => stream(runtime, { ...rebased })).toThrow("not allowed");
    expect(events).toEqual([
      "model.select acmecode/acme/coder",
      "model.select acmecode/acme/coder",
    ]);
  });

  it("checks a routed model by model.select when no model.dispatch rule decides it", async () => {
    const { resolve, events } = await routed({ selectDeny: ["acme/coder"] });
    await expect(resolve()).rejects.toMatchObject({ code: "MODEL_DENIED" });
    expect(events).toEqual(["model.dispatch acmecode/acme/coder"]);
  });

  it("refuses a route outside the declared routes before any request", async () => {
    const { runtime, auto, routeTo, resolve, events, keyRequests } =
      await routed();
    routeTo("acme/general");
    await expect(resolve()).rejects.toMatchObject({ code: "MODEL_DENIED" });
    expect(events).toEqual([
      "model.dispatch acmecode/acme/general (not a declared route)",
    ]);
    const result = await stream(runtime, auto).result();
    expect(result).toMatchObject({ stopReason: "error" });
    expect(result.errorMessage).toContain("not a declared route");
    expect(keyRequests()).toBe(0);
  });

  it("refuses an undeclared or unselectable virtual model in resolveModel", async () => {
    const options = {
      reason: "direct" as const,
      thinkingLevel: "off" as const,
    };
    const denied = await routed({ selectDeny: ["acme/auto"] });
    await expect(
      denied.runtime.resolveModel({ ...denied.auto }, [], options),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
    const undeclared = await routed();
    await expect(
      undeclared.runtime.resolveModel(
        { ...undeclared.auto, id: "acme/other-auto" },
        [],
        options,
      ),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
    expect(undeclared.events).toEqual([
      "model.select acmecode/acme/other-auto",
    ]);
  });

  it("returns an error result for a denied classifier or image model, without a request", async () => {
    const { runtime, events, keyRequests } = await routed({
      selectDeny: ["acme/classify", "acme/image"],
    });
    const classified = await runtime.classify(
      classifier() as never,
      { messages: [] } as never,
    );
    expect(classified).toMatchObject({
      stopReason: "error",
      answers: {},
      model: "acme/classify",
    });
    expect(classified.errorMessage).toMatch(/^MODEL_DENIED: /);
    const images = await runtime.generateImages(
      physical("acme/image", {
        api: "openrouter-images",
        type: "image",
        output: ["image"],
      }) as never,
      { messages: [] } as never,
    );
    expect(images).toMatchObject({ stopReason: "error", output: [] });
    expect(images.errorMessage).toMatch(/^MODEL_DENIED: /);
    expect(events).toEqual([
      "model.select acmecode/acme/classify",
      "model.select acmecode/acme/image",
    ]);
    expect(keyRequests()).toBe(0);
  });

  it("refuses deferred requests for a denied model before any request", async () => {
    const { runtime, keyRequests } = await routed({
      selectDeny: ["acme/general"],
    });
    const general = physical("acme/general") as never;
    const handle = { id: "deferred" } as never;
    expect(() => runtime.streamDeferred(general, handle)).toThrow(
      "not allowed",
    );
    await expect(runtime.fetchDeferred(general, handle)).rejects.toMatchObject({
      code: "MODEL_DENIED",
    });
    await expect(runtime.cancelDeferred(general, handle)).rejects.toMatchObject(
      { code: "MODEL_DENIED" },
    );
    expect(keyRequests()).toBe(0);
  });

  it("hides denied classifier and image models from the type-aware listings", async () => {
    const { runtime } = await routed({ selectDeny: ["acme/classify"] });
    expect(runtime.getModelsOfType("classifier", "acmecode")).toEqual([]);
    expect(
      runtime.getModelOfType("classifier", "acmecode", "acme/classify"),
    ).toBeUndefined();
    expect(
      runtime.getModelsOfType("image", "acmecode").map((item) => item.id),
    ).toEqual(["acme/image"]);
    expect(await runtime.getAvailableOfType("classifier")).toEqual([]);
    expect(
      runtime.getAllModels("acmecode").map((item) => item.id),
    ).not.toContain("acme/classify");
    expect(
      (await runtime.getAllAvailable()).map((item) => item.id),
    ).not.toContain("acme/classify");
  });

  it("refuses registering or unregistering a virtual model outside PiShip's registration", async () => {
    const { runtime, governed, events } = await routed();
    const definition = {
      provider: "acmecode",
      id: "acme/late",
      name: "Late",
      route: () => ({
        model: physical("acme/coder") as never,
        thinkingLevel: "off" as const,
      }),
    };
    expect(() => runtime.registerVirtualModel(definition)).toThrow(
      expect.objectContaining({ code: "POLICY_DENIED" }),
    );
    expect(() =>
      runtime.unregisterVirtualModel("acmecode", "acme/auto"),
    ).toThrow(expect.objectContaining({ code: "POLICY_DENIED" }));
    expect(runtime.getModel("acmecode", "acme/auto")).toBeDefined();
    expect(runtime.getModel("acmecode", "acme/late")).toBeUndefined();
    expect(events).toEqual([
      "model.select acmecode/acme/late",
      "model.select acmecode/acme/auto",
    ]);
    governed.withRegistrationWindow(() =>
      runtime.unregisterVirtualModel("acmecode", "acme/auto"),
    );
    expect(runtime.getModel("acmecode", "acme/auto")).toBeUndefined();
  });

  it("preserves the required-control refusal when its denial audit fails", async () => {
    const unavailable = new PiShipError(
      "AUDIT_UNAVAILABLE",
      "Audit is unavailable",
    );
    const denied = vi.fn(() => {
      throw new Error("audit delivery failed");
    });
    const { runtime, keyRequests } = await routed({
      available: () => {
        throw unavailable;
      },
      onDenied: denied,
    });
    expect(() => stream(runtime, physical("acme/coder"))).toThrow(unavailable);
    expect(denied).toHaveBeenCalledWith(
      "model.dispatch",
      "acmecode",
      "acme/coder",
      { error: "AUDIT_UNAVAILABLE" },
    );
    expect(keyRequests()).toBe(0);
  });

  it("keeps the required-control gate on routed, classifier, and deferred requests", async () => {
    let down = false;
    const { runtime, resolve, keyRequests, events } = await routed({
      available: () => {
        if (down)
          throw new PiShipError("AUDIT_UNAVAILABLE", "Audit is unavailable");
      },
    });
    const route = await resolve();
    down = true;
    expect(() => stream(runtime, route.model)).toThrow("Audit is unavailable");
    const classified = await runtime.classify(
      classifier() as never,
      { messages: [] } as never,
    );
    expect(classified.errorMessage).toMatch(/^AUDIT_UNAVAILABLE: /);
    await expect(
      runtime.fetchDeferred(physical("acme/coder") as never, {} as never),
    ).rejects.toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    expect(keyRequests()).toBe(0);
    expect(events.slice(-3)).toEqual([
      "model.dispatch acmecode/acme/coder",
      "model.dispatch acmecode/acme/classify",
      "model.dispatch acmecode/acme/coder",
    ]);
  });
});
