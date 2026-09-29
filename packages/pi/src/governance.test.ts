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
import { governModelRuntime, isCredentialRejection } from "./governance.js";

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
  options: { keys: string[]; tools?: boolean } = { keys: [] },
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
    apiKey: async ({ force }) => {
      calls += 1;
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
});
