// Pi compatibility of model governance (09-B4): every Pi path that sends a
// model request with a virtual selection (agent loop, an extension's direct
// stream, compaction, the cache warmer's stream) passes PiShip's model
// runtime after Pi routes it, and the virtual model registration PiShip
// takes over from Pi behaves as asserted. Runs against the pinned Pi and a
// loopback gateway fixture; a Pi upgrade that changes one of these seams
// must fail here.
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createAgentSession,
  DefaultResourceLoader,
  type ExtensionContext,
  type InlineExtension,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  governModelRuntime,
  type GovernedRuntime,
  type ModelPolicy,
  PI_VIRTUAL_MODEL_API,
  type VirtualModelRule,
} from "./governance.js";
import type { ManagedFetch } from "@piship/contracts";
import { type ActivatedAccess, resolveLock } from "@piship/core";
import type { CatalogModel } from "@piship/schema";
import { GovernanceSession } from "./governance-session.js";
import type { LaunchContext, PreparedAccess } from "./launch/context.js";
import { modelPolicy } from "./launch/governance.js";
import { createModelRuntime } from "./launch/model-runtime.js";
import { governVirtualModels } from "./launch/virtual-models.js";

const API_KEY = "sk-compat-models-key";
const cost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
const chat = (id: string) => ({
  id,
  name: id,
  reasoning: false,
  input: ["text" as const],
  cost,
  contextWindow: 64000,
  maxTokens: 4096,
});

// The router the fixture extension reads, so a test can change its answer.
interface RouterControl {
  target: string;
  /** Register nothing (a reload that drops the router). */
  skip?: boolean;
  id?: string;
}
const control = globalThis as unknown as { __pishipRouter?: RouterControl };
const ROUTER_SOURCE = `export default function (pi) {
  const control = globalThis.__pishipRouter;
  if (control && control.skip) return;
  pi.registerVirtualModel({
    provider: "acmecode",
    id: (control && control.id) || "acme/auto",
    name: "Acme Auto",
    contextWindow: 64000,
    maxTokens: 4096,
    route: () => ({
      model: { provider: "acmecode", id: globalThis.__pishipRouter.target },
      thinkingLevel: "off",
    }),
  });
}
`;

let services: Awaited<ReturnType<typeof startLocalServices>>;
let temp: string;
let routerPath: string;
beforeEach(async () => {
  services = await startLocalServices({ knobs: { acceptedKeys: [API_KEY] } });
  temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-compat-models-")));
  routerPath = join(temp, "resources", "extensions", "router.ts");
  mkdirSync(join(temp, "resources", "extensions"), { recursive: true });
  writeFileSync(routerPath, ROUTER_SOURCE);
  control.__pishipRouter = { target: "acme/coder" };
});
afterEach(async () => {
  await services.close();
  rmSync(temp, { recursive: true, force: true });
  delete control.__pishipRouter;
});

const completions = (): string[] =>
  services.state.requests
    .filter((item: { path: string }) => item.path.endsWith("/chat/completions"))
    .map((item: { body: string }) => JSON.parse(item.body).model);

/** The managed runtime of these tests, governed with every model allowed. */
async function testRuntime(
  rule: VirtualModelRule,
  denied: string[],
  policy: ModelPolicy | undefined,
): Promise<{ runtime: ModelRuntime; governed: GovernedRuntime }> {
  const runtime = await ModelRuntime.create({
    credentials: {
      read: async () => undefined as never,
      list: async () => [],
      modify: async () => undefined as never,
      delete: async () => {},
    } as never,
    modelsPath: null,
    refreshOnCreate: false,
    allowModelNetwork: false,
  });
  runtime.registerProvider("acmecode", {
    name: "AcmeCode",
    baseUrl: services.gatewayUrl,
    api: "openai-completions",
    models: [
      chat("acme/coder"),
      chat("acme/general"),
      {
        id: "acme/classify",
        name: "Classify",
        type: "classifier",
        api: "llama-cpp-classify",
        input: ["text"],
        cost,
        contextWindow: 4096,
      },
    ],
  });
  const governed = governModelRuntime(
    runtime,
    {
      kind: "managed-endpoint",
      providerId: "acmecode",
      allowedModelIds: [
        "acme/coder",
        "acme/general",
        "acme/classify",
        "acme/auto",
      ],
      dispatchModelIds: ["acme/coder", "acme/general", "acme/classify"],
      apiKey: async () => API_KEY,
    },
    {
      selects: () => true,
      denied: (action, provider, id) =>
        denied.push(`${action} ${provider}/${id}`),
      ...policy,
    },
    [rule],
  );
  return { runtime, governed };
}

async function launch(
  options: {
    policy?: ModelPolicy;
    extensions?: InlineExtension[];
    sessionManager?: SessionManager;
    /** Select the virtual model (default) or let Pi restore one. */
    select?: boolean;
    routerPath?: string;
    routes?: string[];
    /** The runtime as launch creates it, instead of this test's own. */
    create?: (
      rule: VirtualModelRule,
    ) => Promise<{ runtime: ModelRuntime; governed: GovernedRuntime }>;
  } = {},
) {
  const rule: VirtualModelRule = {
    provider: "acmecode",
    id: "acme/auto",
    routes: (options.routes ?? ["acme/coder"]).map((id) => ({
      provider: "acmecode",
      id,
    })),
    router: "./extensions/router.ts",
    routerPath: options.routerPath ?? routerPath,
  };
  const denied: string[] = [];
  const { runtime, governed } = options.create
    ? await options.create(rule)
    : await testRuntime(rule, denied, options.policy);
  const settingsManager = SettingsManager.inMemory({
    retry: { enabled: false },
    compaction: { keepRecentTokens: 1 },
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
    additionalExtensionPaths: [routerPath],
    extensionFactories: options.extensions ?? [],
  });
  await resourceLoader.reload();
  const pending = resourceLoader
    .getExtensions()
    .runtime.pendingVirtualModelRegistrations.map((item) => ({
      id: item.definition.id,
      extensionPath: item.extensionPath,
    }));
  governVirtualModels(resourceLoader, governed, runtime, [rule]);
  const auto = runtime.getModel("acmecode", "acme/auto");
  const { session } = await createAgentSession({
    cwd: temp,
    agentDir: temp,
    modelRuntime: runtime,
    ...(options.select === false || !auto ? {} : { model: auto }),
    settingsManager,
    sessionManager: options.sessionManager ?? SessionManager.inMemory(temp),
    resourceLoader,
    noTools: "builtin",
    customTools: [],
  });
  return { runtime, session, governed, resourceLoader, pending, denied };
}
const lastAssistant = (session: { messages: unknown[] }) =>
  session.messages.at(-1) as { stopReason?: string; errorMessage?: string };

describe("Pi model governance seams", () => {
  it("exposes every ModelRuntime method model governance wraps", () => {
    const prototype = ModelRuntime.prototype as unknown as Record<
      string,
      unknown
    >;
    for (const method of [
      "resolveModel",
      "getPhysicalModel",
      "hasConfiguredAuth",
      "registerVirtualModel",
      "unregisterVirtualModel",
      "classify",
      "generateImages",
      "streamDeferred",
      "fetchDeferred",
      "cancelDeferred",
      "getModelsOfType",
      "getModelOfType",
      "getAllModels",
      "getAvailableOfType",
      "getAllAvailable",
    ])
      expect(typeof prototype[method], method).toBe("function");
  });

  it("gives a registered virtual model the pi-virtual API", async () => {
    const { runtime } = await launch();
    expect(PI_VIRTUAL_MODEL_API).toBe("pi-virtual");
    expect(runtime.getModel("acmecode", "acme/auto")?.api).toBe(
      PI_VIRTUAL_MODEL_API,
    );
  });

  it("queues a load-time registration with its extension path, and registers nothing more once PiShip empties the queue", async () => {
    const { pending, resourceLoader, runtime } = await launch();
    expect(pending).toEqual([{ id: "acme/auto", extensionPath: routerPath }]);
    expect(
      resourceLoader.getExtensions().runtime.pendingVirtualModelRegistrations,
    ).toEqual([]);
    expect(
      runtime.getModels("acmecode").filter((model) => model.id === "acme/auto"),
    ).toHaveLength(1);
  });

  it("agent loop: sends the routed physical model, and nothing for a route outside the declared routes", async () => {
    const { session } = await launch();
    await session.prompt("hello");
    expect(session.getLastAssistantText()).toBe("Hello from acme/coder.");
    expect(completions()).toEqual(["acme/coder"]);
    control.__pishipRouter = { target: "acme/general" };
    await session.prompt("again");
    expect(lastAssistant(session)).toMatchObject({ stopReason: "error" });
    expect(lastAssistant(session).errorMessage).toContain(
      "not a declared route",
    );
    expect(completions()).toEqual(["acme/coder"]);
    session.dispose();
  });

  it("direct stream: an extension's ctx.modelRegistry.streamSimple of the virtual model is routed through the gate", async () => {
    let context: ExtensionContext | undefined;
    const { session } = await launch({
      extensions: [
        {
          name: "capture",
          factory: (pi) => {
            pi.on("before_agent_start", (_event, ctx) => {
              context = ctx;
            });
          },
        },
      ],
    });
    await session.prompt("hello");
    const registry = context?.modelRegistry;
    const auto = registry?.find("acmecode", "acme/auto");
    if (!registry || !auto) throw new Error("no extension context");
    const request = {
      messages: [{ role: "user" as const, content: "x", timestamp: 0 }],
    };
    const routed = await registry.streamSimple(auto, request).result();
    expect(routed.stopReason).toBe("stop");
    expect(completions()).toEqual(["acme/coder", "acme/coder"]);
    control.__pishipRouter = { target: "acme/general" };
    const refused = await registry.streamSimple(auto, request).result();
    expect(refused.stopReason).toBe("error");
    expect(completions()).toHaveLength(2);
    session.dispose();
  });

  it("compaction: the summary request goes to the routed model, and none to a refused one", async () => {
    const { session } = await launch();
    await session.prompt("hello");
    await session.prompt("more");
    await session.compact();
    // Summary requests besides the two prompts, all to the routed model.
    expect(completions().length).toBeGreaterThan(2);
    expect(new Set(completions())).toEqual(new Set(["acme/coder"]));
    await session.prompt("after the summary");
    const sent = completions().length;
    control.__pishipRouter = { target: "acme/general" };
    await expect(session.compact()).rejects.toThrow("not a declared route");
    expect(completions()).toHaveLength(sent);
    session.dispose();
  });

  it("cache warm: the routed model the warmer replays is the governed one, refused once dispatch no longer allows it", async () => {
    // The warmer records the model the sdk stream function received and
    // later calls modelRuntime.streamSimple(run.model) on the same runtime.
    let dispatchable = true;
    const { runtime, session } = await launch({
      policy: {
        selects: () => true,
        dispatches: () => dispatchable,
      },
    });
    const sent: unknown[] = [];
    const governedStream = runtime.streamSimple.bind(runtime);
    runtime.streamSimple = ((model: never, ...rest: never[]) => {
      sent.push(model);
      return (governedStream as (...args: unknown[]) => unknown)(
        model,
        ...rest,
      );
    }) as typeof runtime.streamSimple;
    await session.prompt("hello");
    const routed = sent.find(
      (model) => (model as { id: string }).id === "acme/coder",
    );
    expect(routed).toBeDefined();
    dispatchable = false;
    expect(() =>
      governedStream(routed as never, { messages: [] } as never),
    ).toThrow("not allowed");
    expect(completions()).toEqual(["acme/coder"]);
    session.dispose();
  });

  it("refuses an undeclared registration at load, and one an extension makes at runtime", async () => {
    await expect(
      launch({ routerPath: join(temp, "resources", "extensions", "other.ts") }),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    control.__pishipRouter = { target: "acme/coder", id: "acme/undeclared" };
    await expect(launch()).rejects.toMatchObject({ code: "MODEL_DENIED" });
    control.__pishipRouter = { target: "acme/coder" };
    let refusal: unknown;
    const { runtime, session } = await launch({
      extensions: [
        {
          name: "late",
          factory: (pi) => {
            pi.on("before_agent_start", () => {
              try {
                pi.registerVirtualModel({
                  provider: "acmecode",
                  id: "acme/late",
                  name: "Late",
                  route: () => ({
                    model: chat("acme/general") as never,
                    thinkingLevel: "off",
                  }),
                });
              } catch (error) {
                refusal = error;
              }
            });
          },
        },
      ],
    });
    await session.prompt("hello");
    expect(refusal).toMatchObject({ code: "POLICY_DENIED" });
    expect(runtime.getModel("acmecode", "acme/late")).toBeUndefined();
    session.dispose();
  });

  it("the agent's stream function is the governed runtime's, not pi-ai's raw stream", async () => {
    const { session } = await launch({
      policy: { selects: (_provider, id) => id !== "acme/general" },
    });
    const general = {
      ...chat("acme/general"),
      provider: "acmecode",
      api: "openai-completions",
      baseUrl: services.gatewayUrl,
    };
    // pi-ai's raw streamSimple would send this with the environment's keys.
    await expect(
      (async () =>
        session.agent.streamFunction(
          general as never,
          { messages: [] } as never,
        ))(),
    ).rejects.toThrow("not allowed");
    expect(completions()).toEqual([]);
    session.dispose();
  });

  it("classify through an extension's model registry: a denied classifier gets an error result and sends nothing", async () => {
    let context: ExtensionContext | undefined;
    const { session } = await launch({
      policy: { selects: (_provider, id) => id !== "acme/classify" },
      extensions: [
        {
          name: "capture",
          factory: (pi) => {
            pi.on("before_agent_start", (_event, ctx) => {
              context = ctx;
            });
          },
        },
      ],
    });
    await session.prompt("hello");
    const registry = context?.modelRegistry as unknown as {
      classify(
        model: unknown,
        context: unknown,
      ): Promise<{
        stopReason: string;
        errorMessage?: string;
      }>;
    };
    const result = await registry.classify(
      {
        ...chat("acme/classify"),
        provider: "acmecode",
        type: "classifier",
        api: "llama-cpp-classify",
      },
      { messages: [] },
    );
    expect(result.stopReason).toBe("error");
    expect(result.errorMessage).toMatch(/^MODEL_DENIED: /);
    expect(completions()).toEqual(["acme/coder"]);
    session.dispose();
  });

  it("resumes a session whose selection is the virtual model", async () => {
    const sessionDir = join(temp, "sessions");
    const first = await launch({
      sessionManager: SessionManager.create(temp, sessionDir),
    });
    await first.session.prompt("hello");
    const file = first.session.sessionManager.getSessionFile();
    first.session.dispose();
    if (!file) throw new Error("no session file");
    const resumed = await launch({
      sessionManager: SessionManager.open(file, sessionDir),
      select: false,
    });
    expect(resumed.session.model).toMatchObject({
      provider: "acmecode",
      id: "acme/auto",
      api: PI_VIRTUAL_MODEL_API,
    });
    resumed.session.dispose();
  });

  it("/reload registers the router's model again; a reload without the router fails closed", async () => {
    const { session, runtime } = await launch();
    await session.reload();
    expect(runtime.getModel("acmecode", "acme/auto")).toBeDefined();
    await session.prompt("hello");
    expect(completions()).toEqual(["acme/coder"]);
    control.__pishipRouter = { target: "acme/coder", skip: true };
    await session.reload();
    await session.prompt("again");
    // The old registration's router belongs to the replaced extensions.
    expect(lastAssistant(session)).toMatchObject({ stopReason: "error" });
    expect(completions()).toEqual(["acme/coder"]);
    session.dispose();
  });
});

// Launch's own runtime (createModelRuntime) and policy (modelPolicy), so the
// allowlist narrowing and the policy's deny-wins dispatch are checked
// against Pi's routing, not only the governance wrapper.
const catalogEntry = (id: string, routes?: string[]): CatalogModel => ({
  id,
  name: id,
  contextWindow: 64000,
  maxOutputTokens: 4096,
  input: ["text"],
  reasoning: false,
  tools: true,
  streaming: true,
  policyTags: [],
  type: "chat",
  ...(routes ? { virtual: { router: "./extensions/router.ts", routes } } : {}),
});

/** createModelRuntime for an activation whose effective allowlist is `allowed`. */
function launchRuntime(
  allowed: string[],
  policy?: ModelPolicy,
): (
  rule: VirtualModelRule,
) => Promise<{ runtime: ModelRuntime; governed: GovernedRuntime }> {
  return async (rule) => {
    const routes = rule.routes.map((route) => route.id);
    const catalog = [
      catalogEntry("acme/coder"),
      catalogEntry("acme/general"),
      catalogEntry("acme/auto", routes),
    ];
    const ctx = {
      agentDir: temp,
      metadata: {
        app: { name: "AcmeCode", command: "acme" },
        access: { models: { catalog } },
      },
    } as unknown as LaunchContext;
    const activated = {
      runtime: {
        kind: "managed-endpoint",
        providerId: "acmecode",
        baseUrl: services.gatewayUrl,
        api: "openai-completions",
        requiresCredential: true,
        models: catalog.map((entry) => ({
          id: entry.id,
          name: entry.name,
          provider: "acmecode",
          capabilities: {
            input: ["text"],
            contextWindow: 64000,
            maxOutputTokens: 4096,
          },
          policyTags: [],
          availability: { available: true },
        })),
      },
      config: { allowedModels: allowed, modelsRestricted: true },
      incompatibleModels: {},
    } as unknown as ActivatedAccess;
    const prepared = {
      activated,
      access: { requestSecret: async () => ({ reveal: () => API_KEY }) },
    } as unknown as PreparedAccess;
    const { modelRuntime, governed } = await createModelRuntime(
      ctx,
      prepared,
      policy,
      [rule],
    );
    if (!governed) throw new Error("not governed");
    return { runtime: modelRuntime, governed };
  };
}

const policySessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of policySessions.splice(0))
    await session.close().catch(() => undefined);
});

/** The distribution policy as launch resolves it, for a selected `acmecode/acme/auto`. */
async function launchPolicy(
  defaults: string[],
  enforced: string[],
  routes: string[],
): Promise<ModelPolicy> {
  const distribution = join(temp, "distribution");
  mkdirSync(distribution, { recursive: true });
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "1.1.0" }',
      "deployment: { mode: personal }",
      "policy:",
      "  id: unit",
      "  version: 1",
      "  default: deny",
      "  enforced:",
      ...enforced,
      "  defaults:",
      ...defaults,
      "",
    ].join("\n"),
  );
  const session = await GovernanceSession.open({
    lock: resolveLock(manifest) as Parameters<
      typeof GovernanceSession.open
    >[0]["lock"],
    distributionDir: distribution,
    stateDir: join(temp, "state"),
    cwd: temp,
    piVersion: "1.1.0",
    interactive: false,
    fetch: (() => {
      throw new Error("no network in compatibility tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: join(temp, "home"),
    user: "alice",
  });
  policySessions.push(session);
  return modelPolicy(session, "acmecode/acme/auto", [
    {
      provider: "acmecode",
      id: "acme/auto",
      routes: routes.map((id) => ({ provider: "acmecode", id })),
      router: "./extensions/router.ts",
    },
  ]);
}

describe("launch model governance against Pi routing", () => {
  it("routes a virtual model that is the only selectable model (enforced or narrowed), and keeps its routes unselectable", async () => {
    const { session, governed } = await launch({
      create: launchRuntime(["acme/auto"]),
    });
    expect(session.model).toMatchObject({ id: "acme/auto" });
    await session.prompt("hello");
    expect(session.getLastAssistantText()).toBe("Hello from acme/coder.");
    expect(completions()).toEqual(["acme/coder"]);
    expect(governed.isSelectable("acmecode", "acme/coder")).toBe(false);
    // A request for the route itself, not routed, is still refused.
    const coder = {
      ...chat("acme/coder"),
      provider: "acmecode",
      api: "openai-completions",
      baseUrl: services.gatewayUrl,
    };
    await expect(
      (async () =>
        session.agent.streamFunction(
          coder as never,
          { messages: [] } as never,
        ))(),
    ).rejects.toThrow("not allowed");
    expect(completions()).toEqual(["acme/coder"]);
    session.dispose();
  });

  it("a wildcard allow does not route around a model.select deny (deny wins)", async () => {
    const rule = (
      id: string,
      action: string,
      resource: string,
      effect: string,
    ) =>
      `    - { id: ${id}, action: "${action}", resource: "${resource}", effect: ${effect} }`;
    for (const wildcard of ["*", "model.*"]) {
      services.state.requests.length = 0;
      const policy = await launchPolicy(
        [rule("everything", wildcard, "acmecode/**", "allow")],
        [rule("no-general", "model.select", "acmecode/acme/general", "deny")],
        ["acme/coder", "acme/general"],
      );
      control.__pishipRouter = { target: "acme/general" };
      const { session } = await launch({
        routes: ["acme/coder", "acme/general"],
        create: launchRuntime(
          ["acme/coder", "acme/general", "acme/auto"],
          policy,
        ),
      });
      await session.prompt("hello");
      expect(lastAssistant(session), wildcard).toMatchObject({
        stopReason: "error",
      });
      expect(completions(), wildcard).toEqual([]);
      control.__pishipRouter = { target: "acme/coder" };
      await session.prompt("again");
      expect(session.getLastAssistantText(), wildcard).toBe(
        "Hello from acme/coder.",
      );
      session.dispose();
    }
  });
});
