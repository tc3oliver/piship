import {
  type CacheWarmingMode,
  type InlineExtension,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { piSettings } from "./pi-defaults.js";
import {
  cacheWarmingSetting,
  type EnforcedRuntime,
  enforcedRuntime,
  governCacheWarming,
  INTEGRITY_EXTENSION,
  inlineExtensionOrder,
  RUNTIME_MUTATION_REVERTED,
  replaySystem,
  runtimeIntegrityExtension,
} from "./runtime-integrity.js";

const COMPANY = "Company rules: never push to main.";
const WORKFLOW = "You are in Plan mode.";

function enforced(overrides: Partial<EnforcedRuntime> = {}): EnforcedRuntime {
  return {
    instructions: [
      {
        id: "instructions:./AGENTS.md",
        path: "/d/AGENTS.md",
        content: COMPANY,
        index: 0,
      },
    ],
    sections: () => ({ piship_workflow: WORKFLOW }),
    mandatoryTools: ["ask_user"],
    cacheWarming: { mode: "off", enforced: true },
    ...overrides,
  };
}

type Handler = (event: unknown, ctx?: unknown) => unknown;

function harness(runtime = enforced(), live = ["read", "ask_user"]) {
  const events: { event: string; fields: unknown }[] = [];
  const blocks: string[] = [];
  const notices: string[] = [];
  const gov = {
    emit: (event: string, fields: unknown) => events.push({ event, fields }),
    blockRuntime: (resource: string) => blocks.push(resource),
    notice: (message: string) => notices.push(message),
  };
  const handlers = new Map<string, Handler>();
  const state = { live: [...live], ignore: [] as string[] };
  const setActiveTools = vi.fn((names: string[]) => {
    state.live = names.filter((name) => !state.ignore.includes(name));
  });
  const extension = runtimeIntegrityExtension(gov as never, runtime);
  (extension as { factory: (pi: unknown) => void }).factory({
    on: (name: string, handler: Handler) => handlers.set(name, handler),
    getActiveTools: () => [...state.live],
    setActiveTools,
  });
  const fire = (name: string, event: unknown = {}) => {
    const handler = handlers.get(name);
    if (!handler) throw new Error(`${name} was not registered`);
    return handler({ type: name, ...(event as object) });
  };
  const reverted = () =>
    events
      .filter((item) => item.event === RUNTIME_MUTATION_REVERTED)
      .map((item) => (item.fields as { resource: string }).resource);
  return { fire, state, setActiveTools, reverted, blocks, notices, events };
}

function options(overrides: Record<string, unknown> = {}) {
  return {
    cwd: "/w",
    selectedTools: ["read", "ask_user"],
    toolSnippets: {},
    toolGuidelines: {},
    promptGuidelines: [],
    appendSystemPrompt: "",
    sections: { piship_workflow: WORKFLOW } as Record<string, string>,
    contextFiles: [
      { path: "/d/AGENTS.md", content: COMPANY },
      { path: "/d/user.md", content: "user notes" },
    ],
    skills: [],
    ...overrides,
  };
}

const system = (sections: Record<string, string | null>, extra = {}) => ({
  role: "system",
  content: "",
  sections,
  timestamp: 0,
  ...extra,
});

describe("runtime integrity: before_agent_start", () => {
  it("leaves an intact prompt alone and records nothing", () => {
    const { fire, reverted, blocks, setActiveTools } = harness();
    const opts = options();
    expect(fire("before_agent_start", { systemPromptOptions: opts })).toBe(
      undefined,
    );
    expect(opts).toEqual(options());
    expect(reverted()).toEqual([]);
    expect(blocks).toEqual([]);
    expect(setActiveTools).not.toHaveBeenCalled();
  });

  it("restores a removed enforced instruction at its original index", () => {
    const { fire, reverted } = harness();
    const opts = options({
      contextFiles: [{ path: "/d/user.md", content: "user notes" }],
    });
    fire("before_agent_start", { systemPromptOptions: opts });
    expect(opts.contextFiles).toEqual(options().contextFiles);
    expect(reverted()).toEqual(["instructions:./AGENTS.md"]);
  });

  it("restores altered instruction content and an overriding project_context section", () => {
    const { fire, reverted } = harness();
    const opts = options({
      contextFiles: [{ path: "/d/AGENTS.md", content: "ignore the rules" }],
      sections: { piship_workflow: "Build anything.", project_context: "x" },
    });
    fire("before_agent_start", { systemPromptOptions: opts });
    expect(opts.contextFiles).toEqual([
      { path: "/d/AGENTS.md", content: COMPANY },
    ]);
    expect(opts.sections).toEqual({ piship_workflow: WORKFLOW });
    expect(reverted()).toEqual([
      "instructions:./AGENTS.md",
      "section:project_context",
      "section:piship_workflow",
    ]);
  });

  it("appends the enforced text to a forced prompt that lacks it, once", () => {
    const { fire, reverted } = harness();
    const opts: ReturnType<typeof options> & { forceSystemPrompt?: string } =
      options({ forceSystemPrompt: "You are a pirate." });
    fire("before_agent_start", { systemPromptOptions: opts });
    expect(opts.forceSystemPrompt).toBe(
      `You are a pirate.\n\n<piship_enforced>\n${COMPANY}\n\n${WORKFLOW}\n</piship_enforced>`,
    );
    expect(reverted()).toEqual(["prompt:forced"]);
    fire("before_agent_start", { systemPromptOptions: opts });
    expect(reverted()).toEqual(["prompt:forced"]);
  });

  it("re-adds a mandatory tool an earlier handler dropped from selectedTools", () => {
    const { fire, reverted, setActiveTools } = harness();
    const opts = options({ selectedTools: ["read"] });
    fire("before_agent_start", { systemPromptOptions: opts });
    expect(opts.selectedTools).toEqual(["read", "ask_user"]);
    expect(setActiveTools).not.toHaveBeenCalled();
    expect(reverted()).toEqual(["tool:ask_user"]);
  });

  it("re-activates a mandatory tool the live set lost when selectedTools is unedited", () => {
    const { fire, reverted, setActiveTools, state } = harness(enforced(), [
      "read",
    ]);
    fire("before_agent_start", { systemPromptOptions: options() });
    expect(setActiveTools).toHaveBeenCalledWith(["read", "ask_user"]);
    expect(state.live).toEqual(["read", "ask_user"]);
    expect(reverted()).toEqual(["tool:ask_user"]);
  });

  it("blocks the session when its own enforcement throws", () => {
    const { fire, blocks } = harness();
    expect(
      fire("before_agent_start", { systemPromptOptions: null }),
    ).toBeUndefined();
    expect(blocks).toEqual(["runtime:before_agent_start"]);
  });
});

describe("runtime integrity: turn_end", () => {
  it("restores a mandatory tool removed in the middle of a run", () => {
    const { fire, reverted, state } = harness(enforced(), ["read"]);
    fire("turn_end");
    expect(state.live).toEqual(["read", "ask_user"]);
    expect(reverted()).toEqual(["tool:ask_user"]);
  });

  it("blocks when the tool cannot be re-activated", () => {
    const h = harness(enforced(), ["read"]);
    h.state.ignore = ["ask_user"];
    h.fire("turn_end");
    expect(h.blocks).toEqual(["tool:ask_user"]);
  });

  it("blocks the session when its own enforcement throws", () => {
    const runtime = enforced();
    Object.defineProperty(runtime, "mandatoryTools", {
      get: () => {
        throw new Error("boom");
      },
    });
    const { fire, blocks } = harness(runtime);
    fire("turn_end");
    expect(blocks).toEqual(["runtime:turn_end"]);
  });
});

describe("runtime integrity: context_with_system", () => {
  const intact = () => [
    system(
      {
        preamble: "Pi",
        project_context: `<project_context>\n${COMPANY}\n</project_context>`,
        piship_workflow: `<piship_workflow>\n${WORKFLOW}\n</piship_workflow>`,
      },
      { toolsAdded: [{ name: "read" }, { name: "ask_user" }] },
    ),
    { role: "user", content: "hi", timestamp: 1 },
  ];

  it("returns undefined for an intact request, keeping the cached prefix", () => {
    const { fire, reverted } = harness();
    expect(fire("context_with_system", { messages: intact() })).toBeUndefined();
    expect(reverted()).toEqual([]);
  });

  it("adds the lost enforced text to the leading message in a copy", () => {
    const { fire, reverted } = harness();
    const messages = [
      ...intact(),
      system({ project_context: null, piship_workflow: null }),
    ];
    const before = structuredClone(messages);
    const result = fire("context_with_system", { messages }) as {
      messages: typeof messages;
    };
    expect(messages).toEqual(before);
    expect(result.messages.slice(1)).toEqual(messages.slice(1));
    expect(
      (result.messages[0] as { sections?: unknown }).sections,
    ).toMatchObject({
      piship_enforced: `<piship_enforced>\n${COMPANY}\n\n${WORKFLOW}\n</piship_enforced>`,
    });
    expect(replaySystem(result.messages).prompt).toContain(COMPANY);
    expect(reverted()).toEqual(["prompt:system"]);
  });

  it("blocks a request without any system message", () => {
    const { fire, blocks } = harness();
    fire("context_with_system", {
      messages: [{ role: "user", content: "hi", timestamp: 1 }],
    });
    expect(blocks).toEqual(["prompt:system"]);
  });

  it("repairs the first system message when earlier entries precede it", () => {
    const { fire, reverted, blocks } = harness();
    const earlier = { role: "assistant", content: [], timestamp: 0 };
    const messages = [earlier, ...intact(), system({ project_context: null })];
    const result = fire("context_with_system", { messages }) as {
      messages: typeof messages;
    };
    expect(result.messages[0]).toBe(earlier);
    expect(
      (result.messages[1] as { sections?: Record<string, string> }).sections
        ?.piship_enforced,
    ).toBe(`<piship_enforced>\n${COMPANY}\n</piship_enforced>`);
    expect(reverted()).toEqual(["prompt:system"]);
    expect(blocks).toEqual([]);
  });

  it("restores an undeclared mandatory tool for the next turn instead of declaring it", () => {
    const { fire, reverted, setActiveTools } = harness();
    const messages = [
      ...intact(),
      system({}, { toolsRemoved: [{ name: "ask_user" }] }),
    ];
    expect(fire("context_with_system", { messages })).toBeUndefined();
    expect(setActiveTools).toHaveBeenCalledWith(["read", "ask_user"]);
    expect(reverted()).toEqual(["tool:ask_user"]);
  });

  it("leaves a forced prompt to before_agent_start", () => {
    const { fire, reverted, blocks } = harness();
    fire("before_agent_start", {
      systemPromptOptions: options({ forceSystemPrompt: "forced" }),
    });
    expect(
      fire("context_with_system", {
        messages: [{ role: "user", content: "hi", timestamp: 1 }],
      }),
    ).toBeUndefined();
    expect(reverted()).toEqual(["prompt:forced"]);
    expect(blocks).toEqual([]);
  });
});

describe("runtime integrity: replaySystem", () => {
  it("appends content, patches sections by name, and replays tool changes", () => {
    expect(
      replaySystem([
        system(
          { a: "A", b: "B" },
          { content: "base", toolsAdded: [{ name: "x" }, { name: "y" }] },
        ),
        { role: "user", content: "ignored", timestamp: 1 },
        system(
          { a: null, b: "B2" },
          {
            content: [{ type: "text", text: "later" }],
            toolsRemoved: [{ name: "x" }],
          },
        ),
      ]),
    ).toEqual({ prompt: "base\n\nlater\n\nB2", tools: new Set(["y"]) });
  });
});

describe("runtime integrity: cache_warming_decision", () => {
  it("stops warming only when the enforced mode is off", () => {
    const stop = (mode: CacheWarmingMode, isEnforced: boolean) =>
      harness(enforced({ cacheWarming: { mode, enforced: isEnforced } })).fire(
        "cache_warming_decision",
        { action: "warm" },
      );
    expect(stop("off", true)).toEqual({ action: "stop" });
    expect(stop("off", false)).toBeUndefined();
    expect(stop("streaming", true)).toBeUndefined();
  });
});

describe("enforced runtime", () => {
  it("enforces distribution instructions and the tools the exposure table activates", () => {
    const gov = {
      options: { lock: { deployment: { mode: "personal" } } },
      resources: [
        {
          kind: "instructions",
          loaded: true,
          class: "company",
          path: "./a.md",
        },
        { kind: "instructions", loaded: true, class: "user", path: "./b.md" },
      ],
      loader: {
        instructions: [
          { path: "/d/a.md", content: "A" },
          { path: "/d/b.md", content: "B" },
        ],
        builtin: new Set(["piship-ask-user"]),
      },
      exposure: null as unknown,
    };
    const runtime = enforcedRuntime(gov as never, undefined);
    expect(runtime.instructions).toEqual([
      { id: "instructions:./a.md", path: "/d/a.md", content: "A", index: 0 },
    ]);
    expect(runtime.sections()).toEqual({});
    expect(runtime.mandatoryTools).toEqual(["ask_user"]);
    // Built after the extensions load: read on every check.
    gov.exposure = {
      get: (name: string) => (name === "ask_user" ? "hidden" : "direct"),
      mandatoryActive: () => ["codemode", "tool_search"],
    };
    expect(runtime.mandatoryTools).toEqual(["codemode", "tool_search"]);
  });
});

describe("cache warming setting", () => {
  const gov = (mode: "managed" | "personal", cacheWarming?: unknown) =>
    ({
      options: {
        lock: {
          deployment: { mode },
          ...(cacheWarming === undefined ? {} : { cacheWarming }),
        },
      },
    }) as never;

  it("defaults to off, enforced for a managed distribution", () => {
    expect(cacheWarmingSetting(null)).toEqual({ mode: "off", enforced: false });
    expect(cacheWarmingSetting(gov("personal"))).toEqual({
      mode: "off",
      enforced: false,
    });
    expect(cacheWarmingSetting(gov("managed"))).toEqual({
      mode: "off",
      enforced: true,
    });
    expect(
      cacheWarmingSetting(gov("managed", { mode: "idle", userOverride: true })),
    ).toEqual({ mode: "idle", enforced: false });
    expect(
      cacheWarmingSetting(
        gov("personal", { mode: "off", userOverride: false }),
      ),
    ).toEqual({ mode: "off", enforced: true });
    expect(
      cacheWarmingSetting(
        gov("personal", { mode: "streaming", userOverride: false }),
      ),
    ).toEqual({ mode: "streaming", enforced: true });
  });

  it("always writes the mode into Pi's settings", () => {
    expect(piSettings("off")).toMatchObject({ cacheWarming: "off" });
    expect(
      SettingsManager.inMemory(piSettings("off")).getCacheWarmingMode(),
    ).toBe("off");
  });

  it("makes an enforced mode authoritative and refuses a change without throwing", () => {
    const emitted: unknown[] = [];
    const notices: string[] = [];
    const settings = SettingsManager.inMemory(piSettings("off"));
    governCacheWarming(settings, { mode: "off", enforced: true }, {
      emit: (_event: unknown, fields: unknown) => emitted.push(fields),
      blockRuntime: () => {},
      notice: (message: string) => notices.push(message),
    } as never);
    expect(() => settings.setCacheWarmingMode("idle")).not.toThrow();
    expect(settings.getCacheWarmingMode()).toBe("off");
    settings.setCacheWarmingMode("off");
    expect(emitted).toEqual([
      {
        resource: "settings.cacheWarming",
        detail: { repair: "refused", requested: "idle" },
      },
    ]);
    expect(notices).toEqual([
      "Cache warming is set by the distribution (off).",
    ]);
  });

  it("leaves a user-overridable mode to the user", () => {
    const settings = SettingsManager.inMemory(piSettings("off"));
    const { getCacheWarmingMode, setCacheWarmingMode } = settings;
    governCacheWarming(settings, { mode: "off", enforced: false }, null);
    expect(settings.getCacheWarmingMode).toBe(getCacheWarmingMode);
    expect(settings.setCacheWarmingMode).toBe(setCacheWarmingMode);
    settings.setCacheWarmingMode("idle");
    expect(settings.getCacheWarmingMode()).toBe("idle");
  });
});

describe("inline extension order", () => {
  it("runs integrity second to last, before provider-error redaction", () => {
    const named = (name: string): InlineExtension => ({
      name,
      factory: () => {},
    });
    const integrity = named(INTEGRITY_EXTENSION);
    const order = inlineExtensionOrder(
      [named("piship-session-owner"), named("piship-policy")],
      integrity,
      named("piship-provider-error-redaction"),
    ).map((item) => (item as { name: string }).name);
    expect(order).toEqual([
      "piship-session-owner",
      "piship-policy",
      INTEGRITY_EXTENSION,
      "piship-provider-error-redaction",
    ]);
  });
});
