// Pi compatibility: every public Pi seam PiShip's managed, governance, and
// lifecycle surfaces rely on is asserted here individually, and exercised
// where that is cheap and deterministic (no network beyond loopback fixtures,
// no real model). A Pi upgrade that renames, removes, or changes one of these
// seams must fail here before it can silently weaken governance.
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import * as upstreamPi from "@earendil-works/pi-coding-agent";
import {
  type BashOperations,
  createAgentSession,
  createAgentSessionRuntime,
  createBashToolDefinition,
  createEditToolDefinition,
  createLocalBashOperations,
  createReadTool,
  createReadToolDefinition,
  createWriteToolDefinition,
  DefaultResourceLoader,
  type EditOperations,
  type InlineExtension,
  InteractiveMode,
  ModelRuntime,
  type ReadOperations,
  SessionManager,
  SettingsManager,
  type ToolDefinition,
  VERSION,
  type WriteOperations,
} from "@earendil-works/pi-coding-agent";
import { PI_VERSION } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { governModelRuntime, PINNED_PI_VERSION } from "./index.js";

// The tool definitions PiShip builds, called the way Pi's agent loop calls
// them: execute(toolCallId, params, signal, onUpdate, ctx).
type Execute = (
  id: string,
  params: unknown,
  signal: AbortSignal | undefined,
  onUpdate: undefined,
  ctx: undefined,
) => Promise<{ content: { type: string; text?: string }[] }>;
const run = (tool: unknown, params: unknown) =>
  (tool as { execute: Execute }).execute(
    "call_compat",
    params,
    undefined,
    undefined,
    undefined,
  );
const text = (result: { content: { type: string; text?: string }[] }) =>
  result.content.map((part) => part.text ?? "").join("");

const model = (id: string) => ({
  id,
  name: id,
  reasoning: false,
  input: ["text" as const],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 64000,
  maxTokens: 4096,
});

/** The in-memory credential store the managed runtime passes to Pi. */
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

const API_KEY = "sk-compat-fixture-key";

/** ModelRuntime.create + registerProvider, as the managed runtime does. */
async function managedRuntime(baseUrl: string) {
  const runtime = await ModelRuntime.create({
    credentials: memoryCredentials() as never,
    modelsPath: null,
    refreshOnCreate: false,
    allowModelNetwork: false,
  });
  runtime.registerProvider("acmecode", {
    name: "AcmeCode",
    baseUrl,
    apiKey: API_KEY,
    api: "openai-completions",
    models: [model("acme/coder"), model("acme/general")],
  });
  return runtime;
}

let temp: string;
beforeEach(() => {
  // Resolve symlinked temp roots (macOS /var -> /private/var) so the paths
  // Pi reports and the paths the test compares are the same.
  temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-pi-compat-")));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

function write(path: string, content: string): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  return path;
}

describe("Pi public SDK", () => {
  it("imports createAgentSession from the public package entrypoint", () => {
    expect(typeof upstreamPi.createAgentSession).toBe("function");
    expect(upstreamPi.VERSION).toBe(PINNED_PI_VERSION);
    expect(PI_VERSION).toBe(PINNED_PI_VERSION);
  });

  // Every value export PiShip imports from Pi. A rename or removal fails here
  // by name rather than as a type error in a distant module.
  it("exports every public value PiShip uses", () => {
    const exported = upstreamPi as unknown as Record<string, unknown>;
    for (const name of [
      "createAgentSessionRuntime",
      "createAgentSession",
      "DefaultResourceLoader",
      "ModelRuntime",
      "SessionManager",
      "SettingsManager",
      "InteractiveMode",
      "createReadTool",
      "createReadToolDefinition",
      "createWriteToolDefinition",
      "createEditToolDefinition",
      "createBashToolDefinition",
      "createLocalBashOperations",
    ])
      expect(typeof exported[name], name).toBe("function");
    expect(VERSION).toBe(PINNED_PI_VERSION);
    expect(typeof InteractiveMode.prototype.run).toBe("function");
    expect(typeof ModelRuntime.create).toBe("function");
    expect(typeof SettingsManager.inMemory).toBe("function");
    for (const factory of ["inMemory", "create", "open", "continueRecent"])
      expect(
        typeof (SessionManager as unknown as Record<string, unknown>)[factory],
        `SessionManager.${factory}`,
      ).toBe("function");
    const tool = createReadTool(temp);
    expect(tool.name).toBe("read");
    expect(typeof tool.execute).toBe("function");
  });

  // Managed model governance narrows these public ModelRuntime methods on the
  // instance PiShip creates. If an upgrade renames or removes one, governance
  // could be bypassed, so the upgrade must fail here first.
  it("exposes every ModelRuntime method that managed governance narrows", () => {
    const prototype = upstreamPi.ModelRuntime.prototype as unknown as Record<
      string,
      unknown
    >;
    for (const method of [
      "getModel",
      "getModels",
      "getAvailable",
      "getAvailableSnapshot",
      "checkAuth",
      "getAuth",
      "stream",
      "streamSimple",
      "complete",
      "completeSimple",
      "login",
      "setRuntimeApiKey",
      "registerProvider",
    ])
      expect(typeof prototype[method], method).toBe("function");
    expect(typeof upstreamPi.DefaultResourceLoader).toBe("function");
  });

  it("lists a provider registered with an in-memory credential store, and governance narrows it", async () => {
    const runtime = await managedRuntime("http://127.0.0.1:9/v1");
    const keys = (models: readonly { provider: string; id: string }[]) =>
      models
        .filter((item) => item.provider === "acmecode")
        .map((item) => `${item.provider}/${item.id}`);
    expect(keys(runtime.getModels("acmecode"))).toEqual([
      "acmecode/acme/coder",
      "acmecode/acme/general",
    ]);
    expect(keys(await runtime.getAvailable("acmecode"))).toEqual([
      "acmecode/acme/coder",
      "acmecode/acme/general",
    ]);
    expect(runtime.getModel("acmecode", "acme/general")).toBeDefined();
    governModelRuntime(runtime, {
      kind: "managed-endpoint",
      providerId: "acmecode",
      allowedModelIds: ["acme/coder"],
      apiKey: async () => API_KEY,
    });
    expect(keys(runtime.getModels("acmecode"))).toEqual([
      "acmecode/acme/coder",
    ]);
    expect(keys(await runtime.getAvailable())).toEqual(["acmecode/acme/coder"]);
    expect(runtime.getAvailableSnapshot().map((item) => item.id)).toEqual([
      "acme/coder",
    ]);
    expect(runtime.getModel("acmecode", "acme/general")).toBeUndefined();
  });
});

// Governed tools reuse Pi's tool definitions and supply only the file and
// command operations. Each definition must route every access through the
// override, or a governed tool would touch the disk behind the policy.
describe("Pi tool definitions route through their operations overrides", () => {
  // A cwd that does not exist: any access that bypasses the overrides fails.
  const cwd = () => join(temp, "virtual");

  it("read", async () => {
    const path = resolve(cwd(), "notes.txt");
    const calls: string[] = [];
    const operations: ReadOperations = {
      readFile: async (file) => {
        calls.push(`readFile ${file}`);
        return Buffer.from("virtual read content\n");
      },
      access: async (file) => {
        calls.push(`access ${file}`);
      },
    };
    const tool = createReadToolDefinition(cwd(), { operations });
    expect(tool.name).toBe("read");
    const result = await run(tool, { path: "notes.txt" });
    expect(text(result)).toContain("virtual read content");
    expect(calls).toEqual([`access ${path}`, `readFile ${path}`]);
  });

  it("read refuses when the access override throws", async () => {
    let read = false;
    const tool = createReadToolDefinition(cwd(), {
      operations: {
        readFile: async () => {
          read = true;
          return Buffer.from("");
        },
        access: async () => {
          throw new Error("compat: read denied");
        },
      },
    });
    await expect(run(tool, { path: "secret.txt" })).rejects.toThrow(
      "compat: read denied",
    );
    expect(read).toBe(false);
  });

  it("write", async () => {
    const path = resolve(cwd(), "nested", "out.txt");
    const calls: string[] = [];
    const operations: WriteOperations = {
      mkdir: async (dir) => {
        calls.push(`mkdir ${dir}`);
      },
      writeFile: async (file, content) => {
        calls.push(`writeFile ${file} ${content}`);
      },
    };
    const tool = createWriteToolDefinition(cwd(), { operations });
    expect(tool.name).toBe("write");
    await run(tool, { path: join("nested", "out.txt"), content: "hello" });
    expect(calls).toEqual([
      `mkdir ${dirname(path)}`,
      `writeFile ${path} hello`,
    ]);
    expect(readdirSync(temp)).toEqual([]);
  });

  it("edit", async () => {
    const path = resolve(cwd(), "code.ts");
    const calls: string[] = [];
    let written = "";
    const operations: EditOperations = {
      access: async (file) => {
        calls.push(`access ${file}`);
      },
      readFile: async (file) => {
        calls.push(`readFile ${file}`);
        return Buffer.from("const value = 1;\n");
      },
      writeFile: async (file, content) => {
        calls.push(`writeFile ${file}`);
        written = content;
      },
    };
    const tool = createEditToolDefinition(cwd(), { operations });
    expect(tool.name).toBe("edit");
    await run(tool, {
      path: "code.ts",
      edits: [{ oldText: "value = 1", newText: "value = 2" }],
    });
    expect(calls).toContain(`access ${path}`);
    expect(calls).toContain(`readFile ${path}`);
    expect(calls.at(-1)).toBe(`writeFile ${path}`);
    expect(written).toBe("const value = 2;\n");
    expect(readdirSync(temp)).toEqual([]);
  });

  it("bash", async () => {
    const calls: { command: string; cwd: string }[] = [];
    const operations: BashOperations = {
      exec: async (command, dir, options) => {
        calls.push({ command, cwd: dir });
        options.onData(Buffer.from("virtual output\n"));
        return { exitCode: 0 };
      },
    };
    const tool = createBashToolDefinition(cwd(), { operations });
    expect(tool.name).toBe("bash");
    const result = await run(tool, { command: "echo compat" });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.command).toContain("echo compat");
    expect(calls[0]?.cwd).toBe(cwd());
    expect(text(result)).toContain("virtual output");
  });

  it("bash refuses when the exec override throws", async () => {
    const tool = createBashToolDefinition(cwd(), {
      operations: {
        exec: async () => {
          throw new Error("compat: command denied");
        },
      },
    });
    await expect(run(tool, { command: "rm -rf /" })).rejects.toThrow(
      "compat: command denied",
    );
  });

  // Governed bash falls back to Pi's local shell backend when no sandbox is
  // enforced, with the same exec signature.
  it("createLocalBashOperations runs a command in the given cwd", async () => {
    const local = createLocalBashOperations();
    const chunks: Buffer[] = [];
    const ok = await local.exec("echo piship-local-bash", temp, {
      onData: (data) => chunks.push(data),
    });
    expect(ok.exitCode).toBe(0);
    expect(Buffer.concat(chunks).toString()).toContain("piship-local-bash");
    const failed = await local.exec("exit 3", temp, { onData: () => {} });
    expect(failed.exitCode).toBe(3);
  });
});

// PiShip disables ambient discovery and passes only admitted paths.
describe("DefaultResourceLoader with ambient discovery disabled", () => {
  function fixtures() {
    const cwd = join(temp, "project");
    const agentDir = join(temp, "agent");
    const explicit = join(temp, "distribution");
    const skill = (dir: string, name: string) =>
      write(
        join(dir, name, "SKILL.md"),
        `---\nname: ${name}\ndescription: The ${name} compatibility skill.\n---\n\n${name} body.\n`,
      );
    write(join(cwd, "AGENTS.md"), "ambient project instructions\n");
    write(join(agentDir, "AGENTS.md"), "ambient user instructions\n");
    skill(join(agentDir, "skills"), "ambient-skill");
    write(
      join(agentDir, "extensions", "ambient.js"),
      `export default function (pi) { pi.registerCommand("ambient-ext", { handler: async () => {} }); }\n`,
    );
    skill(join(explicit, "skills"), "explicit-skill");
    const extension = write(
      join(explicit, "extensions", "explicit.js"),
      `export default function (pi) { pi.registerCommand("explicit-ext", { handler: async () => {} }); }\n`,
    );
    const instructions = join(explicit, "AGENTS.md");
    return { cwd, agentDir, explicit, extension, instructions };
  }
  const inventory = (loader: DefaultResourceLoader) => ({
    skills: loader
      .getSkills()
      .skills.map((item) => item.name)
      .sort(),
    agentsFiles: loader
      .getAgentsFiles()
      .agentsFiles.map((item) => item.content.trim())
      .sort(),
    commands: loader
      .getExtensions()
      .extensions.flatMap((item) => [...item.commands.keys()])
      .sort(),
  });

  it("discovers ambient resources by default, proving the fixture is at Pi's discovery locations", async () => {
    const { cwd, agentDir } = fixtures();
    const loader = new DefaultResourceLoader({
      cwd,
      agentDir,
      settingsManager: SettingsManager.inMemory(),
    });
    await loader.reload();
    const found = inventory(loader);
    expect(found.skills).toContain("ambient-skill");
    expect(found.agentsFiles).toContain("ambient project instructions");
    expect(found.commands).toContain("ambient-ext");
  });

  it("loads only the explicit paths PiShip passes", async () => {
    const { cwd, agentDir, explicit, extension, instructions } = fixtures();
    const loader = new DefaultResourceLoader({
      cwd,
      agentDir,
      settingsManager: SettingsManager.inMemory(),
      additionalExtensionPaths: [extension],
      additionalSkillPaths: [join(explicit, "skills")],
      additionalPromptTemplatePaths: [],
      additionalThemePaths: [],
      noExtensions: true,
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
      agentsFilesOverride: () => ({
        agentsFiles: [
          { path: instructions, content: "explicit distribution instructions" },
        ],
      }),
    });
    await loader.reload();
    expect(loader.getExtensions().errors).toEqual([]);
    expect(inventory(loader)).toEqual({
      skills: ["explicit-skill"],
      agentsFiles: ["explicit distribution instructions"],
      commands: ["explicit-ext"],
    });
  });
});

// A real Pi session driven headlessly against the loopback fixture gateway,
// which scripts one tool call per model turn.
describe("Pi session seams used by governance", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  beforeEach(async () => {
    services = await startLocalServices({
      knobs: { acceptedKeys: [API_KEY] },
    });
  });
  afterEach(async () => {
    await services.close();
  });

  async function session(
    options: {
      extensions?: InlineExtension[];
      customTools?: ToolDefinition[];
      sessionManager?: SessionManager;
    } = {},
  ) {
    const runtime = await managedRuntime(services.gatewayUrl);
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
      extensionFactories: options.extensions ?? [],
    });
    await resourceLoader.reload();
    const selected = runtime.getModel("acmecode", "acme/coder");
    if (!selected) throw new Error("fixture model missing");
    return createAgentSession({
      cwd: temp,
      agentDir: temp,
      modelRuntime: runtime,
      model: selected,
      settingsManager,
      sessionManager: options.sessionManager ?? SessionManager.inMemory(temp),
      resourceLoader,
      noTools: "builtin",
      customTools: options.customTools ?? [],
    });
  }
  const completions = () =>
    services.state.requests
      .filter((item: { path: string }) =>
        item.path.endsWith("/chat/completions"),
      )
      .map((item: { body: string }) => JSON.parse(item.body));

  it("delivers every extension event and registration PiShip uses", async () => {
    const seen: string[] = [];
    const context: { hasUI?: unknown; ui?: Record<string, unknown> } = {};
    const bashCalls: string[] = [];
    const probeCalls: unknown[] = [];
    const commandArgs: string[] = [];
    const modelSelections: string[] = [];
    let providerPayload: { model?: string } | undefined;
    const extension: InlineExtension = {
      name: "piship-compat",
      factory: (pi) => {
        pi.on("session_start", (event, ctx) => {
          seen.push(`session_start:${event.reason}`);
          context.hasUI = ctx.hasUI;
          context.ui = ctx.ui as unknown as Record<string, unknown>;
        });
        pi.on("before_agent_start", (event) => {
          seen.push("before_agent_start");
          return {
            systemPrompt: `${event.systemPrompt}\n\nPISHIP-COMPAT-MARKER`,
          };
        });
        pi.on("before_provider_request", (event) => {
          seen.push("before_provider_request");
          providerPayload = event.payload as { model?: string };
        });
        pi.on("message_end", (event) => {
          seen.push(`message_end:${(event.message as { role: string }).role}`);
        });
        pi.on("model_select", (event) => {
          modelSelections.push(`${event.model.provider}/${event.model.id}`);
        });
        pi.on("tool_call", (event) => {
          seen.push(`tool_call:${event.toolName}`);
          return undefined;
        });
        pi.on("user_bash", () => ({
          operations: {
            exec: async (command, _cwd, options) => {
              bashCalls.push(command);
              options.onData(Buffer.from("governed user bash\n"));
              return { exitCode: 0 };
            },
          },
        }));
        pi.registerTool({
          name: "compat_probe",
          label: "Compat probe",
          description: "Compatibility probe tool.",
          parameters: {
            type: "object",
            properties: { value: { type: "string" } },
            required: ["value"],
            additionalProperties: false,
          } as never,
          async execute(_id, params) {
            probeCalls.push(params);
            return {
              content: [{ type: "text" as const, text: "probe ok" }],
              details: {},
            };
          },
        });
        pi.registerCommand("compat", {
          description: "Compatibility command",
          handler: async (args) => {
            commandArgs.push(args);
          },
        });
      },
    };
    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = [
      { name: "compat_probe", arguments: { value: "x" } },
    ];
    const { session: agent } = await session({ extensions: [extension] });
    await agent.bindExtensions({});
    expect(seen).toContain("session_start:startup");
    expect(context.hasUI).toBe(false);
    for (const dialog of ["confirm", "select", "setStatus", "notify"])
      expect(typeof context.ui?.[dialog], dialog).toBe("function");

    // noTools: "builtin" leaves no Pi built-in tool; registered tools remain.
    expect(agent.getActiveToolNames()).toEqual(["compat_probe"]);

    await agent.prompt("run the probe");
    expect(probeCalls).toEqual([{ value: "x" }]);
    expect(seen).toContain("before_agent_start");
    expect(seen).toContain("before_provider_request");
    expect(seen).toContain("tool_call:compat_probe");
    expect(seen).toContain("message_end:user");
    expect(seen).toContain("message_end:assistant");
    expect(providerPayload?.model).toBe("acme/coder");
    const [first] = completions();
    expect(
      first.tools.map(
        (tool: { function: { name: string } }) => tool.function.name,
      ),
    ).toEqual(["compat_probe"]);
    expect(JSON.stringify(first.messages)).toContain("PISHIP-COMPAT-MARKER");

    await agent.prompt("/compat some args");
    expect(commandArgs).toEqual(["some args"]);

    const general = agent.modelRuntime.getModel("acmecode", "acme/general");
    if (!general) throw new Error("fixture model missing");
    await agent.setModel(general);
    expect(modelSelections).toContain("acmecode/acme/general");

    // Interactive `!` commands: Pi asks user_bash handlers for operations,
    // then runs the command through them.
    const intercepted = await agent.extensionRunner.emitUserBash({
      type: "user_bash",
      command: "echo from-user",
      excludeFromContext: false,
      cwd: temp,
    });
    expect(intercepted && "operations" in intercepted).toBe(true);
    const result = await agent.executeBash("echo from-user", undefined, {
      operations: (intercepted as { operations: BashOperations }).operations,
    });
    expect(bashCalls).toEqual(["echo from-user"]);
    expect(result.output).toContain("governed user bash");
    agent.dispose();
  });

  it("customTools replace built-ins and a tool_call block prevents execution", async () => {
    const reads: string[] = [];
    const writes: string[] = [];
    const customTools = [
      createReadToolDefinition(temp, {
        operations: {
          readFile: async (path) => {
            reads.push(path);
            return Buffer.from("governed read\n");
          },
          access: async () => {},
        },
      }),
      createWriteToolDefinition(temp, {
        operations: {
          mkdir: async () => {},
          writeFile: async (path) => {
            writes.push(path);
          },
        },
      }),
    ] as ToolDefinition[];
    const blocker: InlineExtension = {
      name: "piship-policy-compat",
      factory: (pi) => {
        pi.on("tool_call", (event) =>
          event.toolName === "write"
            ? { block: true, reason: "compat policy denies write" }
            : undefined,
        );
      },
    };
    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = [
      { name: "write", arguments: { path: "blocked.txt", content: "x" } },
      { name: "read", arguments: { path: "allowed.txt" } },
    ];
    const { session: agent } = await session({
      extensions: [blocker],
      customTools,
    });
    await agent.bindExtensions({});
    expect(agent.getActiveToolNames().sort()).toEqual(["read", "write"]);
    await agent.prompt("write then read");
    expect(writes).toEqual([]);
    expect(reads).toEqual([join(temp, "allowed.txt")]);
    expect(readdirSync(temp)).toEqual([]);
    const [blocked, allowed] = services.state.toolResults as string[];
    expect(blocked).toContain("compat policy denies write");
    expect(allowed).toContain("governed read");
    expect(agent.getLastAssistantText()).toBe(
      "Script finished with 2 tool result(s).",
    );
    agent.dispose();
  });

  it("a tool_call handler that throws does not let the tool run", async () => {
    // PiShip's own hook fails closed with a block result; this pins that Pi
    // also refuses the call when a handler throws instead of returning.
    const writes: string[] = [];
    const customTools = [
      createWriteToolDefinition(temp, {
        operations: {
          mkdir: async () => {},
          writeFile: async (path) => {
            writes.push(path);
          },
        },
      }),
    ] as ToolDefinition[];
    const thrower: InlineExtension = {
      name: "piship-policy-throws",
      factory: (pi) => {
        pi.on("tool_call", () => {
          throw new Error("decision failed");
        });
      },
    };
    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = [
      { name: "write", arguments: { path: "thrown.txt", content: "x" } },
    ];
    const { session: agent } = await session({
      extensions: [thrower],
      customTools,
    });
    await agent.bindExtensions({});
    await agent.prompt("write");
    expect(writes).toEqual([]);
    expect((services.state.toolResults as string[])[0]).toContain(
      "decision failed",
    );
    expect(readdirSync(temp)).toEqual([]);
    agent.dispose();
  });

  it("resumes a persisted session through createAgentSessionRuntime and SessionManager", async () => {
    const sessionDir = join(temp, "sessions");
    const first = await session({
      sessionManager: SessionManager.create(temp, sessionDir),
    });
    await first.session.prompt("remember PISHIP-RESUME-TOKEN");
    expect(first.session.getLastAssistantText()).toBe("Hello from acme/coder.");
    const file = first.session.sessionFile;
    first.session.dispose();
    expect(file).toBeDefined();
    expect(realpathSync(dirname(file as string))).toBe(
      realpathSync(sessionDir),
    );

    const runtime = await createAgentSessionRuntime(
      async ({ sessionManager }) => {
        const result = await session({ sessionManager });
        return {
          ...result,
          services: {
            cwd: temp,
            agentDir: temp,
            settingsManager: SettingsManager.inMemory(),
            modelRuntime: result.session.modelRuntime,
            resourceLoader: result.session.resourceLoader,
            diagnostics: [],
          },
          diagnostics: [],
        };
      },
      {
        cwd: temp,
        agentDir: temp,
        sessionManager: SessionManager.continueRecent(temp, sessionDir),
      },
    );
    const resumed = runtime.session;
    expect(resumed.sessionFile).toBe(file);
    expect(JSON.stringify(resumed.messages)).toContain("PISHIP-RESUME-TOKEN");
    await resumed.prompt("continue");
    const last = completions().at(-1);
    expect(JSON.stringify(last.messages)).toContain("PISHIP-RESUME-TOKEN");
    await runtime.dispose();

    const reopened = SessionManager.open(file as string, sessionDir);
    expect(JSON.stringify(reopened.buildSessionContext().messages)).toContain(
      "continue",
    );
  });
});
