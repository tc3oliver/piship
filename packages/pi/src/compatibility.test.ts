// Pi compatibility: every public Pi seam PiShip's managed, governance, and
// lifecycle surfaces rely on is asserted here individually, and exercised
// where that is cheap and deterministic (no network beyond loopback fixtures,
// no real model). A Pi upgrade that renames, removes, or changes one of these
// seams must fail here before it can silently weaken governance.
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { inspect } from "node:util";
import { basename, dirname, join, resolve } from "node:path";
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
import { SecretValue } from "@piship/contracts";
import { PI_VERSION } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import type { GovernanceSession } from "./governance-session.js";
import { governedTools } from "./governed-tools.js";
import { governModelRuntime, PINNED_PI_VERSION } from "./index.js";
import {
  installCrashRedaction,
  uninstallCrashRedaction,
} from "./launch/crash-redaction.js";
import { ASSISTANT_MESSAGE_FIELDS } from "./launch/redaction.js";
import { SessionOutputStore } from "./shell-output.js";

// The scheduled Pi latest canary installs the newest published Pi over the
// pin in a throwaway checkout and runs this suite read-only. Only the
// exact-version assertions are relaxed there; every seam is still checked.
const CANARY = process.env.PISHIP_PI_CANARY === "1";
const EXPECTED_PI_VERSION = CANARY ? VERSION : PINNED_PI_VERSION;

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
async function managedRuntime(
  baseUrl: string,
  headers?: Record<string, string>,
) {
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
    ...(headers ? { headers } : {}),
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
    expect(upstreamPi.VERSION).toBe(EXPECTED_PI_VERSION);
    expect(upstreamPi.VERSION).toMatch(/^\d+\.\d+\.\d+/);
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
      "truncateTail",
      "formatSize",
    ])
      expect(typeof exported[name], name).toBe("function");
    for (const name of ["DEFAULT_MAX_BYTES", "DEFAULT_MAX_LINES"])
      expect(typeof exported[name], name).toBe("number");
    expect(VERSION).toBe(EXPECTED_PI_VERSION);
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
      // Pi's `/login` lists the providers this returns.
      "getProviders",
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

  // PiShip's governed bash keeps Pi's bash definition but runs its own
  // execute, so the full output is owned by the session. Its results, live
  // updates, and failures must match Pi's, apart from the saved path.
  describe("governed bash execute matches Pi's", () => {
    const outputs = {
      small: [Buffer.from("one\ntwo\n")],
      "truncated by lines": [
        Buffer.from(
          Array.from({ length: 3000 }, (_, i) => `line ${i}\n`).join(""),
        ),
      ],
      "truncated by bytes": [
        Buffer.from(`${"y".repeat(200)}\n`.repeat(400)),
        Buffer.from("tail\n"),
      ],
      "one long line": [Buffer.alloc(120 * 1024, 122)],
      empty: [],
    } as const;
    const exitCodes = [0, 2, null] as const;
    let store = new SessionOutputStore();
    beforeEach(() => {
      store = new SessionOutputStore();
    });
    afterEach(async () => {
      await store.dispose();
    });

    // The full-output path, from the result, a live update, or the error.
    // Both come from JSON text, so a Windows path is decoded from its escaped
    // form before it is compared with a real path.
    const savedPath = (json: string) => {
      const found =
        /"fullOutputPath":"((?:[^"\\]|\\.)+)"/.exec(json)?.[1] ??
        /Full output: ([^\]\s]+)\]/.exec(json)?.[1];
      return found === undefined
        ? undefined
        : (JSON.parse(`"${found}"`) as string);
    };

    async function capture(tool: ToolDefinition) {
      const updates: unknown[] = [];
      const outcome = await tool
        .execute(
          "call_compat",
          { command: "emit" } as never,
          undefined,
          (update) => updates.push(update),
          {
            hasUI: false,
            cwd: cwd(),
            sessionManager: SessionManager.inMemory(temp),
          } as never,
        )
        .then(
          (result) => ({ result }),
          (error: Error) => ({ error: error.message }),
        );
      const json = JSON.stringify({ outcome, updates });
      const path = savedPath(json);
      return {
        path,
        // The path appears in the JSON text in its escaped form.
        json: path
          ? json.replaceAll(JSON.stringify(path).slice(1, -1), "<full-output>")
          : json,
      };
    }

    for (const [name, chunks] of Object.entries(outputs))
      for (const exitCode of exitCodes)
        it(`${name}, exit ${exitCode}`, async () => {
          const exec: BashOperations["exec"] = async (_c, _d, options) => {
            for (const chunk of chunks) options.onData(chunk);
            return { exitCode };
          };
          const pi = createBashToolDefinition(cwd(), { operations: { exec } });
          const gov = {
            workflowMode: "build",
            currentChannel: () => undefined,
            decide: async () => ({ outcome: "allow" }),
            sandbox: { report: { level: "enforced" }, exec },
            outputStore: store,
            withChannel: (_channel: unknown, fn: () => unknown) => fn(),
            mcp: null,
          } as unknown as GovernanceSession;
          const governed = governedTools(gov, cwd()).find(
            (tool) => tool.name === "bash",
          ) as ToolDefinition;
          const fromPi = await capture(pi as ToolDefinition);
          const fromPiShip = await capture(governed);
          if (fromPi.path) rmSync(fromPi.path, { force: true });
          expect(Boolean(fromPiShip.path)).toBe(Boolean(fromPi.path));
          if (fromPiShip.path)
            expect(fromPiShip.path.startsWith(store.dir as string)).toBe(true);
          expect(fromPiShip.json).toBe(fromPi.json);
        });

    it("runs the command, cwd, timeout, and environment Pi would run", async () => {
      const calls: unknown[] = [];
      const exec: BashOperations["exec"] = async (command, dir, options) => {
        calls.push({
          command,
          dir,
          timeout: options.timeout,
          path: options.env?.PATH,
          session: options.env?.PI_SESSION_ID,
        });
        return { exitCode: 0 };
      };
      const ctx = {
        hasUI: false,
        cwd: join(cwd(), "sub"),
        sessionManager: SessionManager.inMemory(temp),
      } as never;
      const gov = {
        workflowMode: "build",
        currentChannel: () => undefined,
        decide: async () => ({ outcome: "allow" }),
        sandbox: { report: { level: "enforced" }, exec },
        outputStore: store,
        withChannel: (_channel: unknown, fn: () => unknown) => fn(),
        mcp: null,
      } as unknown as GovernanceSession;
      const params = { command: "echo env", timeout: 5 } as never;
      await createBashToolDefinition(cwd(), { operations: { exec } }).execute(
        "a",
        params,
        undefined,
        undefined,
        ctx,
      );
      await (
        governedTools(gov, cwd()).find(
          (tool) => tool.name === "bash",
        ) as ToolDefinition
      ).execute("b", params, undefined, undefined, ctx);
      expect(calls).toHaveLength(2);
      expect(calls[1]).toEqual(calls[0]);
      expect(calls[0]).toMatchObject({ dir: join(cwd(), "sub"), timeout: 5 });
      expect((calls[0] as { session?: string }).session).toBeTruthy();
    });
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
      headers?: Record<string, string>;
    } = {},
  ) {
    const runtime = await managedRuntime(services.gatewayUrl, options.headers);
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
    const shutdownOutputs: string[] = [];
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
        pi.on("session_shutdown", (_event, ctx) => {
          for (const entry of ctx.sessionManager.getEntries())
            if (
              entry.type === "message" &&
              entry.message.role === "bashExecution" &&
              entry.message.fullOutputPath
            )
              shutdownOutputs.push(entry.message.fullOutputPath);
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

    // PiShip removes a `!` command's full-output file when the session
    // closes: Pi names it pi-bash-<16 hex>.log directly in the OS temp
    // directory, records it in the session entries with a timestamp, and
    // session_shutdown hands extensions those entries.
    const large = await agent.executeBash("echo large", undefined, {
      operations: {
        exec: async (_command, _cwd, options) => {
          options.onData(Buffer.alloc(60 * 1024, 120));
          return { exitCode: 0 };
        },
      },
    });
    const fullOutput = large.fullOutputPath as string;
    try {
      expect(fullOutput).toBeDefined();
      expect(dirname(fullOutput)).toBe(tmpdir());
      expect(basename(fullOutput)).toMatch(/^pi-bash-[0-9a-f]{16}\.log$/);
      const recorded = agent.sessionManager
        .getEntries()
        .flatMap((entry) => (entry.type === "message" ? [entry.message] : []))
        .find(
          (message) =>
            message.role === "bashExecution" &&
            message.fullOutputPath === fullOutput,
        );
      expect(typeof recorded?.timestamp).toBe("number");
      await agent.extensionRunner.emit({
        type: "session_shutdown",
        reason: "quit",
      });
      expect(shutdownOutputs).toContain(fullOutput);
    } finally {
      rmSync(fullOutput, { force: true });
    }
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

  // The managed runtime sends PiShip-Client to the gateway through the
  // provider's public `headers` option (launch/model-runtime.ts).
  it("sends a registered provider's headers on every model request", async () => {
    const client =
      'distribution="acmecode", version="1.0.0", piship="0.7.0", protocol=1';
    const { session: agent } = await session({
      headers: { "piship-client": client },
    });
    await agent.prompt("hello");
    const sent = services.state.requests.filter((item: { path: string }) =>
      item.path.endsWith("/chat/completions"),
    );
    expect(sent.length).toBeGreaterThan(0);
    for (const item of sent) expect(item.client).toBe(client);
    agent.dispose();
  });

  it("persists the message a message_end handler returns in place of a provider error", async () => {
    // PiShip redacts provider error text this way before Pi records it
    // (launch/redaction.ts): the replacement must be what the session file
    // and the agent state keep, with the original text in neither.
    services.knobs.gatewayStatus = 500;
    const replacer: InlineExtension = {
      name: "piship-replace-error",
      factory: (pi) => {
        pi.on("message_end", (event) => {
          const message = event.message as { errorMessage?: string };
          if (typeof message.errorMessage !== "string") return undefined;
          return {
            message: {
              ...event.message,
              errorMessage: message.errorMessage.replace(
                "gateway failure",
                "PISHIP-REPLACED",
              ),
            } as typeof event.message,
          };
        });
      },
    };
    const sessionDir = join(temp, "sessions");
    const { session: agent } = await session({
      extensions: [replacer],
      sessionManager: SessionManager.create(temp, sessionDir),
    });
    await agent.bindExtensions({});
    await agent.prompt("fail");
    const last = agent.messages.at(-1) as { errorMessage?: string };
    expect(last.errorMessage).toContain("PISHIP-REPLACED");
    const file = readFileSync(
      agent.sessionManager.getSessionFile() ?? "",
      "utf8",
    );
    expect(file).toContain("PISHIP-REPLACED");
    expect(file).not.toContain("gateway failure");
    agent.dispose();
  });

  it("builds assistant messages only from fields PiShip has classified for redaction", async () => {
    // launch/redaction.ts classifies every AssistantMessage field at compile
    // time; this checks the messages Pi builds at run time, answered and
    // failed, against the same list, and which fields are redacted.
    expect(
      Object.entries(ASSISTANT_MESSAGE_FIELDS)
        .filter(([, kind]) => kind === "redacted")
        .map(([field]) => field)
        .sort(),
    ).toEqual(["diagnostics", "errorMessage"]);
    const { session: agent } = await session();
    await agent.prompt("hello");
    services.knobs.gatewayStatus = 500;
    await agent.prompt("fail");
    const assistants = agent.messages.filter(
      (message) => (message as { role: string }).role === "assistant",
    );
    expect(assistants.length).toBe(2);
    for (const message of assistants)
      for (const field of Object.keys(message))
        expect(Object.keys(ASSISTANT_MESSAGE_FIELDS)).toContain(field);
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

  it("passes a switched session through the runtime factory, and a session_before_switch handler can cancel a resume", async () => {
    const sessionDir = join(temp, "sessions");
    const target = SessionManager.create(temp, sessionDir);
    target.appendMessage({ role: "user", content: "other", timestamp: 1 });
    const targetFile = target.getSessionFile() as string;
    writeFileSync(targetFile, `${JSON.stringify(target.getHeader())}\n`);
    const factoryFiles: (string | undefined)[] = [];
    const switches: string[] = [];
    const refuse: InlineExtension = {
      name: "piship-session-owner",
      factory: (pi) => {
        pi.on("session_before_switch", (event) => {
          switches.push(`${event.reason}:${event.targetSessionFile ?? ""}`);
          return event.reason === "resume" ? { cancel: true } : undefined;
        });
      },
    };
    const runtime = await createAgentSessionRuntime(
      async ({ sessionManager }) => {
        factoryFiles.push(sessionManager.getSessionFile());
        const result = await session({
          sessionManager,
          extensions: [refuse],
        });
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
        sessionManager: SessionManager.create(temp, sessionDir),
      },
    );
    const initial = runtime.session.sessionFile;
    expect(await runtime.switchSession(targetFile)).toEqual({
      cancelled: true,
    });
    expect(runtime.session.sessionFile).toBe(initial);
    expect(switches).toEqual([`resume:${targetFile}`]);
    expect(await runtime.newSession()).toEqual({ cancelled: false });
    expect(factoryFiles).toHaveLength(2);
    expect(factoryFiles[0]).toBe(initial);
    expect(factoryFiles[1]).toBe(runtime.session.sessionFile);
    expect(factoryFiles[1]).not.toBe(initial);
    await runtime.dispose();
  });
});

describe("Pi session loading that PiShip gates before a resume", () => {
  function persisted() {
    const sessionDir = join(temp, "sessions");
    const manager = SessionManager.create(temp, sessionDir);
    manager.appendMessage({ role: "user", content: "one", timestamp: 1 });
    manager.appendMessage({
      role: "assistant",
      content: [{ type: "text", text: "two" }],
      api: "piship-test",
      provider: "piship",
      model: "none",
      usage: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "stop",
      timestamp: 2,
    });
    manager.appendMessage({ role: "user", content: "three", timestamp: 3 });
    const file = manager.getSessionFile() as string;
    return { sessionDir, file, lines: readFileSync(file, "utf8").split("\n") };
  }

  // PiShip inspects the session first (launch/session-file.ts) because Pi
  // resumes these files silently. When Pi reports them instead, the gate
  // can be reconsidered.
  it("continueRecent drops a malformed line without a signal", () => {
    const { sessionDir, file, lines } = persisted();
    writeFileSync(file, [lines[0], "{broken", ...lines.slice(2)].join("\n"));
    const resumed = SessionManager.continueRecent(temp, sessionDir);
    expect(resumed.getSessionFile()).toBe(file);
    expect(resumed.getEntries()).toHaveLength(2);
  });

  it("continueRecent completes a truncated last record by writing to the file", () => {
    const { sessionDir, file, lines } = persisted();
    const truncated = `${lines.slice(0, 3).join("\n")}\n${lines[3]?.slice(0, 20)}`;
    writeFileSync(file, truncated);
    SessionManager.continueRecent(temp, sessionDir);
    expect(readFileSync(file, "utf8")).toBe(`${truncated}\n`);
  });

  it("open with the cwd resumes the file continueRecent resumes, as it would", () => {
    const { sessionDir, file } = persisted();
    const recent = SessionManager.continueRecent(temp, sessionDir);
    const opened = SessionManager.open(file, sessionDir, temp);
    expect(opened.getSessionFile()).toBe(recent.getSessionFile());
    expect(opened.getSessionId()).toBe(recent.getSessionId());
    expect(opened.getLeafId()).toBe(recent.getLeafId());
    expect(opened.getCwd()).toBe(recent.getCwd());
    expect(opened.getSessionDir()).toBe(recent.getSessionDir());
    expect(opened.buildSessionContext()).toEqual(recent.buildSessionContext());
  });
});

describe("Pi ends an interactive session by awaiting dispose, then exiting", () => {
  // PiShip ends its governance session inside `runtime.dispose()` because
  // nothing after `InteractiveMode.run()` ever runs: Pi's shutdown awaits the
  // runtime host's dispose and then calls process.exit(0). If a Pi upgrade
  // exits before that await, or stops calling dispose, the audit flush would
  // be silently skipped again.
  for (const fromSignal of [false, true]) {
    it(`shutdown${fromSignal ? " from a signal" : ""} resolves dispose before it exits`, async () => {
      const order: string[] = [];
      let disposed = false;
      const self = {
        isShuttingDown: false,
        themeController: { disableAutoSync: () => {} },
        ui: { terminal: { drainInput: async () => {} } },
        stop: () => {},
        sessionManager: {
          getSessionFile: () => undefined,
          getSessionId: () => "s",
        },
        runtimeHost: {
          dispose: async () => {
            await new Promise((done) => setTimeout(done, 20));
            disposed = true;
            order.push("dispose");
          },
        },
      };
      const exit = process.exit;
      process.exit = ((code?: number) => {
        order.push(`exit:${code}:${disposed}`);
        throw new Error("exit");
      }) as typeof process.exit;
      try {
        await (
          upstreamPi.InteractiveMode.prototype as unknown as {
            shutdown(
              this: unknown,
              options?: { fromSignal?: boolean },
            ): Promise<void>;
          }
        ).shutdown
          .call(self, fromSignal ? { fromSignal: true } : undefined)
          .catch((error: Error) => {
            if (error.message !== "exit") throw error;
          });
      } finally {
        process.exit = exit;
      }
      expect(order).toEqual(["dispose", "exit:0:true"]);
    });
  }

  // PiShip replaces `dispose` on the runtime object it hands to
  // InteractiveMode. That only works while Pi disposes that same object, not a
  // wrapper or a copy of it.
  it("keeps the runtime it is given as the one it disposes", () => {
    const source = String(upstreamPi.InteractiveMode);
    expect(source).toMatch(/constructor\(\s*runtimeHost\b/);
    expect(source).toMatch(/this\.runtimeHost\s*=\s*runtimeHost\s*;/);
  });
});

describe("Pi's interactive crash handler runs after PiShip's crash redaction", () => {
  // Pi's interactive mode prepends an uncaughtException handler that prints
  // the error, records it in <agent dir>/crashes.json (which /bug attaches to
  // a report), and exits. PiShip prepends a listener that redacts the error
  // in place at session_start, which Pi emits only after it registered its
  // handler, so PiShip's runs first and Pi prints and records redacted text.
  type Proto = Record<string, (this: unknown, ...args: unknown[]) => unknown>;
  const proto = upstreamPi.InteractiveMode.prototype as unknown as Proto;

  it("registers its handler in init before it binds extensions", () => {
    const init = String(proto.init);
    const registers = init.indexOf("this.registerSignalHandlers()");
    const binds = init.indexOf("this.rebindCurrentSession()");
    expect(registers).toBeGreaterThanOrEqual(0);
    expect(binds).toBeGreaterThan(registers);
  });

  it("prints and records a crash with registered secrets redacted", () => {
    const secret = new SecretValue("piship-fake-crash-credential-0123456789");
    const agentDir = join(temp, "agent");
    mkdirSync(agentDir);
    const savedDir = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const self = Object.create(proto) as Record<string, unknown>;
    Object.assign(self, {
      signalCleanupHandlers: [],
      isShuttingDown: false,
      ui: { stop: () => {} },
    });
    // `session` is a getter on the prototype; an own property shadows it.
    Object.defineProperty(self, "session", {
      value: {
        sessionFile: undefined,
        sessionManager: { getCwd: () => temp },
        resourceLoader: { getExtensions: () => ({ extensions: [] }) },
      },
    });
    const before = process.listeners("uncaughtException");
    const rejections = process.listenerCount("unhandledRejection");
    const printed: string[] = [];
    const error = new Error(
      `invalid header value: Authorization ${secret.reveal()}`,
    );
    (error as Error & { cause?: unknown }).cause = new Error(
      `echoed ${secret.reveal()}`,
    );
    const consoleError = console.error;
    const exit = process.exit;
    try {
      proto.registerSignalHandlers?.call(self);
      const piHandler = process.listeners("uncaughtException")[0];
      expect(before).not.toContain(piHandler);
      // Pi adds no unhandledRejection listener: Node raises an unhandled
      // rejection as an uncaught exception, which both listeners see.
      expect(process.listenerCount("unhandledRejection")).toBe(rejections);
      installCrashRedaction();
      const [first, second] = process.listeners("uncaughtException");
      expect(second).toBe(piHandler);
      console.error = (...args: unknown[]) => {
        printed.push(args.map((item) => inspect(item)).join(" "));
      };
      process.exit = ((code?: number) => {
        throw new Error(`exit ${code}`);
      }) as typeof process.exit;
      for (const listener of [first, second])
        try {
          listener?.(error, "uncaughtException");
        } catch (thrown) {
          if ((thrown as Error).message !== "exit 1") throw thrown;
        }
    } finally {
      console.error = consoleError;
      process.exit = exit;
      proto.unregisterSignalHandlers?.call(self);
      uninstallCrashRedaction();
      if (savedDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = savedDir;
    }
    const crashes = readFileSync(join(agentDir, "crashes.json"), "utf8");
    expect(crashes).toContain("invalid header value");
    expect(crashes).toContain("[REDACTED]");
    expect(crashes).not.toContain(secret.reveal());
    expect(printed.join("\n")).toContain("invalid header value");
    expect(printed.join("\n")).not.toContain(secret.reveal());
    expect(process.listeners("uncaughtException")).toEqual(before);
  });
});
