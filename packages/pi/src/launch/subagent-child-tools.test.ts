// The effective tools of a subagent child's real Pi session. The parser
// refusals (subagent-child.test.ts) keep every `--tools` list a strict
// allowlist of explicit names; these tests assert against the pinned Pi why:
// a `*` pattern or a `+`/`-` modifier reaching `createAgentSession` unbounds
// the child's tool exposure, and a mixed list makes Pi throw a raw error.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AgentSession,
  createAgentSession,
  createCodemodeExtension,
  createToolSearchExtension,
  DefaultResourceLoader,
  type ExtensionAPI,
  type InlineExtension,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it } from "vitest";
import { UNGOVERNED_PI_BASE_TOOLS } from "../governance/exposure.js";
import { childToolOptions } from "./subagent-child.js";

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

let temp: string;
afterEach(() => {
  if (temp) rmSync(temp, { recursive: true, force: true });
});

// A session as the launch creates one for a governed child: Pi's built-in
// tools off, the Codemode and tool search extensions loaded (a bounded child
// keeps them registered but PiShip activates neither), and one extension tool
// registered direct, which Pi activates on registration without an allowlist.
async function childSession(options: {
  tools?: string[];
  excludeTools?: string[];
  /** Extra extension tools to register alongside `company_probe`. */
  extraTools?: string[];
}) {
  temp = mkdtempSync(join(tmpdir(), "piship-subagent-tools-"));
  const runtime = await ModelRuntime.create({
    credentials: memoryCredentials() as never,
    modelsPath: null,
    refreshOnCreate: false,
    allowModelNetwork: false,
  });
  const settingsManager = SettingsManager.inMemory({
    retry: { enabled: false },
  });
  const registerTool = (pi: ExtensionAPI, name: string) =>
    pi.registerTool({
      name,
      label: name,
      description: "Probe the workbench tool.",
      parameters: { type: "object", properties: {} } as never,
      async execute() {
        return { content: [{ type: "text", text: "ran" }], details: {} };
      },
    } as never);
  const probe: InlineExtension = {
    name: "test-probe",
    factory: (pi) => {
      registerTool(pi, "company_probe");
      for (const name of options.extraTools ?? []) registerTool(pi, name);
    },
  };
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
      probe,
      {
        name: "piship-codemode",
        factory: createCodemodeExtension({ mode: "on", models: false }),
      },
      { name: "piship-tool-search", factory: createToolSearchExtension() },
    ],
  });
  await resourceLoader.reload();
  const { session } = await createAgentSession({
    cwd: temp,
    agentDir: temp,
    modelRuntime: runtime,
    settingsManager,
    sessionManager: SessionManager.inMemory(temp),
    resourceLoader,
    noTools: "builtin",
    customTools: [],
    ...(options.tools ? { tools: options.tools } : {}),
    ...(options.excludeTools ? { excludeTools: options.excludeTools } : {}),
  });
  return session;
}

const names = (session: AgentSession) => session.getActiveToolNames();

describe("a bounded child's effective tools", () => {
  it("activates only its allowlist plus the mandatory tools", async () => {
    const options = childToolOptions(
      { prompt: "t", tools: ["read"] },
      [...UNGOVERNED_PI_BASE_TOOLS],
      ["company_probe"],
    );
    expect(options).toEqual({
      excludeTools: [...UNGOVERNED_PI_BASE_TOOLS],
      tools: ["read", "company_probe"],
    });
    const session = await childSession(options);
    const active = names(session);
    expect(active.sort()).toEqual(["company_probe", "read"]);
    // A strict allowlist is stronger than deactivation: Pi's `_isAllowedTool`
    // keeps a tool the list does not name out of the registry entirely, so
    // codemode, tool search, and an excluded tool are not even registered.
    const registered = session.getAllTools().map((tool) => tool.name);
    for (const tool of ["codemode", "tool_search", "grep"])
      expect(registered).not.toContain(tool);
    session.dispose();
  });
});

// What the pinned Pi 1.1.0 does with the forms the parser refuses. Should a
// Pi upgrade change this, these tests fail and the refusal can be re-examined.
describe("why the parser refuses patterns and modifiers (Pi 1.1.0)", () => {
  it("activates every registered declarable tool for a `*` allowlist, Codemode and tool search included", async () => {
    // A bounded child's exclusions do not name codemode or tool_search: they
    // are registered and merely kept inactive by PiShip, so `*` activates them.
    const session = await childSession({
      tools: ["*"],
      excludeTools: [...UNGOVERNED_PI_BASE_TOOLS],
    });
    const active = names(session);
    for (const tool of ["read", "codemode", "tool_search", "company_probe"])
      expect(active).toContain(tool);
    session.dispose();
  });

  it("drops the allowlist bound for a `+name` modifier and activates every extension tool", async () => {
    // PiShip passes noTools: "builtin", so Pi takes the modifier branch with
    // an empty default list and no allowedToolNames at all.
    const session = await childSession({
      tools: ["+codemode"],
      excludeTools: [...UNGOVERNED_PI_BASE_TOOLS],
    });
    const active = names(session);
    expect(active).toContain("codemode");
    // The extension tool nobody asked for is active because the bound is gone.
    expect(active).toContain("company_probe");
    session.dispose();
  });

  it("throws a raw Pi error for a modifier mixed with a plain name", async () => {
    await expect(
      childSession({
        tools: ["read", "+codemode"],
        excludeTools: [...UNGOVERNED_PI_BASE_TOOLS],
      }),
    ).rejects.toThrow(/Invalid tools option: tool names cannot be mixed/);
  });
});

// The other side of the list. `--exclude-tools` accepts `*` patterns (Pi
// documents `--exclude-tools 'mcp__*'`), which the parser refuses on `--tools`
// because there a pattern drops the bound. These assert against the pinned Pi
// why the same shape is safe here: an exclusion can only remove tools. Pi's
// `_isAllowedTool` applies `excludeTools` to both the active set and
// registration, so a pattern narrows; it never adds a tool or re-widens one the
// allowlist left out.
describe("why an exclusion pattern only narrows (Pi 1.1.0)", () => {
  it("removes the tools a `*` exclusion matches and never adds one", async () => {
    const options = childToolOptions(
      {
        prompt: "t",
        tools: ["company_probe", "company_alpha", "other_tool"],
        excludeTools: ["company_*"],
      },
      [...UNGOVERNED_PI_BASE_TOOLS],
      [],
    );
    const session = await childSession({
      ...options,
      extraTools: ["company_alpha", "other_tool"],
    });
    // Narrowed: the pattern removed both matching tools from the active set.
    expect(names(session).sort()).toEqual(["other_tool"]);
    const registered = session.getAllTools().map((tool) => tool.name);
    // The excluded tools are gone from registration too — `_isAllowedTool`
    // filters them — and nothing outside the allowlist appeared: codemode and
    // tool search stay unregistered, so the bound `--tools` set is intact.
    for (const tool of ["company_probe", "company_alpha"])
      expect(registered).not.toContain(tool);
    expect(registered).toContain("other_tool");
    for (const tool of ["codemode", "tool_search"])
      expect(registered).not.toContain(tool);
    session.dispose();
  });
});
