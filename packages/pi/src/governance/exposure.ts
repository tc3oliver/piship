// The session's tool exposure table: what each tool the session can register
// is exposed as, which names are excluded from the session, and whether the
// Codemode and tool search extensions run. Exposure decides what the model
// can see or discover; policy still decides, at every tool_call, what runs.
import {
  type AgentSession,
  createCodemodeExtension,
  createToolSearchExtension,
  type InlineExtension,
  type ResourceLoader,
} from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import {
  BUILTIN_DEFAULT_RULE,
  EXPOSURE_VISIBILITY,
  effectiveExposure,
  resolveExposure,
} from "@piship/policy";
import type {
  RuntimeToolsConfig,
  ToolExposure,
  ToolExposureRule,
} from "@piship/schema";
import type { GovernanceSession } from "../governance-session.js";

/**
 * Pi's base tools PiShip does not replace with a governed one. With
 * `noTools: "builtin"` they are only inactive: still registered, without a
 * PiShip path gate, and any extension could activate them. A governed
 * session always excludes them.
 */
export const UNGOVERNED_PI_BASE_TOOLS = [
  "grep",
  "find",
  "ls",
  "powershell",
] as const;

/**
 * PiShip's own tools, resolved against `runtime.tools.exposure`. `ask_user`
 * is one only while `piship-ask-user` registers it.
 */
export const PISHIP_TOOLS = ["read", "write", "edit", "bash", "ask_user"];

export const CODEMODE_TOOL = "codemode";
export const TOOL_SEARCH_TOOL = "tool_search";

export type ExposureConfig = RuntimeToolsConfig;

/** v0.8 behavior: no Codemode, no tool search, every tool direct. */
export const DEFAULT_EXPOSURE_CONFIG: ExposureConfig = {
  codemode: "off",
  toolSearch: "off",
  exposure: [],
};

/**
 * The session's `runtime.tools` settings, as the v1alpha6 lock records them.
 * An older lock has the v0.8 defaults.
 */
export function exposureConfigOf(gov: GovernanceSession): ExposureConfig {
  return gov.options.lock.runtimeTools ?? DEFAULT_EXPOSURE_CONFIG;
}

/** The exposure rules of a declared MCP server; project servers have none. */
export function mcpServerExposure(
  gov: GovernanceSession,
  server: string,
): { fallback: ToolExposure; rules: readonly ToolExposureRule[] } {
  const declared =
    gov.manifest.mcp.mode === "off" ? [] : gov.manifest.mcp.servers;
  const config = declared.find((item) => item.id === server);
  return {
    fallback: config?.exposure ?? "direct",
    rules: config?.toolExposure ?? [],
  };
}

/** An MCP tool's exposure, before `tool.execute` on its exposed name. */
export function mcpToolExposure(
  gov: GovernanceSession,
  server: string,
  tool: string,
): ToolExposure {
  const { fallback, rules } = mcpServerExposure(gov, server);
  const denied =
    gov.engine.evaluate({
      action: "mcp.tool.call",
      resource: `${server}:${tool}`,
    }).effect === "deny";
  return effectiveExposure(resolveExposure(tool, rules, fallback), denied);
}

/** A tool an extension registered while it loaded, as Pi declares it. */
export interface ExtensionToolInfo {
  readonly exposure?: ToolExposure;
  /** The tool can rewrite other tools' descriptions (`doctor`, `diff`). */
  readonly prepareLoadout: boolean;
  readonly extension: string;
}

/** The tools extensions registered at load time, by name. */
export function extensionToolsOf(
  loader: ResourceLoader,
): Map<string, ExtensionToolInfo> {
  const tools = new Map<string, ExtensionToolInfo>();
  for (const extension of loader.getExtensions().extensions)
    for (const [name, registered] of extension.tools) {
      const { exposure, prepareLoadout } = registered.definition;
      tools.set(name, {
        ...(exposure ? { exposure } : {}),
        prepareLoadout: typeof prepareLoadout === "function",
        extension: extension.path,
      });
    }
  return tools;
}

/**
 * Which of Pi's Codemode and tool search extensions a session loads. They
 * are loaded before the tools extensions register are known, so tool search
 * is loaded for any statically deferred rule; `buildExposureTable` then
 * activates or excludes what was loaded.
 */
export function exposureExtensions(
  gov: GovernanceSession,
  config: ExposureConfig,
): { readonly codemode: boolean; readonly toolSearch: boolean } {
  const servers =
    gov.manifest.mcp.mode === "off" ? [] : gov.manifest.mcp.servers;
  const deferred =
    config.exposure.some((rule) => rule.exposure === "deferred") ||
    servers.some(
      (server) =>
        server.exposure === "deferred" ||
        (server.toolExposure ?? []).some(
          (rule) => rule.exposure === "deferred",
        ),
    );
  return {
    codemode: config.codemode !== "off",
    toolSearch: config.toolSearch === "on" || deferred,
  };
}

/**
 * Pi's Codemode and tool search, as extension factories, when the session
 * uses them. Both register their tool inactive; `activateExposure` turns
 * them on. Codemode scripts get no `models` global until the
 * classify/image gate is proven.
 */
export function exposureFactories(
  gov: GovernanceSession,
  config: ExposureConfig,
): InlineExtension[] {
  const loaded = exposureExtensions(gov, config);
  return [
    ...(loaded.codemode
      ? [
          {
            name: "piship-codemode",
            factory: createCodemodeExtension({
              mode: config.codemode === "only" ? "only" : "on",
              models: false,
            }),
          },
        ]
      : []),
    ...(loaded.toolSearch
      ? [{ name: "piship-tool-search", factory: createToolSearchExtension() }]
      : []),
  ];
}

/**
 * After `createAgentSession`: fail closed if Pi registered a tool the
 * session excludes, then activate Codemode and tool search. `noTools` keeps
 * Pi from reading `defaultTools`, so PiShip activates them itself.
 */
export function activateExposure(
  session: AgentSession,
  table: ToolExposureTable,
): void {
  const excluded = new Set(table.excluded());
  const leaked = session.getAllTools().find((tool) => excluded.has(tool.name));
  if (leaked)
    throw new PiShipError(
      "POLICY_DENIED",
      `Tool ${leaked.name} is excluded from the session, but Pi registered it`,
      { component: "policy" },
    );
  const mandatory = table.mandatoryActive();
  if (mandatory.length)
    session.setActiveToolsByName([
      ...new Set([...session.getActiveToolNames(), ...mandatory]),
    ]);
}

export interface ToolExposureTable {
  readonly codemode: ExposureConfig["codemode"];
  /** The Codemode extension runs and its tool is activated. */
  readonly codemodeOn: boolean;
  /** The tool search extension runs and its tool is activated. */
  readonly toolSearchOn: boolean;
  /** The exposure of a tool the session knows; undefined for any other. */
  get(name: string): ToolExposure | undefined;
  /** Names passed to `createAgentSession({ excludeTools })`. */
  excluded(): string[];
  /** Tools PiShip activates after the session is created. */
  mandatoryActive(): string[];
  /** Extension tools that define `prepareLoadout`. */
  prepareLoadoutTools(): string[];
}

function denied(gov: GovernanceSession, tool: string): boolean {
  return (
    gov.engine.evaluate({ action: "tool.execute", resource: tool }).effect ===
    "deny"
  );
}

/** Script-reachable: exposed to Codemode `tools.*` / `executeTool`. */
const scriptReachable = (exposure: ToolExposure) =>
  exposure === "direct" || exposure === "codemode" || exposure === "deferred";

/**
 * Resolve every tool the session can register. Fails the launch with
 * CONFIG_INVALID when an extension declares a tool wider than the manifest
 * allows (PiShip cannot rewrite another extension's definition), and in
 * managed mode with POLICY_DENIED when Codemode could reach a tool whose
 * decision comes only from the policy's built-in default.
 */
export function buildExposureTable(
  gov: GovernanceSession,
  config: ExposureConfig,
  extensionTools: ReadonlyMap<string, ExtensionToolInfo>,
): ToolExposureTable {
  const table = new Map<string, ToolExposure>();
  const excluded = new Set<string>(UNGOVERNED_PI_BASE_TOOLS);
  const set = (name: string, exposure: ToolExposure) => {
    table.set(name, exposure);
    if (exposure === "hidden") excluded.add(name);
  };
  const runtimeExposure = (name: string, fallback: ToolExposure) =>
    effectiveExposure(
      resolveExposure(name, config.exposure, fallback),
      denied(gov, name),
    );
  for (const name of PISHIP_TOOLS)
    if (name !== "ask_user" || extensionTools.has(name))
      set(name, runtimeExposure(name, "direct"));
  const mcpTools = gov.mcp?.tools() ?? [];
  for (const tool of mcpTools) {
    const exposure = mcpToolExposure(gov, tool.server, tool.tool);
    set(
      tool.name,
      exposure === "hidden" || denied(gov, tool.name) ? "hidden" : exposure,
    );
  }
  for (const [name, info] of extensionTools) {
    // SDK custom tools (PiShip's own and MCP) win over extension tools of
    // the same name; Codemode and tool search are decided below.
    if (table.has(name) || name === CODEMODE_TOOL || name === TOOL_SEARCH_TOOL)
      continue;
    const declared = info.exposure ?? "direct";
    const resolution = resolveExposure(name, config.exposure, declared);
    if ("tie" in resolution || denied(gov, name)) {
      set(name, "hidden");
      continue;
    }
    if (resolution.rule === undefined) {
      set(name, declared);
      continue;
    }
    if (resolution.exposure === "hidden") {
      set(name, "hidden");
      continue;
    }
    if (
      EXPOSURE_VISIBILITY[declared] > EXPOSURE_VISIBILITY[resolution.exposure]
    )
      throw new PiShipError(
        "CONFIG_INVALID",
        `Extension tool ${name} declares exposure ${declared}, and the distribution allows at most ${resolution.exposure} (runtime.tools.exposure ${resolution.rule})`,
        {
          userAction:
            "Rebuild the distribution with an exposure rule that allows the tool, or remove the extension",
          component: "policy",
        },
      );
    set(name, declared);
  }
  const loaded = exposureExtensions(gov, config);
  const deferred = [...table.values()].some((item) => item === "deferred");
  const codemodeOn = loaded.codemode && !denied(gov, CODEMODE_TOOL);
  const toolSearchOn =
    loaded.toolSearch &&
    (config.toolSearch === "on" || deferred) &&
    !denied(gov, TOOL_SEARCH_TOOL);
  for (const [name, on] of [
    [CODEMODE_TOOL, codemodeOn],
    [TOOL_SEARCH_TOOL, toolSearchOn],
  ] as const)
    set(name, on ? "model-only" : "hidden");
  if (codemodeOn && gov.options.lock.deployment.mode === "managed") {
    const mcpByName = new Map(mcpTools.map((tool) => [tool.name, tool]));
    for (const [name, exposure] of table) {
      if (!scriptReachable(exposure)) continue;
      const mcp = mcpByName.get(name);
      const fallback = [
        gov.engine.evaluate({ action: "tool.execute", resource: name }),
        ...(mcp
          ? [
              gov.engine.evaluate({
                action: "mcp.tool.call",
                resource: `${mcp.server}:${mcp.tool}`,
              }),
            ]
          : []),
      ].some((decision) => decision.ruleId === BUILTIN_DEFAULT_RULE);
      if (fallback)
        throw new PiShipError(
          "POLICY_DENIED",
          `Codemode is on, but the policy decides ${name} only by its built-in default`,
          {
            userAction: `Add a policy rule for tool.execute ${name}${mcp ? ` and mcp.tool.call ${mcp.server}:${mcp.tool}` : ""}, or set runtime.tools.codemode: off`,
            component: "policy",
          },
        );
    }
  }
  const prepareLoadout = [...extensionTools]
    .filter(([name, info]) => info.prepareLoadout && !excluded.has(name))
    .map(([name]) => name);
  return {
    codemode: config.codemode,
    codemodeOn,
    toolSearchOn,
    get: (name) => table.get(name),
    excluded: () => [...excluded],
    mandatoryActive: () => [
      ...(codemodeOn ? [CODEMODE_TOOL] : []),
      ...(toolSearchOn ? [TOOL_SEARCH_TOOL] : []),
    ],
    prepareLoadoutTools: () => [...prepareLoadout],
  };
}
