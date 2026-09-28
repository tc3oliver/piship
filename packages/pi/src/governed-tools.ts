// Governed replacements for Pi's built-in tools. Pi's own tool definitions are
// reused through their public operation hooks, so rendering, truncation and
// diff behavior stay upstream; PiShip only decides each file access and each
// command before it happens. Custom tools passed to the SDK take precedence
// over any extension tool of the same name.
import { constants } from "node:fs";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import {
  type BashOperations,
  createBashToolDefinition,
  createEditToolDefinition,
  createLocalBashOperations,
  createReadToolDefinition,
  createWriteToolDefinition,
  type ExtensionContext,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import {
  type ApprovalChannel,
  type PolicyAction,
  redact,
} from "@piship/contracts";
import type { GovernedMcpTool } from "@piship/mcp";
import { isWithin, realpathNearest } from "@piship/sandbox";
import type { GovernanceSession } from "./governance-session.js";

/** True when `path` is `root` or below it. */
const inside = (root: string, path: string) => isWithin(path, root);

/** Tools a Plan-mode session may not run. */
export const PLAN_BLOCKED_TOOLS: ReadonlySet<string> = new Set([
  "write",
  "edit",
  "bash",
]);
export const PLAN_RULE = "piship-workflow.plan";

/** An approval channel backed by Pi's dialog UI, or none when headless. */
export function uiChannel(ctx: ExtensionContext): ApprovalChannel | undefined {
  if (!ctx.hasUI) return undefined;
  return async (_decision, detail) =>
    (await ctx.ui.confirm(detail.title, detail.message))
      ? "approved"
      : "denied";
}

class BlockedError extends Error {}

function blocked(message: string): BlockedError {
  return new BlockedError(redact(message));
}

/** Workspace, home, temp, or other: audit records a path class, not the path. */
export function pathClass(gov: GovernanceSession, path: string): string {
  const { workspaceRoot, homeDir, tmpDir } = gov.engine.context;
  const posix = path.split("\\").join("/");
  if (inside(workspaceRoot, posix)) return "workspace";
  if (inside(tmpDir, posix)) return "tmp";
  if (inside(homeDir, posix)) return "home";
  return "other";
}

/**
 * Decide one file access on both the path as given and its symlink-resolved
 * target; the stricter decision wins. Plan mode and the active sandbox
 * profile are applied to the same in-process tools.
 */
export async function gatePath(
  gov: GovernanceSession,
  action: Extract<PolicyAction, "filesystem.read" | "filesystem.write">,
  path: string,
  tool: string,
): Promise<void> {
  const lexical = resolve(path);
  const real = realpathNearest(lexical);
  const classOf = pathClass(gov, real);
  if (action === "filesystem.write" && gov.workflowMode === "plan") {
    gov.metrics.recordPolicyDenial(action);
    gov.emit("tool.denied", {
      resource: tool,
      decision: "denied",
      policy: gov.policyId,
      rule: PLAN_RULE,
      enforcement: "control-plane",
      detail: { action, path: classOf },
    });
    throw blocked(
      `Plan mode does not change files. Switch to Build mode (/build) to write ${path}.`,
    );
  }
  if (gov.sandbox.report.level === "enforced") {
    const profile = gov.sandbox.profile;
    const hidden = profile.readDeny.some(
      (denied) => inside(denied, real) || inside(denied, lexical),
    );
    const writable =
      action !== "filesystem.write" ||
      profile.writeAllow.some((allowed) => inside(allowed, real));
    if (hidden || !writable) {
      gov.metrics.recordPolicyDenial(action);
      gov.emit("tool.denied", {
        resource: tool,
        decision: "denied",
        policy: gov.policyId,
        rule: hidden
          ? "sandbox.filesystem.read.deny"
          : "sandbox.filesystem.write.allow",
        enforcement: "sandbox",
        detail: { action, path: classOf },
      });
      throw blocked(
        hidden
          ? `${path} is outside what this distribution lets tools read.`
          : `${path} is outside the directories this distribution lets tools write.`,
      );
    }
  }
  const decision = await gov.decide(
    action,
    [lexical, real],
    gov.currentChannel(),
    {
      denied: "tool.denied",
      resource: tool,
      detail: { path: classOf },
    },
  );
  if (decision.outcome !== "allow")
    throw blocked(
      `${action} ${path} is not allowed by ${decision.policyId} rule ${decision.ruleId}${decision.reason ? `: ${decision.reason}` : ""}${decision.approval === "unavailable" ? " (approval needs an interactive session)" : ""}.`,
    );
}

/** Decide a shell command; return a refusal message or undefined when allowed. */
async function gateCommand(
  gov: GovernanceSession,
  command: string,
  source: "bash" | "user-bash",
): Promise<string | undefined> {
  if (gov.workflowMode === "plan") {
    gov.metrics.recordPolicyDenial("shell.execute");
    gov.emit("tool.denied", {
      resource: source,
      decision: "denied",
      policy: gov.policyId,
      rule: PLAN_RULE,
      enforcement: "control-plane",
      detail: { action: "shell.execute" },
    });
    return "Plan mode does not run commands. Switch to Build mode (/build) first.";
  }
  const decision = await gov.decide(
    "shell.execute",
    command,
    gov.currentChannel(),
    {
      allowed: "tool.allowed",
      denied: "tool.denied",
      resource: source,
      detail: { commandBytes: Buffer.byteLength(command) },
      content: { command },
    },
  );
  if (decision.outcome === "allow") return undefined;
  return `This command is not allowed by ${decision.policyId} rule ${decision.ruleId}${decision.reason ? `: ${decision.reason}` : ""}${decision.approval === "unavailable" ? " (approval needs an interactive session)" : ""}.`;
}

/**
 * Shell operations: policy first, then the OS sandbox when it is enforced.
 * Without an enforced sandbox the command runs as Pi would run it, and the
 * decision was control-plane only.
 */
export function governedBashOperations(
  gov: GovernanceSession,
  source: "bash" | "user-bash",
): BashOperations {
  const local = createLocalBashOperations();
  return {
    exec: async (command, cwd, options) => {
      const refusal = await gateCommand(gov, command, source);
      if (refusal) {
        if (source === "bash") throw blocked(refusal);
        options.onData(Buffer.from(`${refusal}\n`));
        return { exitCode: 126 };
      }
      if (gov.sandbox.report.level === "enforced")
        return gov.sandbox.exec(command, cwd, {
          onData: options.onData,
          ...(options.signal ? { signal: options.signal } : {}),
          ...(options.timeout !== undefined
            ? { timeout: options.timeout }
            : {}),
          ...(options.env ? { env: options.env } : {}),
        });
      return local.exec(command, cwd, options);
    },
  };
}

function withChannel<T extends ToolDefinition>(
  gov: GovernanceSession,
  tool: T,
): T {
  const execute = tool.execute.bind(tool);
  return {
    ...tool,
    execute: (id, params, signal, onUpdate, ctx) =>
      gov.withChannel(uiChannel(ctx), () =>
        execute(id, params, signal, onUpdate, ctx),
      ),
  } as T;
}

function mcpTool(tool: GovernedMcpTool): ToolDefinition {
  return {
    name: tool.name,
    label: `${tool.server}: ${tool.tool}`,
    description:
      tool.description || `${tool.tool} from the ${tool.server} MCP server`,
    promptSnippet: `${tool.name}: ${(tool.description || tool.tool).split("\n")[0]}`,
    parameters: tool.inputSchema as never,
    executionMode: "sequential",
    async execute(_id, params, signal) {
      const result = await tool.call(params as Record<string, unknown>, signal);
      if (result.isError) throw new Error(result.text || "MCP tool failed");
      return {
        content: [{ type: "text", text: result.text }],
        details: {
          server: tool.server,
          tool: tool.tool,
          truncated: result.truncated,
        },
      };
    },
  };
}

/** The governed tool set for a v1alpha3 session. */
export function governedTools(
  gov: GovernanceSession,
  cwd: string,
): ToolDefinition[] {
  const absolute = (path: string) =>
    isAbsolute(path) ? path : resolve(cwd, path);
  const read = async (path: string, tool: string) => {
    await gatePath(gov, "filesystem.read", absolute(path), tool);
    return readFile(path);
  };
  const exists = async (path: string, tool: string) => {
    await gatePath(gov, "filesystem.read", absolute(path), tool);
    await access(path, constants.R_OK);
  };
  const tools: ToolDefinition[] = [
    createReadToolDefinition(cwd, {
      operations: {
        readFile: (path) => read(path, "read"),
        access: (path) => exists(path, "read"),
      },
    }) as ToolDefinition,
    createWriteToolDefinition(cwd, {
      operations: {
        writeFile: async (path, content) => {
          await gatePath(gov, "filesystem.write", absolute(path), "write");
          await writeFile(path, content, "utf8");
        },
        mkdir: async (dir) => {
          await gatePath(gov, "filesystem.write", absolute(dir), "write");
          await mkdir(dir, { recursive: true });
        },
      },
    }) as ToolDefinition,
    createEditToolDefinition(cwd, {
      operations: {
        readFile: (path) => read(path, "edit"),
        access: async (path) => {
          await gatePath(gov, "filesystem.write", absolute(path), "edit");
          await access(path, constants.R_OK | constants.W_OK);
        },
        writeFile: async (path, content) => {
          await gatePath(gov, "filesystem.write", absolute(path), "edit");
          await writeFile(path, content, "utf8");
        },
      },
    }) as ToolDefinition,
    createBashToolDefinition(cwd, {
      operations: governedBashOperations(gov, "bash"),
    }) as ToolDefinition,
    ...(gov.mcp?.tools() ?? []).map(mcpTool),
  ];
  return tools.map((tool) => withChannel(gov, tool));
}

export function isBlockedError(error: unknown): boolean {
  return error instanceof BlockedError;
}
