// PiShip's built-in extensions for piship/v1alpha3 distributions: the
// governance hooks, `piship-ask-user` (an SDK custom tool), and the small
// Plan/Build workflow. They use only public Pi extension and SDK surfaces;
// Pi's agent loop and TUI stay upstream.
import type {
  ExtensionContext,
  InlineExtension,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import {
  type AuditExecutionSource,
  formatError,
  PiShipError,
  redact,
  type ToolCallFailure,
} from "@piship/contracts";
import { describeUserAuto, describeYolo } from "@piship/core";
import type { ToolExposure } from "@piship/schema";
import { CODEMODE_TOOL, widerExposure } from "./governance/exposure.js";
import type { GovernanceSession } from "./governance-session.js";
import {
  governedBashOperations,
  planRefusal,
  uiChannel,
} from "./governed-tools.js";

export const DEFAULT_PLAN_PROMPT =
  "You are in Plan mode. Investigate and propose a plan. Only the read and ask_user tools are available: do not change files, run commands, or call other tools; the user switches to Build mode with /build when the plan is ready.";
export const DEFAULT_BUILD_PROMPT =
  "You are in Build mode. Carry out the agreed plan with the available tools.";

function showAuto(gov: GovernanceSession, ctx: ExtensionContext): void {
  if (ctx.hasUI)
    ctx.ui.setStatus(
      "piship-auto",
      gov.yolo ? "YOLO" : gov.userAuto.active ? "Auto" : undefined,
    );
}

/**
 * `/auto [on|off|status]`: the user's auto mode, when the distribution
 * allows it. A refusal (`policy.userAuto` off) is shown, never thrown into
 * Pi's command loop.
 */
async function autoCommand(
  gov: GovernanceSession,
  args: string,
  ctx: ExtensionContext,
): Promise<void> {
  const action = args.trim() || "status";
  let message: string;
  let level: "info" | "warning" | "error" = "info";
  const mode = gov.options.lock.deployment.mode;
  if (action === "status")
    message = `Auto mode: ${
      gov.yolo
        ? describeYolo(mode)
        : mode === "personal"
          ? "yolo is off for this session"
          : describeUserAuto(gov.userAuto)
    }`;
  else if (action === "on" || action === "off")
    try {
      const status = await gov.switchUserAuto(action === "on");
      message = status.active
        ? "Auto mode is on: asks from the distribution defaults are approved without a prompt and audited; deny and enforced rules still apply."
        : (status.warning ?? "Auto mode is off.");
      if (status.warning) level = "warning";
    } catch (error) {
      message = formatError(error);
      level = "error";
    }
  else {
    message = "Usage: /auto on | /auto off | /auto status";
    level = "warning";
  }
  showAuto(gov, ctx);
  if (ctx.hasUI) ctx.ui.notify(message, level);
}

function attach(gov: GovernanceSession, ctx: ExtensionContext): void {
  gov.toolApproval = uiChannel(ctx);
  // Session notices (a workspace weaker than declared) reach the screen once
  // the session has a UI; without one they stay held, not lost.
  if (ctx.hasUI)
    gov.attachNotices((message) => ctx.ui.notify(message, "warning"));
}

/** Where a call came from, its parent, and its exposure (audit `detail`). */
type CallDetail = Readonly<Record<string, string>>;

/** A tool call PiShip saw start: gated once its tool_call hook ran. */
interface TrackedCall {
  readonly name: string;
  readonly detail: CallDetail;
  gated: boolean;
}

/** Recorded when a call fails before PiShip's tool_call hook decides it. */
export const PRE_POLICY_RULE = "piship.pre-policy";
/** Managed: a tool registered after the session's exposure was resolved. */
export const UNRESOLVED_EXPOSURE_RULE = "piship.exposure.unresolved";

const lateNoticed = new WeakMap<GovernanceSession, Set<string>>();

/**
 * A tool registered after the session's exposure was resolved (in
 * `session_start` or later) has an exposure nobody checked against the
 * manifest. Managed: it is refused. Personal: policy alone decides, with a
 * notice once per tool.
 */
function lateRegistration(
  gov: GovernanceSession,
  tool: string,
  ctx: ExtensionContext,
): { block: true; reason: string } | undefined {
  if (!gov.exposure || gov.exposure.get(tool) !== undefined) return undefined;
  return unresolvedExposure(
    gov,
    tool,
    ctx,
    `${tool} was registered after the session started`,
  );
}

function unresolvedExposure(
  gov: GovernanceSession,
  tool: string,
  ctx: ExtensionContext,
  what: string,
): { block: true; reason: string } | undefined {
  if (gov.options.lock.deployment.mode !== "managed") {
    const noticed = lateNoticed.get(gov) ?? new Set<string>();
    lateNoticed.set(gov, noticed);
    if (!noticed.has(tool) && ctx.hasUI)
      ctx.ui.notify(
        `${what}, so its exposure was not checked against the distribution; the policy still decides each call.`,
        "warning",
      );
    noticed.add(tool);
    return undefined;
  }
  gov.metrics.recordPolicyDenial("tool.execute");
  gov.emit("tool.denied", {
    resource: tool,
    decision: "denied",
    policy: gov.policyId,
    rule: UNRESOLVED_EXPOSURE_RULE,
    enforcement: "control-plane",
    detail: { action: "tool.execute" },
  });
  return {
    block: true,
    reason: redact(
      `${what}, and this distribution only runs tools whose exposure it resolved at launch`,
    ),
  };
}

/** Pi's path for an inline extension (`<inline:name>`). */
const POLICY_EXTENSION_PATH = "<inline:piship-policy>";

/**
 * Whether another tool_call handler runs before PiShip's, or undefined when
 * the order is unknown. Pi stops at the first handler that blocks, so a
 * call refused there never reaches PiShip's hook, just like a call whose
 * arguments failed validation; with no handler before PiShip's, only
 * validation can have refused it.
 */
function toolCallHandlerBefore(gov: GovernanceSession): boolean | undefined {
  const extensions = gov.piExtensions?.();
  if (!extensions) return undefined;
  const own = extensions.findIndex(
    (extension) => extension.path === POLICY_EXTENSION_PATH,
  );
  if (own < 0) return undefined;
  return extensions
    .slice(0, own)
    .some(
      (extension) => (extension.handlers.get("tool_call")?.length ?? 0) > 0,
    );
}

/**
 * A tool whose live exposure is wider than the exposure resolved at launch:
 * an extension re-registered it (in `session_start` or later) after the
 * table was built. Managed: refused. Personal: policy alone decides, with a
 * notice once per tool.
 */
function widenedRegistration(
  gov: GovernanceSession,
  tool: string,
  liveExposure: () => ToolExposure | undefined,
  ctx: ExtensionContext,
): { block: true; reason: string } | undefined {
  const resolved = gov.exposure?.get(tool);
  if (!resolved) return undefined;
  const live = liveExposure();
  if (!live || !widerExposure(live, resolved)) return undefined;
  return unresolvedExposure(
    gov,
    tool,
    ctx,
    `${tool} was re-registered with exposure ${live} after the session started, wider than the ${resolved} the distribution resolved at launch`,
  );
}

async function decideToolCall(
  gov: GovernanceSession,
  tool: string,
  ctx: ExtensionContext,
  detail: CallDetail = {},
): Promise<{ block: true; reason: string } | undefined> {
  attach(gov, ctx);
  const refusal = planRefusal(gov, tool);
  if (refusal) return { block: true, reason: refusal };
  const decision = await gov.withChannel(uiChannel(ctx), () =>
    gov.decide("tool.execute", tool, gov.currentChannel(), {
      allowed: "tool.allowed",
      denied: "tool.denied",
      resource: tool,
      detail,
    }),
  );
  if (decision.outcome === "allow") return undefined;
  return {
    block: true,
    reason: redact(
      `${tool} is not allowed by ${decision.policyId} rule ${decision.ruleId}${decision.reason ? `: ${decision.reason}` : ""}${decision.approval === "unavailable" ? " (approval needs an interactive session)" : ""}`,
    ),
  };
}

/** Tool-call policy, `!` shell containment, and model request audit. */
export function governanceHooks(gov: GovernanceSession): InlineExtension {
  return {
    name: "piship-policy",
    factory: (pi) => {
      pi.on("session_start", (_event, ctx) => {
        attach(gov, ctx);
        showAuto(gov, ctx);
        if (gov.yolo && ctx.hasUI)
          ctx.ui.notify(
            `${describeYolo(gov.options.lock.deployment.mode)}; /auto off ends it`,
            "warning",
          );
      });
      // Managed, or a personal session started with --yolo (to see it and
      // end it): a personal user owns the policy (config/policy.json).
      if (gov.options.lock.deployment.mode === "managed" || gov.yolo)
        pi.registerCommand("auto", {
          description:
            gov.options.lock.deployment.mode === "managed"
              ? "Auto mode: approve asks from the distribution defaults without a prompt (on, off, or status); deny and enforced rules still apply"
              : "Yolo: show whether every ask is approved without a prompt in this session (status), or end it (off)",
          handler: (args, ctx) => autoCommand(gov, args, ctx),
        });
      // Audit is keyed on tool_execution_start/end, not tool_call: a call
      // to an unknown tool or with invalid arguments ends before tool_call.
      // Nested calls (Codemode scripts, an extension's ctx.executeTool)
      // pass through the same hooks with their parent's call ID.
      const calls = new Map<string, TrackedCall>();
      const callDetail = (
        name: string,
        parent: string | undefined,
      ): CallDetail => {
        const source: AuditExecutionSource = !parent
          ? "top-level"
          : calls.get(parent)?.name === CODEMODE_TOOL
            ? "codemode"
            : "nested";
        const exposure = gov.exposure?.get(name);
        return {
          source,
          ...(parent ? { parent } : {}),
          ...(exposure ? { exposure } : {}),
        };
      };
      pi.on("tool_execution_start", (event) => {
        const detail = callDetail(event.toolName, event.parentToolCallId);
        calls.set(event.toolCallId, {
          name: event.toolName,
          detail,
          gated: false,
        });
        gov.emit("tool.request", { resource: event.toolName, detail });
      });
      pi.on("tool_execution_end", (event) => {
        const call = calls.get(event.toolCallId);
        calls.delete(event.toolCallId);
        if (!call || call.gated || !event.isError) return;
        // Pi refused the call before PiShip's policy hook ran.
        const tool = event.toolName;
        const info = pi.getAllTools().find((item) => item.name === tool);
        const callable = event.parentToolCallId
          ? info !== undefined &&
            (info.exposure === "codemode" ||
              info.exposure === "deferred" ||
              (info.exposure === "direct" &&
                pi.getActiveTools().includes(tool)))
          : pi.getActiveTools().includes(tool);
        // Pi validates the arguments before any tool_call hook runs. The
        // error text is the refusing extension's to choose, so it is never
        // read: a failure is invalid-arguments only when no other handler
        // runs before PiShip's.
        const error: ToolCallFailure = !callable
          ? "not-found"
          : toolCallHandlerBefore(gov) === false
            ? "invalid-arguments"
            : "refused-before-policy";
        gov.emit("tool.denied", {
          resource: tool,
          decision: "denied",
          policy: gov.policyId,
          rule: PRE_POLICY_RULE,
          enforcement: "control-plane",
          detail: { action: "tool.execute", ...call.detail, error },
        });
      });
      pi.on("agent_end", () => calls.clear());
      pi.on("tool_call", async (event, ctx) => {
        const tool = event.toolName;
        const call = calls.get(event.toolCallId);
        if (call) call.gated = true;
        try {
          const late =
            lateRegistration(gov, tool, ctx) ??
            widenedRegistration(
              gov,
              tool,
              () =>
                pi.getAllTools().find((item) => item.name === tool)?.exposure,
              ctx,
            );
          if (late) return late;
          return await decideToolCall(
            gov,
            tool,
            ctx,
            call?.detail ?? callDetail(tool, event.parentToolCallId),
          );
        } catch (error) {
          // Fail closed: a tool call whose decision failed never runs.
          const code = error instanceof PiShipError ? error.code : undefined;
          try {
            gov.emit("tool.denied", {
              resource: tool,
              detail: { error: code ?? "internal" },
            });
          } catch {
            // Audit failure must not turn the block into an allow.
          }
          return {
            block: true,
            reason: redact(
              `${tool} was blocked because the policy check failed${code ? ` (${code})` : ""}`,
            ),
          };
        }
      });
      pi.on("user_bash", (_event, ctx) => {
        attach(gov, ctx);
        return { operations: governedBashOperations(gov, "user-bash") };
      });
      // Pi writes a `!` command's full output to its own pi-bash-*.log and
      // records the path in the session; the session's close removes them.
      pi.on("session_shutdown", (_event, ctx) => {
        gov.outputStore.adoptUserBashOutput(ctx.sessionManager.getEntries());
      });
      pi.on("before_provider_request", (_event, ctx) => {
        const model = ctx.model;
        gov.emit("model.request", {
          ...(model ? { resource: `${model.provider}/${model.id}` } : {}),
        });
      });
    },
  };
}

interface AskInput {
  readonly question: string;
  readonly options?: readonly string[];
}

/**
 * `piship-ask-user`: an explicit choice or approval from the user. Passed to
 * Pi as an SDK custom tool: those win a name conflict with extension tools,
 * so a loaded extension cannot replace the tool Plan mode allows by name.
 */
export function askUserTool(gov: GovernanceSession): ToolDefinition {
  return {
    name: "ask_user",
    label: "Ask user",
    description:
      "Ask the user a question and wait for the answer. Give options for a choice; without options the question is a yes/no approval. Use it only when the user's decision is needed.",
    promptSnippet:
      "ask_user: ask the user for a decision (choice or yes/no approval)",
    parameters: {
      type: "object",
      properties: {
        question: { type: "string", description: "The question to ask." },
        options: {
          type: "array",
          items: { type: "string" },
          description: "Choices to offer; omit for a yes/no approval.",
        },
      },
      required: ["question"],
      additionalProperties: false,
    } as never,
    executionMode: "sequential",
    async execute(_id, params, signal, _onUpdate, ctx) {
      const input = params as AskInput;
      const reply = (outcome: string, text: string) => {
        gov.emit("tool.request", {
          resource: "ask_user",
          detail: { outcome },
        });
        return {
          content: [{ type: "text" as const, text }],
          details: { outcome },
        };
      };
      if (!ctx.hasUI)
        return reply(
          "unavailable",
          "No interactive user is available to answer. Do not assume an answer; stop and report what decision is needed.",
        );
      const options = (input.options ?? []).filter(
        (item) => typeof item === "string" && item.trim(),
      );
      // Pi does not queue dialogs: the question waits for open approval
      // prompts (Codemode can run it next to a call that asks), and closes
      // with the call.
      const dialog = signal ? { signal } : {};
      const cancelled = () =>
        reply("cancelled", "The user cancelled the question without choosing.");
      if (options.length) {
        const choice = await gov.serializeDialog(async () =>
          signal?.aborted
            ? undefined
            : ctx.ui.select(input.question, [...options], dialog),
        );
        return choice === undefined
          ? cancelled()
          : reply("answered", `The user chose: ${choice}`);
      }
      const approved = await gov.serializeDialog(async () =>
        signal?.aborted
          ? undefined
          : ctx.ui.confirm("Question", input.question, dialog),
      );
      if (approved === undefined) return cancelled();
      return approved
        ? reply("approved", "The user approved.")
        : reply("denied", "The user declined.");
    },
  };
}

/** The system prompt section of the current workflow mode. */
export function workflowSection(
  gov: GovernanceSession,
  settings: Readonly<Record<string, string>>,
): string {
  return gov.workflowMode === "build"
    ? settings.buildPrompt || DEFAULT_BUILD_PROMPT
    : settings.planPrompt || DEFAULT_PLAN_PROMPT;
}

/** `piship-workflow`: Plan/Build with enforced tool restrictions in Plan. */
export function workflowExtension(
  gov: GovernanceSession,
  settings: Readonly<Record<string, string>>,
): InlineExtension {
  const initial = settings.defaultMode === "build" ? "build" : "plan";
  gov.workflowMode = initial;
  const show = (ctx: ExtensionContext) => {
    if (ctx.hasUI)
      ctx.ui.setStatus(
        "piship-workflow",
        gov.workflowMode === "plan" ? "Plan mode" : "Build mode",
      );
  };
  return {
    name: "piship-workflow",
    factory: (pi) => {
      const switchTo =
        (mode: "plan" | "build") =>
        async (_args: string, ctx: ExtensionContext) => {
          gov.workflowMode = mode;
          gov.emit("policy.loaded", {
            policy: gov.policyId,
            detail: { workflowMode: mode },
          });
          show(ctx);
          if (ctx.hasUI)
            ctx.ui.notify(
              mode === "plan"
                ? "Plan mode: only reading files and asking the user are allowed."
                : "Build mode: tools follow the distribution policy.",
              "info",
            );
        };
      pi.registerCommand("plan", {
        description:
          "Plan mode: investigate with read-only tools; no changes, commands, or other tools",
        handler: switchTo("plan"),
      });
      pi.registerCommand("build", {
        description: "Build mode: make changes under the distribution policy",
        handler: switchTo("build"),
      });
      pi.on("session_start", (_event, ctx) => show(ctx));
      // A named prompt section, not a forced prompt: the prompt stays
      // structured, and the runtime integrity extension re-asserts it.
      pi.on("before_agent_start", (event) => {
        event.systemPromptOptions.sections.piship_workflow = workflowSection(
          gov,
          settings,
        );
      });
    },
  };
}
