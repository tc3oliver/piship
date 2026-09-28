// PiShip's built-in extensions for piship/v1alpha3 distributions: the
// governance hooks, `piship-ask-user`, and the small Plan/Build workflow.
// They use only public Pi extension surfaces; Pi's agent loop and TUI stay
// upstream.
import type {
  ExtensionContext,
  InlineExtension,
} from "@earendil-works/pi-coding-agent";
import { PiShipError, redact } from "@piship/contracts";
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

function attach(gov: GovernanceSession, ctx: ExtensionContext): void {
  gov.toolApproval = uiChannel(ctx);
}

async function decideToolCall(
  gov: GovernanceSession,
  tool: string,
  ctx: ExtensionContext,
): Promise<{ block: true; reason: string } | undefined> {
  attach(gov, ctx);
  const refusal = planRefusal(gov, tool);
  if (refusal) return { block: true, reason: refusal };
  gov.emit("tool.request", { resource: tool });
  const decision = await gov.withChannel(uiChannel(ctx), () =>
    gov.decide("tool.execute", tool, gov.currentChannel(), {
      allowed: "tool.allowed",
      denied: "tool.denied",
      resource: tool,
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
      pi.on("session_start", (_event, ctx) => attach(gov, ctx));
      pi.on("tool_call", async (event, ctx) => {
        const tool = event.toolName;
        try {
          return await decideToolCall(gov, tool, ctx);
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

/** `piship-ask-user`: an explicit choice or approval from the user. */
export function askUserExtension(gov: GovernanceSession): InlineExtension {
  return {
    name: "piship-ask-user",
    factory: (pi) => {
      pi.registerTool({
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
        async execute(_id, params, _signal, _onUpdate, ctx) {
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
          if (options.length) {
            const choice = await ctx.ui.select(input.question, [...options]);
            return choice === undefined
              ? reply(
                  "cancelled",
                  "The user cancelled the question without choosing.",
                )
              : reply("answered", `The user chose: ${choice}`);
          }
          const approved = await ctx.ui.confirm("Question", input.question);
          return approved
            ? reply("approved", "The user approved.")
            : reply("denied", "The user declined.");
        },
      });
    },
  };
}

/** `piship-workflow`: Plan/Build with enforced tool restrictions in Plan. */
export function workflowExtension(
  gov: GovernanceSession,
  settings: Readonly<Record<string, string>>,
): InlineExtension {
  const initial = settings.defaultMode === "build" ? "build" : "plan";
  const prompts = {
    plan: settings.planPrompt || DEFAULT_PLAN_PROMPT,
    build: settings.buildPrompt || DEFAULT_BUILD_PROMPT,
  };
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
      pi.on("before_agent_start", (event) => ({
        systemPrompt: `${event.systemPrompt}\n\n${gov.workflowMode === "plan" ? prompts.plan : prompts.build}`,
      }));
    },
  };
}
