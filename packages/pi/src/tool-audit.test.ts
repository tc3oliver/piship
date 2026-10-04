// Tool call audit keyed on Pi's tool_execution_start/end: every attempt is
// recorded once, with where it came from (top-level, a Codemode script, or
// another extension tool's ctx.executeTool), and a call Pi refuses before
// PiShip's tool_call hook is classified without its error text.
import type { ExtensionFactory } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import {
  governanceHooks,
  PRE_POLICY_RULE,
  UNRESOLVED_EXPOSURE_RULE,
} from "./builtins.js";
import type { GovernanceSession } from "./governance-session.js";

interface Emitted {
  readonly event: string;
  readonly fields: Record<string, unknown>;
}

function setup(
  options: {
    mode?: "managed" | "personal";
    exposure?: Record<string, string>;
    tools?: { name: string; exposure: string }[];
    active?: string[];
    /** Extensions loaded before PiShip's whose tool_call handlers run first; null: order unknown. */
    before?: { tool_call: number }[] | null | undefined;
  } = {},
) {
  const emitted: Emitted[] = [];
  const decided: { tool: string; detail: unknown }[] = [];
  const exposure = options.exposure ?? {
    read: "direct",
    codemode: "model-only",
    company_batch: "direct",
  };
  const gov = {
    options: { lock: { deployment: { mode: options.mode ?? "personal" } } },
    policyId: "unit",
    workflowMode: null,
    userAuto: { active: false },
    metrics: { recordPolicyDenial: () => undefined },
    exposure: { get: (name: string) => exposure[name] },
    piExtensions:
      options.before === null
        ? null
        : () => [
            ...(options.before ?? []).map((item, index) => ({
              path: `/ext/${index}.js`,
              handlers: new Map(
                item.tool_call
                  ? [["tool_call", Array(item.tool_call).fill(() => undefined)]]
                  : [],
              ),
            })),
            { path: "<inline:piship-policy>", handlers: new Map() },
          ],
    emit: (event: string, fields: Record<string, unknown> = {}) =>
      emitted.push({ event, fields }),
    attachNotices: () => undefined,
    withChannel: (_channel: unknown, run: () => unknown) => run(),
    currentChannel: () => undefined,
    decide: async (
      _action: string,
      tool: string,
      _channel: unknown,
      events: { detail?: unknown },
    ) => {
      decided.push({ tool, detail: events.detail });
      return { outcome: "allow" };
    },
  } as unknown as GovernanceSession;
  const handlers = new Map<
    string,
    (event: unknown, ctx?: unknown) => unknown
  >();
  const extension = governanceHooks(gov);
  (
    (typeof extension === "function"
      ? extension
      : extension.factory) as ExtensionFactory
  )({
    on: (name: string, handler: (event: unknown) => unknown) =>
      handlers.set(name, handler),
    registerCommand: () => undefined,
    getAllTools: () => options.tools ?? [],
    getActiveTools: () => options.active ?? [],
  } as never);
  const ctx = { hasUI: false, ui: { notify: () => undefined } };
  const on = (name: string) => {
    const handler = handlers.get(name);
    if (!handler) throw new Error(`no ${name} handler`);
    return (event: object) => handler(event, ctx);
  };
  return { emitted, decided, on };
}

describe("tool call audit", () => {
  it("records each attempt at its start, with its source, parent, and exposure", async () => {
    const { emitted, decided, on } = setup();
    on("tool_execution_start")({ toolCallId: "c1", toolName: "codemode" });
    on("tool_execution_start")({
      toolCallId: "c1/1",
      toolName: "read",
      parentToolCallId: "c1",
    });
    on("tool_execution_start")({ toolCallId: "c2", toolName: "company_batch" });
    on("tool_execution_start")({
      toolCallId: "c2/1",
      toolName: "read",
      parentToolCallId: "c2",
    });
    expect(
      emitted.map(({ event, fields }) => [
        event,
        fields.resource,
        fields.detail,
      ]),
    ).toEqual([
      [
        "tool.request",
        "codemode",
        { source: "top-level", exposure: "model-only" },
      ],
      [
        "tool.request",
        "read",
        { source: "codemode", parent: "c1", exposure: "direct" },
      ],
      [
        "tool.request",
        "company_batch",
        { source: "top-level", exposure: "direct" },
      ],
      [
        "tool.request",
        "read",
        { source: "nested", parent: "c2", exposure: "direct" },
      ],
    ]);
    await on("tool_call")({
      toolCallId: "c1/1",
      toolName: "read",
      parentToolCallId: "c1",
      input: {},
    });
    expect(decided).toEqual([
      {
        tool: "read",
        detail: { source: "codemode", parent: "c1", exposure: "direct" },
      },
    ]);
    // A call the policy decided is not recorded again when it ends.
    on("tool_execution_end")({
      toolCallId: "c1/1",
      toolName: "read",
      parentToolCallId: "c1",
      isError: true,
    });
    expect(emitted.filter((item) => item.event === "tool.denied")).toEqual([]);
  });

  const refusedBeforePolicy = (before?: { tool_call: number }[] | null) => {
    const { emitted, on } = setup({
      tools: [
        { name: "read", exposure: "direct" },
        { name: "codemode", exposure: "model-only" },
      ],
      active: ["read", "codemode"],
      before,
    });
    const attempt = (
      id: string,
      toolName: string,
      parent?: string,
      text = "secret-canary",
    ) => {
      const event = {
        toolCallId: id,
        toolName,
        ...(parent ? { parentToolCallId: parent } : {}),
      };
      on("tool_execution_start")(event);
      on("tool_execution_end")({
        ...event,
        isError: true,
        result: { content: [{ type: "text", text }] },
      });
    };
    on("tool_execution_start")({ toolCallId: "p", toolName: "codemode" });
    attempt("p/1", "read", "p"); // bad arguments, or an earlier hook
    attempt("p/2", "hidden_tool", "p"); // excluded: not registered
    attempt("p/3", "codemode", "p"); // model-only: never callable nested
    attempt("t1", "nope"); // top-level unknown name
    // The text never decides: a hook can word its reason like Pi's.
    attempt("t2", "read", undefined, 'Validation failed for tool "read":');
    expect(JSON.stringify(emitted)).not.toContain("secret-canary");
    return emitted
      .filter((item) => item.event === "tool.denied")
      .map(({ fields }) => [
        fields.resource,
        fields.rule,
        (fields.detail as Record<string, unknown>).error,
        (fields.detail as Record<string, unknown>).source,
      ]);
  };

  it("classifies a call refused before policy as not-found or invalid-arguments when no hook runs before PiShip's", () => {
    expect(refusedBeforePolicy([{ tool_call: 0 }])).toEqual([
      ["read", PRE_POLICY_RULE, "invalid-arguments", "codemode"],
      ["hidden_tool", PRE_POLICY_RULE, "not-found", "codemode"],
      ["codemode", PRE_POLICY_RULE, "not-found", "codemode"],
      ["nope", PRE_POLICY_RULE, "not-found", "top-level"],
      ["read", PRE_POLICY_RULE, "invalid-arguments", "top-level"],
    ]);
  });

  it("classifies a callable tool as refused-before-policy when another hook runs first, or the order is unknown", () => {
    for (const before of [[{ tool_call: 1 }], null])
      expect(refusedBeforePolicy(before)).toEqual([
        ["read", PRE_POLICY_RULE, "refused-before-policy", "codemode"],
        ["hidden_tool", PRE_POLICY_RULE, "not-found", "codemode"],
        ["codemode", PRE_POLICY_RULE, "not-found", "codemode"],
        ["nope", PRE_POLICY_RULE, "not-found", "top-level"],
        ["read", PRE_POLICY_RULE, "refused-before-policy", "top-level"],
      ]);
  });

  it("managed: refuses a tool registered after the exposure was resolved", async () => {
    const managed = setup({ mode: "managed" });
    const result = await managed.on("tool_call")({
      toolCallId: "late",
      toolName: "late_tool",
      input: {},
    });
    expect(result).toMatchObject({ block: true });
    expect(managed.decided).toEqual([]);
    expect(managed.emitted.at(-1)).toMatchObject({
      event: "tool.denied",
      fields: { resource: "late_tool", rule: UNRESOLVED_EXPOSURE_RULE },
    });
    // Personal: the policy decides it.
    const personal = setup();
    expect(
      await personal.on("tool_call")({
        toolCallId: "late",
        toolName: "late_tool",
        input: {},
      }),
    ).toBeUndefined();
    expect(personal.decided.map((item) => item.tool)).toEqual(["late_tool"]);
  });

  it("managed: refuses a tool re-registered with a wider exposure than launch resolved", async () => {
    const options = {
      exposure: { company_batch: "deferred", company_same: "codemode" },
      tools: [
        { name: "company_batch", exposure: "direct" },
        { name: "company_same", exposure: "codemode" },
      ],
    };
    const managed = setup({ ...options, mode: "managed" });
    expect(
      await managed.on("tool_call")({
        toolCallId: "w",
        toolName: "company_batch",
        input: {},
      }),
    ).toMatchObject({ block: true });
    expect(managed.emitted.at(-1)).toMatchObject({
      event: "tool.denied",
      fields: { resource: "company_batch", rule: UNRESOLVED_EXPOSURE_RULE },
    });
    // The exposure it was resolved with goes on to policy.
    expect(
      await managed.on("tool_call")({
        toolCallId: "s",
        toolName: "company_same",
        input: {},
      }),
    ).toBeUndefined();
    expect(managed.decided.map((item) => item.tool)).toEqual(["company_same"]);
    // Personal: the policy decides it.
    const personal = setup(options);
    expect(
      await personal.on("tool_call")({
        toolCallId: "w",
        toolName: "company_batch",
        input: {},
      }),
    ).toBeUndefined();
    expect(personal.decided.map((item) => item.tool)).toEqual([
      "company_batch",
    ]);
  });
});
