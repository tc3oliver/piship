// Audit events of governed sessions, emitted by the real launch-time flows
// (GovernanceSession, the governed tools and hooks, MCP, capability
// providers, model policy) into a real file sink; and what closing a session
// does with events a required sink did not take.
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  type ExtensionFactory,
  type ExtensionToolContext,
  type InlineExtension,
  SessionManager,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { LocalMetrics } from "@piship/audit";
import {
  AUDIT_EVENT_TYPES,
  type AuditEvent,
  type AuditEventType,
  type ManagedFetch,
} from "@piship/contracts";
import { resolveLock } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { governanceHooks } from "./builtins.js";
import { GovernanceSession } from "./governance-session.js";
import { governedTools } from "./governed-tools.js";
import { modelPolicy } from "./launch/governance.js";

/**
 * Emitted by the branded commands outside a session, and proven from their
 * real flows in packages/core/src/branded-audit.test.ts.
 */
const OUTSIDE_A_SESSION = [
  "identity.login",
  "identity.refresh",
  "identity.logout",
  "credential.acquire",
  "credential.refresh",
  "credential.revoke",
  "runtime.update",
  "runtime.rollback",
];
/**
 * v0.9 event types the contract already carries but no runtime flow emits
 * yet: model dispatch (09-B4), runtime mutation repair (09-B5), and the data
 * sweep and session export (09-B7). Each task removes its names from this
 * list when its flow emits them.
 */
const NOT_YET_EMITTED: readonly AuditEventType[] = [
  "model.dispatch",
  "session.export",
  "runtime.mutation.reverted",
  "data.swept",
];

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0))
    await session.close().catch(() => undefined);
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const fixture = (name: string) =>
  readFileSync(
    new URL(`../../mcp/src/testing/${name}`, import.meta.url),
    "utf8",
  );
// One copy of the stdio fixture server per declared server.
const MCP_FILES = Object.fromEntries(
  [
    ["docs.mjs", "fixture-server.mjs"],
    ["blocked.mjs", "fixture-server.mjs"],
    ["fixture-core.mjs", "fixture-core.mjs"],
  ].flatMap(([name, source]) => [
    [`mcp/${name}`, fixture(source as string)],
    [`resources/mcp/${name}`, fixture(source as string)],
  ]),
);
const PROVIDER_FILES = {
  "providers/flow/index.ts": "export default () => {};\n",
  "resources/providers/flow/index.ts": "export default () => {};\n",
};

const rule = (id: string, action: string, resource: string, effect = "allow") =>
  `    - { id: ${id}, action: ${action}, resource: "${resource}", effect: ${effect} }`;

async function open(
  lines: string[],
  options: {
    readonly mode?: "managed" | "personal";
    readonly userRules?: readonly unknown[];
    readonly fetch?: ManagedFetch;
    readonly metrics?: LocalMetrics;
    /** `policy.userAuto` of a v1alpha5 manifest, set on the v1alpha3 lock. */
    readonly userAuto?: "allowed";
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "piship-audit-events-"));
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  mkdirSync(workspace, { recursive: true });
  writeFileSync(join(workspace, "notes.txt"), "source-canary\n");
  for (const [path, content] of Object.entries({
    ...MCP_FILES,
    ...PROVIDER_FILES,
  })) {
    mkdirSync(dirname(join(distribution, path)), { recursive: true });
    writeFileSync(join(distribution, path), content);
  }
  if (options.userRules) {
    mkdirSync(join(root, "state", "config"), { recursive: true });
    writeFileSync(
      join(root, "state", "config", "policy.json"),
      JSON.stringify(options.userRules),
    );
  }
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "1.0.2" }',
      "deployment: { mode: personal }",
      ...lines,
      "",
    ].join("\n"),
  );
  const resolved = resolveLock(manifest);
  const governance = resolved.governance;
  const lock = {
    ...resolved,
    ...(options.mode
      ? { deployment: { ...resolved.deployment, mode: options.mode } }
      : {}),
    ...(options.userAuto && governance
      ? {
          governance: {
            ...governance,
            manifest: {
              ...governance.manifest,
              policy: {
                ...governance.manifest.policy,
                userAuto: options.userAuto,
              },
            },
          },
        }
      : {}),
  };
  const session = await GovernanceSession.open({
    lock: lock as Parameters<typeof GovernanceSession.open>[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd: workspace,
    piVersion: "1.0.2",
    interactive: false,
    fetch:
      options.fetch ??
      ((() => {
        throw new Error("no network in unit tests");
      }) as unknown as ManagedFetch),
    resolveTemplate: (_key, template) => template,
    homeDir: join(root, "home"),
    user: "alice",
    ...(options.metrics ? { metrics: options.metrics } : {}),
    // A required sink that stays down is reported after this, not after 5 s.
    auditCloseDeadlineMs: 300,
  });
  sessions.push(session);
  const auditFile = join(root, "state", "logs", "audit.jsonl");
  const events = () =>
    readFileSync(auditFile, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
  return { session, workspace, root, events };
}

function context(): ExtensionToolContext {
  return {
    hasUI: false,
    model: { provider: "unit", id: "allowed", input: ["text"] },
    sessionManager: SessionManager.inMemory(tmpdir()),
    ui: { setStatus: () => {}, notify: () => {} },
  } as unknown as ExtensionToolContext;
}

/** The factory of an inline extension, in either of its public shapes. */
const factoryOf = (extension: InlineExtension): ExtensionFactory =>
  typeof extension === "function" ? extension : extension.factory;

/** What an inline extension registers, through the public API shape. */
function handlers(
  gov: GovernanceSession,
  commands = new Map<
    string,
    { handler: (args: string, ctx: unknown) => Promise<void> }
  >(),
) {
  const registered = new Map<
    string,
    (event: unknown, ctx: unknown) => unknown
  >();
  factoryOf(governanceHooks(gov))({
    on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) =>
      registered.set(event, handler),
    registerCommand: (
      name: string,
      options: { handler: (args: string, ctx: unknown) => Promise<void> },
    ) => commands.set(name, options),
  } as never);
  return registered;
}

const FILE_AUDIT = [
  "audit:",
  "  enabled: true",
  "  sinks:",
  "    - { id: local, type: file, required: false }",
];
const PROVIDER = [
  "capabilities:",
  "  workflow:",
  "    enabled: true",
  "    provider:",
  "      id: company/flow",
  "      version: 1.0.0",
  "      implements: [piship.capability/workflow/v1]",
  "      path: ./providers/flow",
];
const MCP = [
  "mcp:",
  "  mode: allowlist",
  "  servers:",
  "    docs: { transport: stdio, module: ./mcp/docs.mjs }",
  "    blocked: { transport: stdio, module: ./mcp/blocked.mjs }",
];

describe("governed session audit events (real flows)", () => {
  it("emits every audit event name, metadata only", async () => {
    // A personal session: resources, a trusted provider, MCP, tools, models.
    const full = await open([
      "policy:",
      "  id: unit",
      "  version: 1",
      "  default: deny",
      "  defaults:",
      rule("read", "filesystem.read", "workspace/**"),
      rule("read-tool", "tool.execute", "read"),
      rule("ask-user", "extension.load", "builtin:piship-ask-user"),
      rule("provider", "provider.load", "company/flow"),
      rule("provider-extension", "extension.load", "company:./providers/flow"),
      rule("docs", "mcp.server.start", "docs"),
      rule("docs-search", "mcp.tool.call", "docs:search"),
      rule("model", "model.select", "unit/allowed"),
      "resources:",
      "  extensions:",
      "    builtin: [piship-ask-user, piship-workflow]",
      ...PROVIDER,
      ...MCP,
      ...FILE_AUDIT,
    ]);
    const { session, workspace } = full;
    const hooks = handlers(session);
    const toolCall = hooks.get("tool_call") as (
      event: unknown,
      ctx: unknown,
    ) => Promise<unknown>;
    expect(
      await toolCall({ toolName: "read", input: {} }, context()),
    ).toBeUndefined();
    expect(
      await toolCall(
        { toolName: "bash", input: { command: "echo command-canary" } },
        context(),
      ),
    ).toMatchObject({ block: true });
    const read = governedTools(session, workspace).find(
      (tool) => tool.name === "read",
    ) as ToolDefinition;
    await read.execute(
      "call",
      { path: "notes.txt" } as never,
      undefined,
      undefined,
      context(),
    );
    await hooks.get("before_provider_request")?.(
      { payload: { messages: [{ role: "user", content: "prompt-canary" }] } },
      context(),
    );
    const policy = await modelPolicy(session, "unit/allowed");
    if (!policy.denied) throw new Error("the model policy reports no denial");
    policy.denied("unit", "other");
    await expect(modelPolicy(session, "unit/denied")).rejects.toMatchObject({
      code: "MODEL_DENIED",
    });
    const search = session.mcp
      ?.tools()
      .find((tool) => tool.name === "mcp__docs__search");
    expect(search).toBeDefined();
    const result = await search?.call({ query: "query-canary" });
    expect(JSON.stringify(result)).toContain("query-canary");
    await session.close();

    // A managed session: a user rule that tries to widen the policy, a
    // provider the policy refuses, and the user's auto mode switched on and
    // off around an `ask` it approves.
    const managed = await open(
      [
        "policy:",
        "  id: unit",
        "  version: 1",
        "  default: deny",
        "  defaults:",
        rule("read-tool", "tool.execute", "read", "ask"),
        ...PROVIDER,
        ...FILE_AUDIT,
      ],
      {
        mode: "managed",
        userAuto: "allowed",
        userRules: [
          { id: "me.shell", action: "shell.execute", effect: "allow" },
        ],
      },
    );
    const commands = new Map<
      string,
      { handler: (args: string, ctx: unknown) => Promise<void> }
    >();
    const managedHooks = handlers(managed.session, commands);
    const auto = commands.get("auto");
    if (!auto) throw new Error("/auto is not registered");
    await auto.handler("on", context());
    expect(
      await (
        managedHooks.get("tool_call") as (
          event: unknown,
          ctx: unknown,
        ) => Promise<unknown>
      )({ toolName: "read", input: {} }, context()),
    ).toBeUndefined();
    await auto.handler("off", context());
    await managed.session.close();
    expect(
      managed.events().find((event) => event.event === "policy.auto_approved"),
    ).toMatchObject({
      user: "alice",
      resource: "read",
      decision: "approved",
      rule: "read-tool",
      detail: { action: "tool.execute", approval: "auto" },
    });

    const events = [...full.events(), ...managed.events()];
    const emitted = new Set(events.map((event) => event.event));
    expect(
      AUDIT_EVENT_TYPES.filter(
        (name) =>
          !emitted.has(name) &&
          !OUTSIDE_A_SESSION.includes(name) &&
          !NOT_YET_EMITTED.includes(name),
      ),
    ).toEqual([]);
    expect(NOT_YET_EMITTED.filter((name) => emitted.has(name))).toEqual([]);
    // Together with the branded commands, the flows cover all 27 v0.8 names.
    expect(
      new Set([...emitted, ...OUTSIDE_A_SESSION, ...NOT_YET_EMITTED]),
    ).toEqual(new Set(AUDIT_EVENT_TYPES));
    expect(events.every((event) => typeof event.id === "string")).toBe(true);
    expect(events.find((event) => event.event === "mcp.call")).toMatchObject({
      user: "alice",
      resource: "docs:search",
      decision: "allowed",
    });
    // Prompt, source, command, and MCP argument or result bodies stay out.
    const text = events.map((event) => JSON.stringify(event)).join("\n");
    for (const canary of [
      "prompt-canary",
      "source-canary",
      "command-canary",
      "query-canary",
    ])
      expect(text).not.toContain(canary);
    expect(text).not.toContain('"content"');
  }, 30_000);
});

describe("GovernanceSession.close with a required sink", () => {
  const REQUIRED = [
    "policy:",
    "  id: unit",
    "  version: 1",
    "  default: deny",
    "audit:",
    "  enabled: true",
    "  sinks:",
    "    - { id: company, type: http, url: https://audit.example/ingest, required: true }",
  ];
  /** A collector that answers the probe and then `status` for every batch. */
  function collector() {
    const state = { status: 200, batches: [] as AuditEvent[][] };
    const fetch = (async (_url: string, init?: RequestInit) => {
      const batch = JSON.parse(String(init?.body)).events as AuditEvent[];
      if (!batch.length || state.status < 300) state.batches.push(batch);
      return new Response(null, {
        status: batch.length ? state.status : 200,
      });
    }) as unknown as ManagedFetch;
    return { state, fetch };
  }

  it("returns the final audit status when every event was delivered", async () => {
    const { state, fetch } = collector();
    const { session } = await open(REQUIRED, { fetch });
    const status = await session.close();
    expect(status).toMatchObject({
      state: "ok",
      sinks: [{ id: "company", pending: 0, dropped: 0 }],
    });
    expect(state.batches.flat().map((event) => event.event)).toEqual([
      "session.start",
      "policy.loaded",
      "session.end",
    ]);
    // Closing again reports the same status and does not fail.
    await expect(session.close()).resolves.toMatchObject({ state: "ok" });
  });

  it("fails with AUDIT_UNAVAILABLE after cleanup when events stay undelivered", async () => {
    const { state, fetch } = collector();
    const root = mkdtempSync(join(tmpdir(), "piship-audit-metrics-"));
    roots.push(root);
    const metrics = new LocalMetrics(root);
    const { session } = await open(REQUIRED, { fetch, metrics });
    // Fault injection: the collector fails from now on.
    state.status = 503;
    let disposed = false;
    const dispose = session.sandbox.dispose.bind(session.sandbox);
    session.sandbox.dispose = async () => {
      disposed = true;
      await dispose();
    };
    const error = await session.close().then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({
      code: "AUDIT_UNAVAILABLE",
      message: expect.stringContaining(
        "The session ended: 3 audit event(s) were not delivered to required audit sink company (3 pending, 0 dropped; last error: collector answered HTTP 503)",
      ),
    });
    expect(disposed).toBe(true);
    // Metrics were still saved.
    expect(readFileSync(join(root, "logs", "metrics.json"), "utf8")).toContain(
      "piship-metrics/v1",
    );
    expect(session.audit.status().sinks[0]?.pending).toBe(3);
  }, 15_000);

  it("still flushes audit when a cleanup step fails, and reports the loss first", async () => {
    const { state, fetch } = collector();
    const { session } = await open(REQUIRED, { fetch });
    session.sandbox.dispose = async () => {
      throw new Error("dispose failed");
    };
    await expect(session.close()).rejects.toThrow("dispose failed");
    expect(state.batches.flat().map((event) => event.event)).toContain(
      "session.end",
    );

    // Every delivery fails: the audit loss outranks the cleanup error.
    const down = collector();
    down.state.status = 500;
    const second = await open(REQUIRED, { fetch: down.fetch });
    second.session.sandbox.dispose = async () => {
      throw new Error("dispose failed");
    };
    await expect(second.session.close()).rejects.toMatchObject({
      code: "AUDIT_UNAVAILABLE",
    });
  }, 15_000);

  it("records a required-sink loss when a failing launch closes audit", async () => {
    const { state, fetch } = collector();
    const root = mkdtempSync(join(tmpdir(), "piship-audit-metrics-"));
    roots.push(root);
    const metrics = new LocalMetrics(root);
    state.status = 503;
    // A required MCP server that cannot start fails the launch after
    // session.start and policy.loaded were emitted.
    await expect(
      open(
        [
          ...REQUIRED,
          "mcp:",
          "  mode: allowlist",
          "  servers:",
          "    docs: { transport: stdio, module: ./mcp/docs.mjs, required: true }",
        ],
        { fetch, metrics },
      ),
    ).rejects.toMatchObject({ code: "MCP_DENIED" });
    expect(metrics.snapshot().startupFailures).toEqual({
      MCP_DENIED: 1,
      AUDIT_UNAVAILABLE: 1,
    });
  }, 15_000);

  describe("with local metrics that cannot be written", () => {
    /** Fault injection: a full disk under every metrics record and save. */
    class FullDiskMetrics extends LocalMetrics {
      saves = 0;
      #fail(): never {
        throw Object.assign(
          new Error("ENOSPC: no space left on device, write"),
          { code: "ENOSPC" },
        );
      }
      override save(): void {
        this.saves += 1;
        this.#fail();
      }
      override recordSandbox(): void {
        this.#fail();
      }
      override recordStartupLatency(): void {
        this.#fail();
      }
      override recordStartupFailure(): void {
        this.#fail();
      }
    }
    const REQUIRED_MCP = [
      ...REQUIRED,
      "mcp:",
      "  mode: allowlist",
      "  servers:",
      "    docs: { transport: stdio, module: ./mcp/docs.mjs, required: true }",
    ];

    it("starts and closes a session that is otherwise valid", async () => {
      const { state, fetch } = collector();
      const root = mkdtempSync(join(tmpdir(), "piship-audit-metrics-"));
      roots.push(root);
      const metrics = new FullDiskMetrics(root);
      const { session } = await open(REQUIRED, { fetch, metrics });
      await expect(session.close()).resolves.toMatchObject({ state: "ok" });
      expect(metrics.saves).toBe(2);
      // Required audit took every event regardless.
      expect(state.batches.flat().map((event) => event.event)).toEqual([
        "session.start",
        "policy.loaded",
        "session.end",
      ]);
    });

    it("starts and closes when the metrics file cannot be replaced on disk", async () => {
      const { fetch } = collector();
      const root = mkdtempSync(join(tmpdir(), "piship-audit-metrics-"));
      roots.push(root);
      // A directory where logs/metrics.json belongs: every save fails.
      mkdirSync(join(root, "logs", "metrics.json", "occupied"), {
        recursive: true,
      });
      const metrics = new LocalMetrics(root);
      expect(() => metrics.save()).toThrow();
      const { session } = await open(REQUIRED, { fetch, metrics });
      await expect(session.close()).resolves.toMatchObject({ state: "ok" });
    });

    it("keeps the original startup error and code", async () => {
      const { fetch } = collector();
      const root = mkdtempSync(join(tmpdir(), "piship-audit-metrics-"));
      roots.push(root);
      const metrics = new FullDiskMetrics(root);
      await expect(
        open(REQUIRED_MCP, { fetch, metrics }),
      ).rejects.toMatchObject({ code: "MCP_DENIED" });
      expect(metrics.saves).toBe(1);
    }, 15_000);

    it("still fails closed on a required audit loss", async () => {
      const { state, fetch } = collector();
      const root = mkdtempSync(join(tmpdir(), "piship-audit-metrics-"));
      roots.push(root);
      const metrics = new FullDiskMetrics(root);
      const { session } = await open(REQUIRED, { fetch, metrics });
      state.status = 503;
      await expect(session.close()).rejects.toMatchObject({
        code: "AUDIT_UNAVAILABLE",
      });
      // A failing launch whose required sink is down keeps its own error.
      const failing = new FullDiskMetrics(root);
      await expect(
        open(REQUIRED_MCP, { fetch, metrics: failing }),
      ).rejects.toMatchObject({ code: "MCP_DENIED" });
      expect(failing.saves).toBe(1);
    }, 15_000);
  });
});
