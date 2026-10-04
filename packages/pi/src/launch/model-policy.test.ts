// model.select and model.dispatch decided by the distribution policy, as
// launch resolves them for the model runtime.
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  ApprovalChannel,
  AuditEvent,
  ManagedFetch,
} from "@piship/contracts";
import { resolveLock } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import type { VirtualModelRule } from "../governance.js";
import { GovernanceSession } from "../governance-session.js";
import { modelPolicy } from "./governance.js";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0))
    await session.close().catch(() => undefined);
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const rule = (id: string, action: string, resource: string, effect: string) =>
  `    - { id: ${id}, action: ${action}, resource: "${resource}", effect: ${effect} }`;

async function open(
  rules: string[],
  enforced: string[] = [],
  extra: {
    /** The user's own `config/policy.json` rules. */
    readonly userRules?: readonly unknown[];
    readonly startupApproval?: ApprovalChannel;
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "piship-model-policy-"));
  roots.push(root);
  if (extra.userRules) {
    mkdirSync(join(root, "state", "config"), { recursive: true });
    writeFileSync(
      join(root, "state", "config", "policy.json"),
      JSON.stringify(extra.userRules),
    );
  }
  const distribution = join(root, "distribution");
  mkdirSync(distribution, { recursive: true });
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "1.0.2" }',
      "deployment: { mode: personal }",
      "audit:",
      "  enabled: true",
      "  sinks:",
      "    - { id: local, type: file, required: false }",
      "policy:",
      "  id: unit",
      "  version: 1",
      "  default: deny",
      ...(enforced.length ? ["  enforced:", ...enforced] : []),
      "  defaults:",
      ...rules,
      "",
    ].join("\n"),
  );
  const session = await GovernanceSession.open({
    lock: resolveLock(manifest) as Parameters<
      typeof GovernanceSession.open
    >[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd: root,
    piVersion: "1.0.2",
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: join(root, "home"),
    user: "alice",
    ...(extra.startupApproval
      ? { startupApproval: extra.startupApproval }
      : {}),
  });
  sessions.push(session);
  const events = () =>
    readFileSync(join(root, "state", "logs", "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
  return { session, events };
}

const AUTO: VirtualModelRule = {
  provider: "acme",
  id: "auto",
  routes: [
    { provider: "acme", id: "coder" },
    { provider: "acme", id: "general" },
  ],
  router: "./extensions/router.ts",
};

describe("model.select and model.dispatch policy", () => {
  it("decides a physical model by model.select when no model.dispatch rule matches it", async () => {
    const { session } = await open([
      rule("no-general", "model.select", "acme/general", "deny"),
      rule("pick", "model.select", "acme/*", "allow"),
      rule("route-review", "model.dispatch", "acme/review", "allow"),
    ]);
    const policy = await modelPolicy(session, "acme/coder");
    expect(policy.dispatches?.("acme", "coder")).toBe(true);
    // A v0.8 model.use (now model.select) deny holds for dispatch too.
    expect(policy.dispatches?.("acme", "general")).toBe(false);
    // An explicit model.dispatch rule decides, whatever select says.
    expect(policy.selects("acme", "review")).toBe(true);
    expect(policy.dispatches?.("acme", "review")).toBe(true);
  });

  it("lets a model.dispatch rule allow a route the session may not select", async () => {
    const { session } = await open([
      rule("pick-auto", "model.select", "acme/auto", "allow"),
      rule("route", "model.dispatch", "acme/coder", "allow"),
    ]);
    const policy = await modelPolicy(session, "acme/auto", [AUTO]);
    expect(policy.selects("acme", "coder")).toBe(false);
    expect(policy.dispatches?.("acme", "coder")).toBe(true);
    // No rule names acme/general: model.select, which the default denies.
    expect(policy.dispatches?.("acme", "general")).toBe(false);
  });

  it("keeps a model.select deny when a wildcard allow decides model.dispatch (deny wins)", async () => {
    for (const wildcard of ["'*'", "model.*"]) {
      const { session } = await open(
        [rule("everything", wildcard, "acme/*", "allow")],
        [rule("no-general", "model.select", "acme/general", "deny")],
      );
      const policy = await modelPolicy(session, "acme/auto", [AUTO]);
      expect(policy.selects("acme", "general"), wildcard).toBe(false);
      // The wildcard names model.select too, so it is no route around it.
      expect(policy.dispatches?.("acme", "general"), wildcard).toBe(false);
      expect(policy.dispatches?.("acme", "coder"), wildcard).toBe(true);
      await session.close();
    }
    // A rule that names model.dispatch itself still routes (router-only),
    // from a layer as authoritative as the deny.
    const { session } = await open(
      [
        rule("route", "model.dispatch", "acme/general", "allow"),
        rule("everything", "model.*", "acme/*", "allow"),
      ],
      [
        rule("no-general", "model.select", "acme/general", "deny"),
        rule("route-enforced", "model.dispatch", "acme/general", "allow"),
      ],
    );
    const policy = await modelPolicy(session, "acme/auto", [AUTO]);
    expect(policy.selects("acme", "general")).toBe(false);
    expect(policy.dispatches?.("acme", "general")).toBe(true);
  });

  it("keeps an enforced model.select deny over a user's model.dispatch allow", async () => {
    const user = {
      userRules: [
        {
          id: "mine",
          action: "model.dispatch",
          resource: "acme/general",
          effect: "allow",
        },
      ],
    };
    const enforced = await open(
      [rule("pick", "model.select", "acme/*", "allow")],
      [rule("no-general", "model.select", "acme/general", "deny")],
      user,
    );
    const policy = await modelPolicy(enforced.session, "acme/auto", [AUTO]);
    expect(policy.dispatches?.("acme", "general")).toBe(false);
    expect(policy.dispatches?.("acme", "coder")).toBe(true);
    await enforced.session.close();
    // Only an enforced model.dispatch allow routes past an enforced deny
    // (the default, deny here, still has to allow the dispatch).
    const routed = await open(
      [
        rule("pick", "model.select", "acme/*", "allow"),
        rule("route-default", "model.dispatch", "acme/general", "allow"),
      ],
      [
        rule("no-general", "model.select", "acme/general", "deny"),
        rule("route", "model.dispatch", "acme/general", "allow"),
      ],
    );
    expect(
      (await modelPolicy(routed.session, "acme/auto", [AUTO])).dispatches?.(
        "acme",
        "general",
      ),
    ).toBe(true);
    await routed.session.close();
    // A personal owner's own allow still routes past a distribution default.
    const defaults = await open(
      [
        rule("pick-auto", "model.select", "acme/auto", "allow"),
        rule("no-general", "model.select", "acme/general", "deny"),
      ],
      [],
      user,
    );
    expect(
      (await modelPolicy(defaults.session, "acme/auto", [AUTO])).dispatches?.(
        "acme",
        "general",
      ),
    ).toBe(true);
  });

  it("asks a wildcard ask once per route at start", async () => {
    const asked: string[] = [];
    const { session } = await open(
      [
        rule("pick-auto", "model.select", "acme/auto", "allow"),
        rule("route-ask", "model.*", "acme/*", "ask"),
      ],
      [],
      {
        startupApproval: async (decision) => {
          asked.push(`${decision.action} ${decision.resource}`);
          return "approved";
        },
      },
    );
    const policy = await modelPolicy(session, "acme/auto", [AUTO]);
    expect(asked).toEqual([
      "model.dispatch acme/coder",
      "model.dispatch acme/general",
    ]);
    expect(policy.dispatches?.("acme", "coder")).toBe(true);
    // Approved to route, not to be selected.
    expect(policy.selects("acme", "coder")).toBe(false);
  });

  it("resolves ask for each route at start, and refuses a virtual model with no route left", async () => {
    const asked = await open([
      rule("pick-auto", "model.select", "acme/auto", "allow"),
      rule("route-ask", "model.dispatch", "acme/*", "ask"),
    ]);
    // Headless: an ask resolves to deny, so no route remains.
    await expect(
      modelPolicy(asked.session, "acme/auto", [AUTO]),
    ).rejects.toMatchObject({
      code: "MODEL_DENIED",
      message: expect.stringContaining("No route of virtual model acme/auto"),
    });
    await asked.session.close();
    expect(
      asked
        .events()
        .filter((event) => event.event === "model.denied")
        .map((event) => [event.resource, event.detail?.action]),
    ).toEqual([
      ["acme/coder", "model.dispatch"],
      ["acme/general", "model.dispatch"],
    ]);
    const physical = await open([
      rule("pick", "model.select", "acme/coder", "allow"),
      rule("never", "model.dispatch", "acme/coder", "deny"),
    ]);
    await expect(
      modelPolicy(physical.session, "acme/coder"),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
  });

  it("records a routed request and a refusal with the selected model, the target, and the router", async () => {
    const { session, events } = await open([
      rule("pick", "model.select", "acme/*", "allow"),
    ]);
    const policy = await modelPolicy(session, "acme/auto", [AUTO]);
    policy.dispatched?.({
      selected: "acme/auto",
      dispatched: "acme/coder",
      router: "./extensions/router.ts",
      type: "chat",
    });
    policy.denied?.("model.dispatch", "acme", "review", {
      selected: "acme/auto",
      router: "./extensions/router.ts",
      reason: "not a declared route",
    });
    await session.close();
    expect(
      events().find((event) => event.event === "model.dispatch"),
    ).toMatchObject({
      resource: "acme/coder",
      decision: "allowed",
      enforcement: "control-plane",
      detail: {
        selected: "acme/auto",
        dispatched: "acme/coder",
        router: "./extensions/router.ts",
        type: "chat",
      },
    });
    expect(
      events().find(
        (event) =>
          event.event === "model.denied" && event.resource === "acme/review",
      ),
    ).toMatchObject({
      decision: "denied",
      detail: {
        action: "model.dispatch",
        selected: "acme/auto",
        router: "./extensions/router.ts",
        reason: "not a declared route",
      },
    });
  });
});
