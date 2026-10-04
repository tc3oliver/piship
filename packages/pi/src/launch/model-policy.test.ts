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
import type { AuditEvent, ManagedFetch } from "@piship/contracts";
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

async function open(rules: string[]) {
  const root = mkdtempSync(join(tmpdir(), "piship-model-policy-"));
  roots.push(root);
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
