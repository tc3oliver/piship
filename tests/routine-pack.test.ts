import { createHash } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  NO_CONTAINMENT,
  type PolicyContext,
  PolicyEngine,
} from "@piship/policy";
import { type PolicyConfig, parsePolicy } from "@piship/schema";
import { afterAll, describe, expect, it } from "vitest";
import { ROUTINE_CASES } from "./fixtures/routine-cases.js";

const base = realpathSync(mkdtempSync(join(tmpdir(), "piship-routine-")));
afterAll(() => rmSync(base, { recursive: true, force: true }));

const context = (shell: boolean): PolicyContext => ({
  workspaceRoot: join(base, "work"),
  homeDir: join(base, "home"),
  tmpDir: join(base, "tmp"),
  containment: { ...NO_CONTAINMENT, shell },
});

function managed(extra: Record<string, unknown> = {}): PolicyConfig {
  return parsePolicy(
    { packs: [{ pack: "piship.routine", version: 1 }], ...extra },
    "managed",
    { id: "acme" },
    { acknowledgeUnenforced: true },
  );
}

const engine = (policy: PolicyConfig, shell = true) =>
  new PolicyEngine({ policy, context: context(shell) });

describe("piship.routine@1", () => {
  it("is frozen", () => {
    const rules = managed().defaults;
    // Changing the pack needs routine@2, not an edit of this digest.
    expect(rules).toHaveLength(RULE_COUNT);
    expect(
      createHash("sha256").update(JSON.stringify(rules)).digest("hex"),
    ).toBe(DIGEST);
  });

  for (const c of ROUTINE_CASES)
    it(`decides ${JSON.stringify(c.command)} as ${c.routine}`, () => {
      expect(
        engine(managed()).evaluate({
          action: "shell.execute",
          resource: c.command,
        }).effect,
      ).toBe(c.routine);
    });

  it("falls back to policy.default for shell commands without containment", () => {
    const e = engine(managed(), false);
    const d = e.evaluate({ action: "shell.execute", resource: "npm test" });
    expect(d.effect).toBe("ask");
    expect(
      e
        .explain({ action: "shell.execute", resource: "npm test" })
        .inactive.map((m) => m.ruleId),
    ).toContain("piship.routine.node.npm-test");
  });

  it("keeps path and tool rules without containment", () => {
    const e = engine(managed(), false);
    expect(
      e.evaluate({ action: "tool.execute", resource: "bash" }).effect,
    ).toBe("allow");
    expect(
      e.evaluate({
        action: "filesystem.write",
        resource: join(base, "work", "a.ts"),
      }).effect,
    ).toBe("allow");
  });

  it("asks for secrets and execution config, allows examples", () => {
    const e = engine(managed());
    const at = (action: "filesystem.read" | "filesystem.write", path: string) =>
      e.evaluate({ action, resource: join(base, "work", path) }).effect;
    expect(at("filesystem.read", ".env")).toBe("ask");
    expect(at("filesystem.read", "app/.env.local")).toBe("ask");
    expect(at("filesystem.read", "app/.env.example")).toBe("allow");
    expect(at("filesystem.write", ".mcp.json")).toBe("ask");
    expect(at("filesystem.write", ".claude/settings.json")).toBe("ask");
    expect(at("filesystem.write", "src/a.ts")).toBe("allow");
    expect(at("filesystem.read", "../outside.txt")).toBe("ask");
  });

  it("lets the author's rules decide first and enforced rules win", () => {
    const authored = managed({
      defaults: [
        {
          id: "own.ask",
          action: "shell.execute",
          resource: "npm test**",
          effect: "ask",
        },
      ],
    });
    expect(
      engine(authored).evaluate({
        action: "shell.execute",
        resource: "npm test",
      }).effect,
    ).toBe("ask");
    const enforced = managed({
      enforced: [
        {
          id: "own.deny",
          action: "shell.execute",
          resource: "git log**",
          effect: "deny",
        },
      ],
    });
    expect(
      engine(enforced).evaluate({
        action: "shell.execute",
        resource: "git log",
      }).effect,
    ).toBe("deny");
  });

  it("removes excluded rules by id or dotted prefix", () => {
    const policy = managed({
      packs: [
        {
          pack: "piship.routine",
          version: 1,
          exclude: ["git.local", "piship.routine.node.npm-test"],
        },
      ],
    });
    const ids = policy.defaults.map((rule) => rule.id);
    expect(ids.some((id) => id.startsWith("piship.routine.git.local."))).toBe(
      false,
    );
    expect(ids).not.toContain("piship.routine.node.npm-test");
    expect(ids).toContain("piship.routine.node.npm-ci");
  });

  it("rejects what it cannot honour", () => {
    const parse = (value: unknown, flags = { acknowledgeUnenforced: true }) =>
      parsePolicy({ packs: value }, "managed", { id: "acme" }, flags);
    expect(() => parse([{ pack: "piship.other", version: 1 }])).toThrow(
      /built-in pack/,
    );
    expect(() => parse([{ pack: "piship.routine", version: 2 }])).toThrow(
      /version/,
    );
    expect(() =>
      parse([{ pack: "piship.routine", version: 1, exclude: ["nothing"] }]),
    ).toThrow(/matches no rule/);
    expect(() =>
      parse([{ pack: "piship.routine", version: 1 }], {} as never),
    ).toThrow();
    expect(() =>
      parsePolicy(
        {
          packs: [{ pack: "piship.routine", version: 1 }],
          defaults: [
            {
              id: "piship.routine.fs.read-workspace",
              action: "shell.execute",
              effect: "ask",
            },
          ],
        },
        "managed",
        { id: "acme" },
        { acknowledgeUnenforced: true },
      ),
    ).toThrow(/already used/);
  });

  it("does not let a manifest rule set contained", () => {
    expect(() =>
      parsePolicy(
        {
          defaults: [
            {
              id: "x",
              action: "shell.execute",
              resource: "a",
              effect: "allow",
              contained: true,
            },
          ],
        },
        "managed",
        { id: "acme" },
        { acknowledgeUnenforced: true },
      ),
    ).toThrow();
  });
});

const RULE_COUNT = 199;
const DIGEST =
  "dd16c33c15bc7f27143fe497906ba0c784aa9fcf7e9d29b139bc5419fdc869e7";
