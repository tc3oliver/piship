// A scripted 30-minute coding session decided by the real policy engine (no
// model, no sandbox), counting how often a managed distribution would stop to
// ask. Routine work must not prompt: a regression that turns it into asks
// fails here, not in a user's terminal. Prompts are counted per call, before
// any session grant or "always allow" answer could reduce them.
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

const base = realpathSync(mkdtempSync(join(tmpdir(), "piship-prompt-budget-")));
afterAll(() => rmSync(base, { recursive: true, force: true }));

const context: PolicyContext = {
  workspaceRoot: join(base, "work"),
  homeDir: join(base, "home"),
  tmpDir: join(base, "tmp"),
  containment: { ...NO_CONTAINMENT, shell: true },
};
const inWorkspace = (path: string) => join(context.workspaceRoot, path);

type Step = readonly [action: string, resource: string];
const shell = (command: string): Step => ["shell.execute", command];

/** One tool call: the tool itself, then what it does. */
const session: Step[] = [
  ...Array.from({ length: 12 }, (_, i): Step[] => [
    ["tool.execute", "read"],
    ["filesystem.read", inWorkspace(`src/file${i}.ts`)],
  ]).flat(),
  ...Array.from({ length: 8 }, (_, i): Step[] => [
    ["tool.execute", i < 6 ? "edit" : "write"],
    ["filesystem.write", inWorkspace(`src/file${i}.ts`)],
  ]).flat(),
  ...["npm test", "npm test -- --run", "npm run build", "npm run lint"].flatMap(
    (command): Step[] => [["tool.execute", "bash"], shell(command)],
  ),
  ...[
    "git status",
    "git diff",
    "git log --oneline -20",
    "git add -A",
    'git commit -m "change"',
    "git push origin feature",
  ].flatMap((command): Step[] => [["tool.execute", "bash"], shell(command)]),
  ...Array.from({ length: 5 }, (_, i): Step[] => [
    ["tool.execute", "bash"],
    shell(`rg "needle${i}" src`),
  ]).flat(),
  ["filesystem.read", join(context.homeDir, "notes", "a.md")],
  ["filesystem.read", join(base, "other-repo", "README.md")],
  ["filesystem.write", join(context.tmpDir, "scratch.txt")],
  ...[
    "curl https://example.org",
    "docker compose up -d",
    "rm -rf build",
  ].flatMap((command): Step[] => [["tool.execute", "bash"], shell(command)]),
];

const asks = (policy: PolicyConfig) => {
  const engine = new PolicyEngine({ policy, context });
  return session
    .filter(
      ([action, resource]) =>
        engine.evaluate({ action: action as never, resource }).effect === "ask",
    )
    .map(([action, resource]) => `${action} ${resource}`);
};

const managed = (packs: unknown) =>
  parsePolicy(
    { packs },
    "managed",
    { id: "acme" },
    {
      acknowledgeUnenforced: true,
    },
  );

describe("prompt budget of a scripted coding session", () => {
  it("asks only for the push, the network, containers, rm and outside reads", () => {
    expect(asks(managed([{ pack: "piship.routine", version: 1 }]))).toEqual([
      "shell.execute git push origin feature",
      `filesystem.read ${join(context.homeDir, "notes", "a.md")}`,
      `filesystem.read ${join(base, "other-repo", "README.md")}`,
      "shell.execute curl https://example.org",
      "shell.execute docker compose up -d",
      "shell.execute rm -rf build",
    ]);
  });

  it("asks far more without the pack", () => {
    expect(asks(managed(undefined)).length).toBeGreaterThan(40);
  });
});
