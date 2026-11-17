import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildEngine,
  filesystemPolicyDigest,
  readUserRules,
} from "./engine.js";

let state: string;
beforeEach(() => {
  state = mkdtempSync(join(tmpdir(), "piship-user-rules-"));
  mkdirSync(join(state, "config"));
});
afterEach(() => {
  rmSync(state, { recursive: true, force: true });
});

describe("the user policy file", () => {
  it("names itself and what to do when a rule is invalid", () => {
    const path = join(state, "config", "policy.json");
    writeFileSync(
      path,
      JSON.stringify({
        rules: [{ id: "x", action: "*", resource: "**", effect: "maybe" }],
      }),
    );
    let error: unknown;
    try {
      readUserRules(state);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PiShipError);
    expect((error as PiShipError).code).toBe("CONFIG_INVALID");
    expect((error as PiShipError).message).toBe(
      `Invalid policy rules in ${path} at rules[0].effect: effect must be allow, ask, or deny`,
    );
    expect((error as PiShipError).userAction).toContain(
      `Fix or remove the rule in ${path}`,
    );
  });

  it("reads valid rules", () => {
    writeFileSync(
      join(state, "config", "policy.json"),
      JSON.stringify([
        { id: "no-push", action: "*", resource: "**", effect: "deny" },
      ]),
    );
    expect(readUserRules(state).map((rule) => rule.id)).toEqual(["no-push"]);
  });
});

describe("filesystemPolicyDigest", () => {
  const options = (mode = "personal") =>
    ({
      stateDir: state,
      distributionDir: state,
      lock: {
        deployment: { mode },
        governance: { manifest: { policy: { enforced: [], defaults: [] } } },
      },
    }) as never;
  const write = (rules: unknown[]) =>
    writeFileSync(join(state, "config", "policy.json"), JSON.stringify(rules));

  it("changes with a filesystem rule, not with an unrelated one", async () => {
    const none = await filesystemPolicyDigest(options(), []);
    write([
      {
        id: "p",
        action: "shell.execute",
        resource: "git push",
        effect: "deny",
      },
    ]);
    expect(await filesystemPolicyDigest(options(), [])).toBe(none);
    write([
      {
        id: "r",
        action: "filesystem.read",
        resource: "**/.env",
        effect: "deny",
      },
    ]);
    const denied = await filesystemPolicyDigest(options(), []);
    expect(denied).not.toBe(none);
    expect(await filesystemPolicyDigest(options(), [])).toBe(denied);
    expect(await filesystemPolicyDigest(options("managed"), [])).not.toBe(
      denied,
    );
  });
});

describe("rule warnings from the adapter and the user file", () => {
  it("reach the engine's diagnostics, naming the file and the rule", async () => {
    const userFile = join(state, "config", "policy.json");
    writeFileSync(
      userFile,
      JSON.stringify([
        {
          id: "me.docs",
          action: "mcp.tool.call",
          resource: "mcp__docs__search",
          effect: "deny",
        },
      ]),
    );
    mkdirSync(join(state, "resources"));
    writeFileSync(
      join(state, "resources", "team.mjs"),
      `export default [{ id: "team.env", action: "filesystem.read", resource: ".env", effect: "deny" }];`,
    );
    const options = {
      stateDir: state,
      distributionDir: state,
      lock: {
        deployment: { mode: "personal" },
        governance: {
          manifest: {
            policy: {
              id: "p",
              version: "1",
              default: "allow",
              enforced: [],
              defaults: [],
              adapter: "./team.mjs",
            },
          },
        },
      },
    } as never;
    const engine = await buildEngine(
      options,
      { root: state } as never,
      [],
      { level: "none", planes: [] } as never,
      state,
      state,
    );
    expect(
      engine.diagnostics.map((item) => [item.source, item.message]),
    ).toEqual([
      [
        "the policy adapter ./team.mjs",
        expect.stringContaining(
          "team.env (deny filesystem.read) never matches .env",
        ),
      ],
      [
        userFile,
        expect.stringContaining(
          "me.docs (deny mcp.tool.call) names the model-facing tool",
        ),
      ],
    ]);
  });
});
