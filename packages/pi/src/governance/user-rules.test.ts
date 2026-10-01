import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readUserRules } from "./engine.js";

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
