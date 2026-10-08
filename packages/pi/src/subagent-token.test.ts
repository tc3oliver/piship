// The session's subagent token is for its children only: no command a model
// runs, contained or not, can read it.
import { isCredentialName, stripCredentials } from "@piship/sandbox";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GovernanceSession } from "./governance-session.js";
import { governedBashOperations } from "./governed-tools.js";
import { SUBAGENT_TOKEN_ENV } from "./launch/subagent-owner.js";

describe("the subagent token's name", () => {
  it("is one the credential filters know, so a sandboxed command never gets it", () => {
    expect(isCredentialName(SUBAGENT_TOKEN_ENV)).toBe(true);
    expect(
      stripCredentials({ PATH: "/bin", [SUBAGENT_TOKEN_ENV]: "secret" }),
    ).toEqual({ PATH: "/bin" });
  });
});

describe.skipIf(process.platform === "win32")(
  "a command run without the sandbox containing it",
  () => {
    const saved = process.env[SUBAGENT_TOKEN_ENV];
    beforeEach(() => {
      process.env[SUBAGENT_TOKEN_ENV] = "a".repeat(64);
    });
    afterEach(() => {
      if (saved === undefined) delete process.env[SUBAGENT_TOKEN_ENV];
      else process.env[SUBAGENT_TOKEN_ENV] = saved;
    });
    const session = {
      workflowMode: null,
      currentChannel: () => undefined,
      decide: async () => ({ outcome: "allow" }),
      options: { lock: { deployment: { mode: "personal" } } },
      sandbox: { report: { level: "not-required" } },
    } as unknown as GovernanceSession;
    const ask = async (
      source: "bash" | "user-bash",
      env?: NodeJS.ProcessEnv,
    ) => {
      let output = "";
      await governedBashOperations(session, source).exec(
        `printf '%s' "\${${SUBAGENT_TOKEN_ENV}:-absent}:\${HOME:+home}"`,
        "/",
        {
          onData: (data) => {
            output += data.toString();
          },
          ...(env ? { env } : {}),
        },
      );
      return output;
    };

    it("does not see the token, whether Pi passes an environment or not", async () => {
      expect(await ask("bash")).toBe("absent:home");
      expect(await ask("bash", { ...process.env })).toBe("absent:home");
      expect(await ask("user-bash", { ...process.env })).toBe("absent:home");
    });
  },
);
