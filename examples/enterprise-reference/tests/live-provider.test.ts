import { writeFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type Installed,
  installDistribution,
  leaks,
  type Smoke,
} from "./support/distribution.js";
import { type Stack, startStack } from "./support/stack.js";

// Live provider qualification: the reference stack with LiteLLM routed to a
// real upstream provider (compose.live-provider.yaml), and one model request
// through the installed AcmeCode distribution. It runs only with
// PISHIP_LIVE_PROVIDER=1 and the provider's key in LIVE_PROVIDER_API_KEY (the
// Live provider workflow), never in `npm run test:reference` otherwise: it
// needs the Internet and a paid key.
//
// With PISHIP_LIVE_PROVIDER_RESULT set, the outcome is written there as JSON
// for the job summary: gateway model, status, stop reason, reply length, and
// time. Never the reply, the provider, or its model.

const live = process.env.PISHIP_LIVE_PROVIDER === "1";
const MODEL = "acme/coder";

describe.skipIf(!live || process.platform === "win32")(
  "AcmeCode on the reference stack with a live upstream provider",
  () => {
    let stack: Stack;
    let acme: Installed;

    beforeAll(async () => {
      if (!process.env.LIVE_PROVIDER_API_KEY)
        throw new Error("LIVE_PROVIDER_API_KEY is not set");
      stack = await startStack({ overrides: ["compose.live-provider.yaml"] });
      acme = await installDistribution(stack, { name: "live" });
    }, 600_000);

    afterAll(() => {
      acme?.remove();
      stack?.stop();
    }, 120_000);

    it("sends a model request through LiteLLM to the provider", async () => {
      const login = await acme.login("alice");
      expect(login.status, login.stderr).toBe(0);

      const started = performance.now();
      const request = await acme.run(["--model", MODEL, "--smoke-model"]);
      const seconds = Math.round((performance.now() - started) / 100) / 10;
      let modelRequest: Smoke["modelRequest"];
      try {
        modelRequest = (JSON.parse(request.stdout) as Smoke).modelRequest;
      } catch {
        // Not JSON: the run failed before it answered; the status says so.
      }
      const result = process.env.PISHIP_LIVE_PROVIDER_RESULT;
      if (result)
        writeFileSync(
          result,
          JSON.stringify({
            model: MODEL,
            status: request.status,
            stopReason: modelRequest?.stopReason,
            replyLength: modelRequest?.text.length ?? 0,
            seconds,
          }),
        );

      // Nothing below prints AcmeCode's output or the provider's key, not even
      // in a failure message: on an upstream error the output names the
      // provider, its host, and its model, and the job log is public.
      const held = await acme.secrets();
      expect(leaks(acme.output(), held?.values ?? [])).toEqual([]);
      expect(
        acme.output().includes(process.env.LIVE_PROVIDER_API_KEY ?? ""),
        "AcmeCode printed the provider's key",
      ).toBe(false);
      expect(
        request.status,
        "--smoke-model failed; its output is not shown because it can name the provider",
      ).toBe(0);
      expect(modelRequest?.model).toBe(`acmecode/${MODEL}`);
      expect(modelRequest?.text.trim()).not.toBe("");
      expect(modelRequest?.stopReason).toBe("stop");

      const logout = await acme.run(["logout"]);
      expect(logout.status, logout.stderr).toBe(0);
    });
  },
);
