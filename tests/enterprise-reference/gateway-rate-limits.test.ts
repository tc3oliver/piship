import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type HttpResult,
  type ReferenceStack,
  errorType,
  startReferenceStack,
} from "./stack.js";

// Section 9: the gateway, not PiShip, enforces each employee's requests per
// minute and tokens per minute. The broker sets them on the employee's
// LiteLLM user when it creates it (BROKER_USER_RPM_LIMIT and
// BROKER_USER_TPM_LIMIT), and the requests below go straight to LiteLLM with
// the key the broker minted.
//
// Observed with LiteLLM v1.103.0 (the pinned image); its error bodies for
// these limits are not documented, so the assertions use the status, the
// error type and a stable part of the message:
// - RPM: 429, type `throttling_error`, `retry-after: 60`, message "Rate limit
//   exceeded for user: <user_id>. Limit type: requests. Current limit: 5,
//   Remaining: 0. Limit resets at: <time> UTC". Exactly RPM requests pass;
//   the window starts at the first request.
// - TPM: 429, type `throttling_error`, `retry-after: 60`, "... Limit type:
//   tokens. Current limit: 3000, Remaining: <n> ...". LiteLLM reserves an
//   estimate of a request's tokens before sending it (input characters / 4
//   plus an output allowance) and corrects it to the real usage afterwards,
//   so a refusal can say "Remaining: 590", and whether the second of two
//   1205-token requests passes depends on whether the first one's correction
//   landed: one or two pass, never three.
// - Both limits belong to the user: a key issued afterwards is refused too.

const RPM = 5;
const TPM = 3000;

let stack: ReferenceStack;
beforeAll(() => {
  stack = startReferenceStack({
    name: "ratelimits",
    brokerEnv: {
      BROKER_USER_RPM_LIMIT: String(RPM),
      BROKER_USER_TPM_LIMIT: String(TPM),
    },
  });
  console.info(
    `reference stack ${stack.project} up in ${stack.startupSeconds} s`,
  );
});
afterAll(() => stack?.stop());

/** Send until the gateway refuses, at most `limit` requests. */
async function untilRefused(key: string, words: number, limit: number) {
  const passed: HttpResult[] = [];
  for (let index = 0; index < limit; index += 1) {
    const response = await stack.chat(key, { words });
    if (response.status !== 200) return { passed, refusal: response };
    passed.push(response);
  }
  return { passed, refusal: undefined };
}

async function userLimits(userId: string) {
  const info = await stack.admin(`/user/info?user_id=${userId}`);
  const user = (info.body as { user_info: Record<string, unknown> }).user_info;
  return { rpm: user.rpm_limit, tpm: user.tpm_limit };
}

describe("per-employee rate limits (live reference stack)", () => {
  it("requests per minute: the gateway refuses the request after the limit, on every key of the employee", async () => {
    const first = await stack.acquire("bob");
    const bob = String((await stack.keyInfo(first.hash)).user_id);
    expect(await userLimits(bob)).toEqual({ rpm: RPM, tpm: TPM });

    const upstreamBefore = (await stack.upstreamRequests()).length;
    const { passed, refusal } = await untilRefused(first.key, 1, RPM + 3);
    expect(passed).toHaveLength(RPM);
    expect(refusal?.status).toBe(429);
    expect(errorType(refusal)).toBe("throttling_error");
    expect(refusal?.scrubbed).toContain(
      `Rate limit exceeded for user: ${bob}. Limit type: requests. Current limit: ${RPM}`,
    );
    expect(refusal?.headers["retry-after"]).toMatch(/^\d+$/);
    // The refused request never reached the model provider.
    expect((await stack.upstreamRequests()).length - upstreamBefore).toBe(RPM);

    const second = await stack.acquire("bob");
    const again = await stack.chat(second.key, { words: 1 });
    expect(again.status).toBe(429);
    expect(again.scrubbed).toContain("Limit type: requests");
  });

  it("tokens per minute: the gateway refuses once the employee's tokens reach the limit, on every key", async () => {
    const first = await stack.acquire("alice");
    const alice = String((await stack.keyInfo(first.hash)).user_id);
    expect(await userLimits(alice)).toEqual({ rpm: RPM, tpm: TPM });

    // 1200 words is 1205 tokens with the reply: a third would pass 3000.
    const { passed, refusal } = await untilRefused(first.key, 1200, RPM - 1);
    expect(passed.length).toBeGreaterThanOrEqual(1);
    expect(passed.length).toBeLessThanOrEqual(2);
    for (const response of passed)
      expect(
        (response.body as { usage: { total_tokens: number } }).usage
          .total_tokens,
      ).toBe(1205);
    expect(refusal?.status).toBe(429);
    expect(errorType(refusal)).toBe("throttling_error");
    expect(refusal?.scrubbed).toContain(
      `Rate limit exceeded for user: ${alice}. Limit type: tokens. Current limit: ${TPM}`,
    );
    expect(refusal?.headers["retry-after"]).toMatch(/^\d+$/);

    const second = await stack.acquire("alice");
    const again = await stack.chat(second.key, { words: 1200 });
    expect(again.status).toBe(429);
    expect(again.scrubbed).toContain("Limit type: tokens");
  });
});
