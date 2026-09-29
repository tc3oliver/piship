import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type ReferenceStack,
  errorType,
  startReferenceStack,
} from "./stack.js";

// Section 9: the gateway, not PiShip, enforces a key's concurrent requests
// (`max_parallel_requests`, set by the broker from
// BROKER_KEY_MAX_PARALLEL_REQUESTS) and model entitlement (the key's
// `models`, from the employee's Keycloak groups). Requests go straight to
// LiteLLM with the key the broker minted.
//
// Observed with LiteLLM v1.103.0 (the pinned image):
// - Concurrency: 429, type `throttling_error`, message "Rate limit exceeded
//   for api_key: <key hash>. Limit type: max_parallel_requests. Current
//   limit: 2, Remaining: 0 ...". The mock answers within milliseconds, yet 10
//   requests sent at once saw 2 to 6 pass and the rest refused: a slot is
//   freed when a request finishes, so it limits concurrency, not volume.
// - Budget reservations interact with concurrency: LiteLLM reserves each
//   running request's maximum cost (up to the model's maximum output, about
//   $0.26 for gpt-4.1) against the user's budget. A user whose remaining
//   budget is below that sees concurrent requests refused as
//   `budget_exceeded` although the recorded spend is under the budget. This
//   file keeps the broker's default budget (10) so the refusals seen are the
//   concurrency limit's.
// - Model entitlement: a model outside the key's list is refused with 403,
//   type `key_model_access_denied`, "The requested model '<model>' is not
//   available for this API key ...", before any upstream call; `/v1/models`
//   lists only the key's models.

let stack: ReferenceStack;
beforeAll(() => {
  stack = startReferenceStack({
    name: "concurrency",
    brokerEnv: { BROKER_KEY_MAX_PARALLEL_REQUESTS: "2" },
  });
  console.info(
    `reference stack ${stack.project} up in ${stack.startupSeconds} s`,
  );
});
afterAll(() => stack?.stop());

describe("per-key concurrency and model entitlement (live reference stack)", () => {
  it("max parallel requests: requests beyond the key's limit at once are refused by the gateway", async () => {
    const key = await stack.acquire("alice");
    expect((await stack.keyInfo(key.hash)).max_parallel_requests).toBe(2);

    const upstreamBefore = (await stack.upstreamRequests()).length;
    const answers = await Promise.all(
      Array.from({ length: 10 }, () => stack.chat(key.key, { words: 2 })),
    );
    const passed = answers.filter((answer) => answer.status === 200);
    const refused = answers.filter((answer) => answer.status !== 200);
    console.info(
      `10 concurrent requests, limit 2: ${passed.length} passed, ${refused.length} refused`,
    );
    expect(passed.length).toBeGreaterThanOrEqual(2);
    expect(refused.length).toBeGreaterThanOrEqual(1);
    for (const answer of refused) {
      expect(answer.status).toBe(429);
      expect(errorType(answer)).toBe("throttling_error");
      expect(answer.scrubbed).toContain(
        "Limit type: max_parallel_requests. Current limit: 2",
      );
    }
    // Only the requests that passed reached the model provider.
    expect((await stack.upstreamRequests()).length - upstreamBefore).toBe(
      passed.length,
    );

    // One at a time, the same key is never refused.
    for (let index = 0; index < 4; index += 1)
      expect((await stack.chat(key.key, { words: 2 })).status).toBe(200);
  });

  it("model entitlement: a model outside the key's list is refused by the gateway", async () => {
    const bob = await stack.acquire("bob");
    expect(bob.models).toEqual(["acme/coder"]);
    expect((await stack.keyInfo(bob.hash)).models).toEqual(["acme/coder"]);

    const listed = await stack.models(bob.key);
    expect(listed.status).toBe(200);
    expect(
      (listed.body as { data: { id: string }[] }).data.map((model) => model.id),
    ).toEqual(["acme/coder"]);

    const upstreamBefore = await stack.upstreamRequests();
    const denied = await stack.chat(bob.key, { model: "acme/general" });
    expect(denied.status).toBe(403);
    expect(errorType(denied)).toBe("key_model_access_denied");
    expect(denied.scrubbed).toContain(
      "The requested model 'acme/general' is not available for this API key",
    );
    expect(await stack.upstreamRequests()).toEqual(upstreamBefore);
    expect((await stack.chat(bob.key, { model: "acme/coder" })).status).toBe(
      200,
    );

    // The same model is served to an employee entitled to it.
    const alice = await stack.acquire("alice");
    expect(alice.models).toEqual(["acme/coder", "acme/general"]);
    expect(
      (await stack.chat(alice.key, { model: "acme/general" })).status,
    ).toBe(200);
  });
});
