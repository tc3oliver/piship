import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type Credential,
  type ReferenceStack,
  type SpendLog,
  errorType,
  poll,
  startReferenceStack,
  sum,
} from "./stack.js";

// Section 9.1 of the v0.7 plan, decision D-01: one employee's credentials A,
// B and C, and every rotation, accrue ONE spend total against ONE budget, and
// a second employee has their own. Every spend figure is read from LiteLLM's
// own records (`/spend/users`, `/spend/logs`, `/key/info`), never counted by
// the test, and every refusal comes from LiteLLM itself: the requests go
// straight to the gateway with the key the real broker minted.
//
// Observed with LiteLLM v1.103.0 (the pinned image):
// - Spend is written in batches: user and key spend and the spend logs
//   appeared 5 to 18 s after the requests, so every spend check polls.
// - Budget enforcement does not wait for those writes: LiteLLM keeps an
//   in-memory spend counter per user (and reserves each request's maximum
//   cost against it while the request runs), so the request after the one
//   that reaches the budget is refused at once, 429 `budget_exceeded`, with
//   "Budget has been exceeded! User=<id> ..." or "ExceededBudget: User=<id>
//   over budget ..." depending on which check sees it first.
// - The broker keeps at most 3 live keys per employee
//   (BROKER_MAX_KEYS_PER_USER): the fourth acquire deletes the oldest.

const BUDGET = 0.01;
const SMALL = 300; // words: about $0.00064 on acme/coder (gpt-4.1 prices)
const LARGE = 1500; // words: about $0.00304

let stack: ReferenceStack;
beforeAll(() => {
  stack = startReferenceStack({
    name: "usage",
    brokerEnv: { BROKER_USER_MAX_BUDGET: String(BUDGET) },
  });
  console.info(
    `reference stack ${stack.project} up in ${stack.startupSeconds} s`,
  );
});
afterAll(() => stack?.stop());

/** Equal but for float noise: LiteLLM adds costs as floats. */
const same = (x: number, y: number) => Math.abs(x - y) < 1e-9;

const successes = (logs: SpendLog[]) =>
  logs.filter((log) => log.status === "success");

/** Wait until the user's spend records show `count` successful requests and the user row agrees with them. */
async function settledSpend(userId: string, count: number) {
  const { value, elapsedMs } = await poll(
    `${count} spend records for ${userId}`,
    async () => {
      const spend = await stack.userSpend(userId);
      const done = successes(spend.logs);
      return done.length === count &&
        same(spend.spend, sum(done.map((log) => log.spend)))
        ? spend
        : undefined;
    },
  );
  console.info(
    `spend records for ${count} requests landed after ${elapsedMs} ms`,
  );
  return value;
}

async function send(credential: Credential, words: number, times: number) {
  let cost = 0;
  for (let index = 0; index < times; index += 1) {
    const response = await stack.chat(credential.key, { words });
    expect(response.status).toBe(200);
    cost += Number(response.headers["x-litellm-response-cost"]);
  }
  return cost;
}

describe("usage continuity across credential rotation (live reference stack)", () => {
  let alice: string;
  let a: Credential;
  let b: Credential;
  let c: Credential;
  let d: Credential;
  let spendAfterRotation: number;
  let aliceResetAt: unknown;

  it("credentials A, B and C of one employee accrue one spend total against one budget", async () => {
    a = await stack.acquire("alice");
    b = await stack.acquire("alice");
    c = await stack.acquire("alice");
    expect(new Set([a.hash, b.hash, c.hash]).size).toBe(3);
    expect(new Set([a, b, c].map((key) => key.credentialId)).size).toBe(3);

    const infos = await Promise.all(
      [a, b, c].map((key) => stack.keyInfo(key.hash)),
    );
    alice = String(infos[0]?.user_id);
    expect(alice).toMatch(/^oidc-[0-9a-f]{40}$/);
    for (const info of infos) {
      // One LiteLLM user, no team (a team key ignores the user's budget), and
      // no budget on the key itself: the budget is the user's.
      expect(info.user_id).toBe(alice);
      expect(info.team_id ?? null).toBeNull();
      expect(info.max_budget ?? null).toBeNull();
    }

    const cost =
      (await send(a, SMALL, 2)) +
      (await send(b, SMALL, 2)) +
      (await send(c, SMALL, 2));

    const spend = await settledSpend(alice, 6);
    expect(spend.maxBudget).toBe(BUDGET);
    expect(spend.spend).toBeCloseTo(cost, 9);
    // Every request is attributed to the one user, whichever key sent it.
    const done = successes(spend.logs);
    expect(new Set(done.map((log) => log.user))).toEqual(new Set([alice]));
    const perKey = new Map<string, number>();
    for (const log of done)
      perKey.set(log.api_key, (perKey.get(log.api_key) ?? 0) + 1);
    expect(perKey).toEqual(
      new Map([
        [a.hash, 2],
        [b.hash, 2],
        [c.hash, 2],
      ]),
    );
    // The keys' own spend adds up to the user's (key spend is written in
    // its own batch, so it is polled too).
    await poll("key spend", async () => {
      const keys = await Promise.all(
        [a, b, c].map((key) => stack.keyInfo(key.hash)),
      );
      return same(sum(keys.map((key) => Number(key.spend))), spend.spend)
        ? true
        : undefined;
    });
    aliceResetAt = spend.row.budget_reset_at;
    expect(aliceResetAt).toEqual(expect.any(String));
  });

  it("rotation (a new key, then the old ones deleted) keeps the spend and the budget", async () => {
    const before = await settledSpend(alice, 6);

    // A fourth acquire: the broker keeps the newest 3 keys and deletes A.
    d = await stack.acquire("alice");
    expect((await stack.chat(a.key)).status).toBe(401);
    const listed = await stack.admin(
      `/key/list?user_id=${alice}&return_full_object=true&size=100`,
    );
    const live = (listed.body as { keys: { token: string }[] }).keys.map(
      (key) => key.token,
    );
    expect(new Set(live)).toEqual(new Set([b.hash, c.hash, d.hash]));

    // PiShip's revoke: B is deleted through the broker.
    const revoked = await stack.revoke(b);
    expect(revoked.status).toBe(200);
    expect(revoked.body).toMatchObject({ revoked: true });
    expect((await stack.chat(b.key)).status).toBe(401);

    expect((await stack.keyInfo(d.hash)).user_id).toBe(alice);
    const cost = await send(d, SMALL, 2);

    const after = await settledSpend(alice, 8);
    // The new key's spend is added to the old total, not started from zero,
    // and the deleted keys' spend still counts.
    expect(after.spend).toBeCloseTo(before.spend + cost, 9);
    expect(after.spend).toBeGreaterThan(before.spend);
    const hashes = new Set(successes(after.logs).map((log) => log.api_key));
    expect(hashes).toEqual(new Set([a.hash, b.hash, c.hash, d.hash]));
    // Same budget: same limit, same reset date.
    expect(after.maxBudget).toBe(BUDGET);
    expect(after.row.budget_reset_at).toBe(aliceResetAt);
    spendAfterRotation = after.spend;
  });

  it("a second employee has a separate spend total and budget", async () => {
    const bob = await stack.acquire("bob");
    const bobUser = String((await stack.keyInfo(bob.hash)).user_id);
    expect(bobUser).toMatch(/^oidc-[0-9a-f]{40}$/);
    expect(bobUser).not.toBe(alice);

    const cost = await send(bob, SMALL, 1);
    const bobSpend = await settledSpend(bobUser, 1);
    expect(bobSpend.spend).toBeCloseTo(cost, 9);
    expect(bobSpend.maxBudget).toBe(BUDGET);
    expect(successes(bobSpend.logs).map((log) => log.api_key)).toEqual([
      bob.hash,
    ]);

    const aliceSpend = await stack.userSpend(alice);
    expect(aliceSpend.spend).toBe(spendAfterRotation);
  });

  it("a request over the budget is refused by the gateway, on every key, and not for the other employee", async () => {
    let lastCost = 0;
    let sent = 0;
    let refusal: Awaited<ReturnType<ReferenceStack["chat"]>> | undefined;
    for (; sent < 10; sent += 1) {
      const response = await stack.chat(d.key, { words: LARGE });
      if (response.status !== 200) {
        refusal = response;
        break;
      }
      lastCost = Number(response.headers["x-litellm-response-cost"]);
    }
    expect(refusal?.status).toBe(429);
    expect(errorType(refusal)).toBe("budget_exceeded");
    expect(refusal?.scrubbed).toContain(`User=${alice}`);

    // A credential issued after the budget ran out does not bring a new one.
    const e = await stack.acquire("alice");
    const refusedNew = await stack.chat(e.key);
    expect(refusedNew.status).toBe(429);
    expect(errorType(refusedNew)).toBe("budget_exceeded");

    // Bob's budget is his own.
    const bob = await stack.acquire("bob");
    expect((await stack.chat(bob.key)).status).toBe(200);

    // From LiteLLM's records: the refusals were charged nothing, and the
    // refusal began at the first request after spend reached the budget.
    const settled = await settledSpend(alice, 8 + sent);
    expect(settled.spend).toBeGreaterThanOrEqual(BUDGET);
    expect(settled.spend - lastCost).toBeLessThan(BUDGET);
    // LiteLLM logs each refusal as a `failure` record (on D and on E), in
    // batches of their own.
    const { value: refusals } = await poll("refusal records", async () => {
      const failures = (await stack.userSpend(alice)).logs.filter(
        (log) => log.status === "failure",
      );
      return failures.length >= 2 ? failures : undefined;
    });
    expect(new Set(refusals.map((log) => log.api_key))).toEqual(
      new Set([d.hash, e.hash]),
    );
    expect(sum(refusals.map((log) => log.spend))).toBe(0);
    expect((await stack.userSpend(alice)).spend).toBe(settled.spend);
  });
});
