import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type ReferenceStack,
  errorType,
  poll,
  startReferenceStack,
} from "./stack.js";

// The check behind the reference broker's budget model: are team-member budgets (`max_budget_in_team`)
// enforced by the pinned LiteLLM? The reference broker issues keys WITHOUT a
// team (one LiteLLM user per principal with a personal budget); teams would
// be adopted only if this holds. The broker does not create teams, so this
// file sets them up with the master key as an operator would, on users named
// like the broker's.
//
// Observed with LiteLLM v1.103.0 (the pinned image):
// - The team-member budget is enforced across all of the member's team keys,
//   including a key generated after it ran out: 429, type `budget_exceeded`,
//   "Budget has been exceeded! TeamMember=<user_id>:<team_id> Current cost:
//   <spend>, Max budget: <max_budget_in_team>". Another member of the same
//   team is not affected.
// - The user's personal `max_budget` is NOT enforced for team keys (fact F2):
//   a member whose personal budget is far below the team-member budget spends
//   past it on team keys. (`general_settings.apply_user_budget_to_team_keys`
//   changes that; the reference config does not set it.)
// - Team-member spend in `/team/info` lands in batches like user spend.

const MEMBER_BUDGET = 0.002;
const PERSONAL_BUDGET = 0.0005;

let stack: ReferenceStack;
beforeAll(() => {
  stack = startReferenceStack({ name: "teams" });
  console.info(
    `reference stack ${stack.project} up in ${stack.startupSeconds} s`,
  );
});
afterAll(() => stack?.stop());

describe("team-member budgets in the pinned LiteLLM (live reference stack)", () => {
  it("enforces max_budget_in_team on every team key of the member, and not the member's personal budget", async () => {
    const suffix = randomBytes(4).toString("hex");
    const members = [
      `oidc-member-a-${suffix}`,
      `oidc-member-b-${suffix}`,
    ] as const;
    for (const userId of members) {
      const created = await stack.admin("/user/new", {
        user_id: userId,
        user_role: "internal_user_viewer",
        auto_create_key: false,
        max_budget: PERSONAL_BUDGET,
      });
      expect(created.status).toBe(200);
    }
    const team = await stack.admin("/team/new", {
      team_alias: `reference-team-${suffix}`,
      max_budget: 100,
    });
    expect(team.status).toBe(200);
    const teamId = String((team.body as { team_id: string }).team_id);
    const added = await stack.admin("/team/member_add", {
      team_id: teamId,
      member: members.map((user_id) => ({ user_id, role: "user" })),
      max_budget_in_team: MEMBER_BUDGET,
    });
    expect(added.status).toBe(200);

    const teamKey = async (userId: string) => {
      const generated = await stack.admin("/key/generate", {
        user_id: userId,
        team_id: teamId,
        models: ["acme/coder"],
        duration: "1h",
      });
      expect(generated.status).toBe(200);
      return String((generated.body as { key: string }).key);
    };
    const [memberA, memberB] = members;
    const keysA = [await teamKey(memberA), await teamKey(memberA)] as const;
    const keyB = await teamKey(memberB);

    let successfulCost = 0;
    const settledMemberSpend = async () => {
      await poll("settled team-member spend", async () => {
        const info = await stack.admin(`/team/info?team_id=${teamId}`);
        expect(info.status).toBe(200);
        const rows = (
          info.body as {
            team_memberships: { user_id: string; spend: number }[];
          }
        ).team_memberships;
        const spend = rows.find((row) => row.user_id === memberA)?.spend ?? 0;
        return Math.abs(spend - successfulCost) < 1e-9 ? spend : undefined;
      });
    };

    // Member A alternates two keys (200 words, about $0.00044 a request).
    let passed = 0;
    let refusal: Awaited<ReturnType<ReferenceStack["chat"]>> | undefined;
    for (let attempts = 0; attempts < 20; attempts += 1) {
      const response = await stack.chat(keysA[passed % 2 === 0 ? 0 : 1], {
        words: 200,
      });
      if (response.status !== 200) {
        expect(response.status).toBe(429);
        expect(errorType(response)).toBe("budget_exceeded");
        expect(response.scrubbed).toContain(`TeamMember=${memberA}:${teamId}`);
        // Admission includes outstanding reservations. CI refused after only
        // $0.00132 of accepted calls; that is temporary, not budget exhaustion.
        // Wait for actual spend before continuing or checking a new key, so
        // persisted membership state also proves exhaustion.
        await settledMemberSpend();
        if (successfulCost < MEMBER_BUDGET) continue;
        refusal = response;
        break;
      }
      passed += 1;
      const cost = Number(response.headers["x-litellm-response-cost"]);
      expect(Number.isFinite(cost) && cost > 0).toBe(true);
      successfulCost += cost;
    }
    // The personal budget (0.0005) was passed after two requests and did not
    // stop the team keys; the team-member budget (0.002) did.
    expect(passed).toBeGreaterThan(2);
    expect(successfulCost).toBeGreaterThanOrEqual(MEMBER_BUDGET);
    expect(refusal?.status).toBe(429);
    expect(errorType(refusal)).toBe("budget_exceeded");
    expect(refusal?.scrubbed).toContain(`TeamMember=${memberA}:${teamId}`);
    expect(refusal?.scrubbed).toContain(`Max budget: ${MEMBER_BUDGET}`);

    for (const key of [...keysA, await teamKey(memberA)]) {
      const answer = await stack.chat(key, { words: 1 });
      expect(answer.status).toBe(429);
      expect(answer.scrubbed).toContain(`TeamMember=${memberA}:${teamId}`);
    }
    expect((await stack.chat(keyB, { words: 1 })).status).toBe(200);

    // LiteLLM's records: member A's team spend reached the member budget
    // and is past the personal budget; member B's is separate.
    const { value: memberships, elapsedMs } = await poll(
      "team-member spend",
      async () => {
        const info = await stack.admin(`/team/info?team_id=${teamId}`);
        const rows = (
          info.body as {
            team_memberships: { user_id: string; spend: number }[];
          }
        ).team_memberships;
        const spend = new Map(rows.map((row) => [row.user_id, row.spend]));
        return (spend.get(memberA) ?? 0) >= MEMBER_BUDGET &&
          (spend.get(memberB) ?? 0) > 0
          ? spend
          : undefined;
      },
    );
    console.info(`team-member spend landed after ${elapsedMs} ms`);
    expect(memberships.get(memberA)).toBeGreaterThan(PERSONAL_BUDGET);
    expect(memberships.get(memberB)).toBeLessThan(MEMBER_BUDGET);
  });
});
