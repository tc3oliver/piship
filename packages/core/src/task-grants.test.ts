// `policy.taskGrants` in the lock diff: enabling grants is a governance change.
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { explainConfiguration } from "./access/index.js";
import {
  diffLocks,
  formatInspection,
  inspection,
  resolveLock,
} from "./index.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);

function demoLock(taskGrants?: object) {
  const lock = resolveLock(DEMO);
  const governance = lock.governance as NonNullable<typeof lock.governance>;
  const { taskGrants: _absent, ...policy } = governance.manifest.policy;
  return {
    ...lock,
    governance: {
      ...governance,
      manifest: {
        ...governance.manifest,
        policy: { ...policy, ...(taskGrants ? { taskGrants } : {}) },
      },
    },
  };
}

const changes = (before: object | undefined, after: object | undefined) =>
  diffLocks(demoLock(before) as never, demoLock(after) as never).changes.filter(
    (change) => change.item.startsWith("policy taskGrants"),
  );

describe("policy.taskGrants in piship diff", () => {
  it("rates enabling session grants medium", () => {
    expect(changes(undefined, { mode: "session" })).toEqual([
      expect.objectContaining({
        item: "policy taskGrants.mode",
        before: "off",
        after: "session",
        risk: "medium",
      }),
    ]);
  });

  it("treats declaring off as no change", () => {
    expect(changes(undefined, { mode: "off" })).toEqual([]);
  });

  it("rates a higher ttl cap medium and a wildcard host high", () => {
    const base = { mode: "session", maxTtlMinutes: 30 };
    expect(changes(base, { ...base, maxTtlMinutes: 120 })[0]).toMatchObject({
      risk: "medium",
    });
    expect(changes(base, { ...base, maxTtlMinutes: 10 })[0]).toMatchObject({
      risk: "low",
    });
    expect(changes(base, { ...base, wildcardHosts: true })[0]).toMatchObject({
      item: "policy taskGrants.wildcardHosts",
      risk: "high",
    });
  });
});

describe("policy.taskGrants in reports", () => {
  const grants = { mode: "session", maxTtlMinutes: 30, actions: ["git.push"] };

  it("inspect names it only when declared", () => {
    const show = (lock: ReturnType<typeof demoLock>) =>
      formatInspection(inspection(lock as never, "/nonexistent-state"));
    expect(show(demoLock(grants))).toMatch(
      /grants\s+session \(ttl <= 30 min\)/,
    );
    expect(show(demoLock())).not.toMatch(/grants\s/);
  });

  it("config explain adds a row only when declared", async () => {
    const explain = async (lock: ReturnType<typeof demoLock>) =>
      explainConfiguration({
        app: lock.app as never,
        mode: "managed",
        access: lock.access,
        stateDir: "/nonexistent-state",
        distributionDir: "/nonexistent-dist",
        schema: lock.manifest.schema,
        governance: lock.governance?.manifest as never,
      });
    expect(
      (await explain(demoLock(grants))).find(
        (row) => row.key === "policy.taskGrants",
      ),
    ).toMatchObject({
      value: "session",
      note: "ttl <= 30 min; actions git.push; no wildcard hosts",
    });
    expect(
      (await explain(demoLock())).find(
        (row) => row.key === "policy.taskGrants",
      ),
    ).toBeUndefined();
  });
  it("reports locked task declarations in doctor inspection", () => {
    const lock = demoLock({
      mode: "session",
      declared: [
        {
          id: "ci-fix",
          task: "CI repair",
          ttlMinutes: 20,
          scope: { paths: ["src"] },
          inheritToSubagents: true,
        },
      ],
    });
    expect(
      formatInspection(inspection(lock as never, "/nonexistent-state")),
    ).toMatch(/grant tasks\s+1 declared/);
  });

});
