import { describe, expect, it } from "vitest";
import { makePolicy, rule } from "./fixtures.test-helpers.js";
import {
  manifestContainment,
  NO_CONTAINMENT,
  type UnenforcedPolicy,
  unenforcedRules,
} from "./index.js";

const contained = {
  filesystem: true,
  network: true,
  shell: true,
  piOffline: true,
};

describe("unenforcedRules", () => {
  const policy = makePolicy({
    enforced: [rule("no.web", "web.request", "**", "deny")],
    defaults: [rule("ask.memory", "memory.write", "**", "ask")],
  });

  it("fails a managed deny or ask on an unsupported action", () => {
    const findings = unenforcedRules("managed", policy, NO_CONTAINMENT);
    expect(findings.map((item) => [item.level, item.key])).toEqual([
      ["error", "web.request:**"],
      ["error", "memory.write:**"],
    ]);
    expect(findings[0]?.message).toContain(
      'add "web.request:**" to policy.acknowledgeUnenforced',
    );
    expect(findings[0]?.status).toBe("unsupported");
  });

  it("only warns in personal mode", () => {
    const findings = unenforcedRules("personal", policy, NO_CONTAINMENT);
    expect(findings.map((item) => item.level)).toEqual(["warning", "warning"]);
    expect(findings[0]?.message).not.toContain("acknowledgeUnenforced");
  });

  it("accepts acknowledged rules by exact action:resource key", () => {
    const acknowledged: UnenforcedPolicy = {
      ...policy,
      acknowledgeUnenforced: ["web.request:**", "memory.write:other"],
    };
    expect(
      unenforcedRules("managed", acknowledged, NO_CONTAINMENT).map(
        (item) => item.level,
      ),
    ).toEqual(["info", "error"]);
  });

  it("ignores allow, the default, wildcard, and prefix rules", () => {
    expect(
      unenforcedRules(
        "managed",
        makePolicy({
          default: "deny",
          enforced: [
            rule("all", "*", "**", "deny"),
            rule("web", "web.*", "**", "ask"),
            rule("mem", "memory.*", "**", "deny"),
            rule("ok", "web.request", "**", "allow"),
          ],
        }),
        NO_CONTAINMENT,
      ),
    ).toEqual([]);
  });

  it("ignores enforced actions and a contained network", () => {
    const enforced = makePolicy({
      enforced: [
        rule("tool", "tool.execute", "bash", "deny"),
        rule("net", "network.connect", "**", "deny"),
      ],
    });
    expect(unenforcedRules("managed", enforced, contained)).toEqual([]);
    expect(
      unenforcedRules("managed", enforced, NO_CONTAINMENT).map(
        (item) => item.key,
      ),
    ).toEqual(["network.connect:**"]);
  });

  it("checks session.export per resource", () => {
    const exports: UnenforcedPolicy = {
      enforced: [
        {
          id: "no.share",
          action: "session.export",
          resource: "public",
          effect: "deny",
        },
        {
          id: "support",
          action: "session.export",
          resource: "support",
          effect: "deny",
        },
        { id: "any", action: "session.export", resource: "**", effect: "ask" },
      ],
      defaults: [],
    };
    expect(
      unenforcedRules("managed", exports, contained).map((item) => item.key),
    ).toEqual(["session.export:public", "session.export:**"]);
    expect(
      unenforcedRules(
        "managed",
        { ...exports, acknowledgeUnenforced: ["session.export:public"] },
        contained,
      ).map((item) => item.level),
    ).toEqual(["info", "error"]);
    // Personal: Pi's /bug upload is open, so a support rule is unsupported too.
    expect(
      unenforcedRules("personal", exports, {
        ...contained,
        piOffline: false,
      }).map((item) => [item.level, item.key]),
    ).toEqual([
      ["warning", "session.export:public"],
      ["warning", "session.export:support"],
      ["warning", "session.export:**"],
    ]);
  });
});

describe("manifestContainment", () => {
  it("contains every plane only with a required sandbox", () => {
    expect(manifestContainment({}, "personal")).toEqual({
      ...NO_CONTAINMENT,
      piOffline: false,
    });
    expect(
      manifestContainment({ sandbox: { required: false } as never }, "managed"),
    ).toEqual({ ...NO_CONTAINMENT, piOffline: true });
    expect(
      manifestContainment({ sandbox: { required: true } as never }, "managed"),
    ).toEqual(contained);
  });

  it("runs Pi offline only in managed mode", () => {
    expect(manifestContainment({}, "managed").piOffline).toBe(true);
    expect(manifestContainment({}, "personal").piOffline).toBe(false);
  });
});
