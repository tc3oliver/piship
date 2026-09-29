// The gate on the sandbox kit's tests must never let a missing isolator pass
// as a green run with no evidence: it says so when it skips, and under
// PISHIP_REQUIRE_ISOLATOR=1 it fails.
import { describe, expect, it } from "vitest";
import { type Host, isolatorGate, noIsolatorReason } from "./isolator-gate.js";

interface Registered {
  readonly kind: "describe" | "describeSkip" | "it" | "itSkip";
  readonly name: string;
  readonly run?: () => void | Promise<void>;
}

/** A host that records what the gate registers and prints instead of running it. */
function recording() {
  const registered: Registered[] = [];
  const warnings: string[] = [];
  const host: Host = {
    describe: (name, define) => {
      registered.push({ kind: "describe", name });
      define();
    },
    describeSkip: (name, define) => {
      registered.push({ kind: "describeSkip", name });
      define();
    },
    it: (name, run) => {
      registered.push({ kind: "it", name, run });
    },
    itSkip: (name, run) => {
      registered.push({ kind: "itSkip", name, run });
    },
    warn: (message) => {
      warnings.push(message);
    },
  };
  return { host, registered, warnings };
}

const REASON = "no isolator here for a test";

function gateFor(required: boolean) {
  const seen = recording();
  const gate = isolatorGate({
    host: seen.host,
    required,
    reason: () => REASON,
  });
  return { ...seen, gate };
}

describe("the isolator gate", () => {
  it("registers a suite and a test as they are when an isolator was found", () => {
    for (const required of [false, true]) {
      const { gate, registered, warnings } = gateFor(required);
      gate.describe("seatbelt")("a suite", () => undefined);
      gate.it("bubblewrap")("a test", () => undefined);
      expect(registered.map(({ kind, name }) => [kind, name])).toEqual([
        ["describe", "a suite"],
        ["it", "a test"],
      ]);
      expect(warnings).toEqual([]);
    }
  });

  it("skips a suite without an isolator, names the reason on the console and in the title, and still registers its tests as skipped", () => {
    const { gate, registered, warnings } = gateFor(false);
    let defined = false;
    gate.describe(undefined)("sandbox backends", () => {
      defined = true;
    });
    expect(defined).toBe(true);
    expect(registered).toEqual([
      {
        kind: "describeSkip",
        name: "sandbox backends (skipped: no OS isolator)",
      },
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("sandbox backends: skipped");
    expect(warnings[0]).toContain(REASON);
    expect(warnings[0]).toContain("PISHIP_REQUIRE_ISOLATOR=1");
  });

  it("skips a test without an isolator the same way", () => {
    const { gate, registered, warnings } = gateFor(false);
    gate.it(undefined)("sandbox.mjs passes", () => undefined, 5_000);
    expect(registered.map(({ kind, name }) => [kind, name])).toEqual([
      ["itSkip", "sandbox.mjs passes (skipped: no OS isolator)"],
    ]);
    expect(warnings.join("\n")).toContain(REASON);
  });

  it("fails a suite without an isolator when one is required, and does not run its tests", () => {
    const { gate, registered, warnings } = gateFor(true);
    let defined = false;
    gate.describe(undefined)("sandbox backends", () => {
      defined = true;
    });
    expect(defined).toBe(false);
    expect(registered.map(({ kind, name }) => [kind, name])).toEqual([
      ["describe", "sandbox backends"],
      ["it", "has an OS isolator (PISHIP_REQUIRE_ISOLATOR=1)"],
    ]);
    expect(() => registered[1]?.run?.()).toThrow(
      /sandbox backends needs an OS isolator and this host has none: no isolator here for a test/,
    );
    expect(warnings).toEqual([]);
  });

  it("fails a test without an isolator when one is required", () => {
    const { gate, registered } = gateFor(true);
    gate.it(undefined)("sandbox.mjs passes", () => undefined);
    expect(registered.map(({ kind, name }) => [kind, name])).toEqual([
      ["it", "sandbox.mjs passes"],
    ]);
    expect(() => registered[0]?.run?.()).toThrow(/needs an OS isolator/);
  });

  it("explains why this host has no isolator, in words that name what to fix", () => {
    expect(noIsolatorReason()).toMatch(/\S{4,}/);
    if (process.platform === "linux")
      expect(noIsolatorReason()).toMatch(/bubblewrap|bwrap/);
    if (process.platform === "darwin")
      expect(noIsolatorReason()).toMatch(/sandbox-exec/);
  });
});
