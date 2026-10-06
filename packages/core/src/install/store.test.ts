import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { describeStoreMaintenance, storeLiveness } from "./store.js";

let home = "";
let saved: string | undefined;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "piship-store-liveness-"));
  saved = process.env.PISHIP_INSTALL_HOME;
  process.env.PISHIP_INSTALL_HOME = home;
  mkdirSync(join(home, "receipts"), { recursive: true });
});
afterEach(() => {
  if (saved === undefined) delete process.env.PISHIP_INSTALL_HOME;
  else process.env.PISHIP_INSTALL_HOME = saved;
  rmSync(home, { recursive: true, force: true });
});

const receipt = (id: string, text: string) =>
  writeFileSync(join(home, "receipts", `${id}.json`), text);
const release = (id: string, version: string, at = home) => ({
  id,
  version,
  home: at,
});

describe("what the installation says of a recorded release", () => {
  it("pins the active release and the rollback target, and no other", () => {
    receipt("acme", JSON.stringify({ active: "1.2.0", previous: "1.1.0" }));
    const judge = storeLiveness();
    expect(judge(release("acme", "1.2.0"))).toBe("live");
    expect(judge(release("acme", "1.1.0"))).toBe("live");
    expect(judge(release("acme", "1.0.0"))).toBe("dead");
  });

  it("pins only the active release when there is no rollback target", () => {
    receipt("acme", JSON.stringify({ active: "2.0.0" }));
    const judge = storeLiveness();
    expect(judge(release("acme", "2.0.0"))).toBe("live");
    expect(judge(release("acme", "1.9.0"))).toBe("dead");
  });

  it("calls a distribution that is not installed here dead", () => {
    expect(storeLiveness()(release("gone", "1.0.0"))).toBe("dead");
  });

  it("does not judge a receipt it cannot read, so its objects stay", () => {
    receipt("broken", "{not json");
    receipt("empty", "{}");
    receipt("null", "null");
    const judge = storeLiveness();
    for (const id of ["broken", "empty", "null"])
      expect(judge(release(id, "1.0.0"))).toBe("unknown");
  });

  it("does not judge a release of another install home that still exists", () => {
    const other = mkdtempSync(join(tmpdir(), "piship-other-home-"));
    try {
      mkdirSync(join(other, "receipts"));
      const judge = storeLiveness();
      expect(judge(release("acme", "1.0.0", other))).toBe("unknown");
      rmSync(other, { recursive: true });
      expect(judge(release("acme", "1.0.0", other))).toBe("dead");
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });
});

describe("what doctor says of the store", () => {
  const collected = {
    busy: false,
    deferred: false,
    removedObjects: 0,
    freedBytes: 0,
    removedReferences: 0,
    removedTemporaries: 0,
    pinnedObjects: 0,
    remaining: false,
  };
  const verified = { checked: 0, damaged: [], repaired: 0, remaining: false };

  it("says nothing when there was nothing to do", () => {
    expect(describeStoreMaintenance(undefined)).toBeUndefined();
    expect(describeStoreMaintenance({ collected, verified })).toBeUndefined();
  });

  it("reports what was removed, what was deferred, and that installed releases are unaffected", () => {
    const text = describeStoreMaintenance({
      collected: {
        ...collected,
        removedObjects: 3,
        freedBytes: 2 * 1_048_576,
        remaining: true,
      },
      verified: { ...verified, damaged: ["x"], repaired: 1 },
    });
    expect(text).toContain("Removed 3 file store objects");
    expect(text).toContain("freed 2.0 MiB");
    expect(text).toContain("run doctor again");
    expect(text).toContain("Removed 1 damaged file store object;");
    expect(text).toContain("Installed releases are unaffected");
    expect(
      describeStoreMaintenance({
        collected: { ...collected, deferred: true },
        verified,
      }),
    ).toContain("an install or update is filling it");
    expect(
      describeStoreMaintenance({
        collected: { ...collected, busy: true },
        verified,
      }),
    ).toContain("another collection is running");
  });
});
