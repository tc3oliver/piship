import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  E2E_FILES,
  e2eFileKey,
  e2eFixtures,
  e2eShard,
  type LifecycleFixture,
} from "./e2e-shards.js";

const e2e = fileURLToPath(new URL("../e2e/", import.meta.url));
const files = readdirSync(e2e)
  .filter((name) => name.endsWith(".test.ts"))
  .map((name) => join(e2e, name));

/** A file's source and that of the sibling modules it imports its scenarios from. */
function source(path: string): string {
  const text = readFileSync(path, "utf8");
  const siblings = [...text.matchAll(/from "\.\/([\w-]+)\.js"/g)].map(
    ([, name]) => readFileSync(join(e2e, `${name}.ts`), "utf8"),
  );
  return [text, ...siblings].join("\n");
}

describe("E2E shards", () => {
  it("has the measured duration of every E2E file and of no other", () => {
    expect(Object.keys(E2E_FILES).sort()).toEqual(files.map(e2eFileKey).sort());
  });

  // A module shared by several test files holds the scenarios of each, so
  // the check is one way: a declared fixture is used, and a file that uses
  // any declares one.
  it("declares lifecycle fixtures that each file's scenarios use", () => {
    const uses: Record<LifecycleFixture, RegExp> = {
      demo: /lifecycleScenario\(|lifecycleReleases\(/,
      "demo-system": /lifecycleScenario\(/,
      "demo-commands": /commands: true/,
      personal: /personalScenario\(/,
      "personal-local": /personalLocalScenario\(/,
    };
    for (const file of files) {
      const text = source(file);
      const declared = [...e2eFixtures([file])];
      for (const fixture of declared)
        expect(text, `${file} uses ${fixture}`).toMatch(uses[fixture]);
      if (
        /lifecycleScenario\(|lifecycleReleases\(|personal\w*Scenario\(/.test(
          text,
        )
      )
        expect(declared, `${file} declares its fixtures`).not.toEqual([]);
    }
  });

  for (const platform of ["linux", "darwin", "win32"] as const)
    it(`puts every file in exactly one shard on ${platform}`, () => {
      for (let count = 1; count <= 6; count++) {
        const shards = Array.from({ length: count }, (_, index) =>
          e2eShard(files, index + 1, count, platform),
        );
        for (const shard of shards) expect(shard.length).toBeGreaterThan(0);
        expect(shards.flat().sort()).toEqual([...files].sort());
        // Files that wait for the live platform store are spread evenly.
        const stores = shards.map(
          (shard) =>
            shard.filter((path) => E2E_FILES[e2eFileKey(path)]?.store).length,
        );
        expect(Math.max(...stores) - Math.min(...stores)).toBeLessThanOrEqual(
          1,
        );
        // Every shard computes the split alone, whatever order Vitest lists
        // the files in.
        expect(
          Array.from({ length: count }, (_, index) =>
            e2eShard([...files].reverse(), index + 1, count, platform),
          ),
        ).toEqual(shards);
      }
    });

  it("places a file it has no duration for", () => {
    const extra = join(e2e, "not-measured-yet.test.ts");
    const shards = [1, 2, 3].map((index) =>
      e2eShard([...files, extra], index, 3, "linux"),
    );
    expect(shards.flat().filter((path) => path === extra)).toHaveLength(1);
  });
});
