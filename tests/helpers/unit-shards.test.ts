import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { unitShard } from "./unit-shards.js";

const ROOT = process.env.PISHIP_BUILD_INPUT as string;

/** The files `npm test` runs, as Vitest lists them with that script's excludes. */
function unitFiles(): string[] {
  const script = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"))
    .scripts.test as string;
  const excludes = [...script.matchAll(/--exclude '([^']+)'/g)].map(
    ([, glob]) => `--exclude=${glob}`,
  );
  expect(excludes.length).toBeGreaterThan(0);
  return execFileSync(
    process.execPath,
    [
      join(ROOT, "node_modules", "vitest", "vitest.mjs"),
      "list",
      "--filesOnly",
      ...excludes,
    ],
    { cwd: ROOT, encoding: "utf8" },
  )
    .split(/\r?\n/)
    .filter((line) => line.endsWith(".test.ts"))
    .map((line) => join(ROOT, line));
}

describe("unit shards", () => {
  const files = unitFiles();

  it("lists the unit files and none of the other tiers", () => {
    expect(files.length).toBeGreaterThan(200);
    expect(files).toContain(
      join(ROOT, "tests", "helpers", "unit-shards.test.ts"),
    );
    for (const file of files)
      expect(file).not.toMatch(
        /[\\/](e2e|compatibility|enterprise-reference)[\\/]/,
      );
  });

  for (const platform of ["linux", "darwin", "win32"] as const)
    it(`puts every file npm test runs in exactly one shard on ${platform}`, () => {
      for (let count = 1; count <= 4; count++) {
        const shards = Array.from({ length: count }, (_, index) =>
          unitShard(files, index + 1, count, platform),
        );
        for (const shard of shards) expect(shard.length).toBeGreaterThan(0);
        expect(shards.flat().sort()).toEqual([...files].sort());
        // Every shard computes the split alone, whatever order Vitest lists
        // the files in.
        expect(
          Array.from({ length: count }, (_, index) =>
            unitShard([...files].reverse(), index + 1, count, platform),
          ),
        ).toEqual(shards);
      }
    });

  it("places a file it has no duration for", () => {
    const extra = join(ROOT, "tests", "not-measured-yet.test.ts");
    const shards = [1, 2, 3].map((index) =>
      unitShard([...files, extra], index, 3, "linux"),
    );
    expect(shards.flat().filter((path) => path === extra)).toHaveLength(1);
    expect(shards.flat()).toHaveLength(files.length + 1);
  });
});
