import { readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { SHARDS } from "../vitest.reference.config.js";

// Reference E2E runs one group of vitest.reference.config.ts per runner. A
// file no group names falls into the last group unweighed, which is how that
// group once took twice as long as the others; name each file exactly once.
it("names every reference E2E file in exactly one group", () => {
  const ROOT = process.env.PISHIP_BUILD_INPUT as string;
  const files = [
    "tests/enterprise-reference",
    "examples/enterprise-reference/tests",
  ].flatMap((dir) =>
    readdirSync(join(ROOT, dir))
      .filter((name) => name.endsWith(".test.ts"))
      .map((name) => `${dir}/${name}`),
  );
  expect([...SHARDS.flat()].sort()).toEqual(files.sort());
});
