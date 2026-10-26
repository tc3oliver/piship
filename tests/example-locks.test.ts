// The seam table is not part of a manifest, so a lock's manifest digest cannot
// see a change to it. The end-to-end test relocks the personal example and
// compares the whole file (tests/e2e/personal-local-model.test.ts); this is the
// fast check for every committed example lock, without building a distribution
// or relocking it.
// It hashes the current seam table and compares the digest each lock records.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { PI_VERSION } from "@piship/core";
import { seamEvidence } from "@piship/policy";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
const examples = join(root, "examples");

interface Lock {
  enforcement?: {
    pi?: string;
    digest?: string;
  };
}

/** Every `piship.lock` under `examples/`, with `/` separators and sorted. */
function lockFiles(): string[] {
  return readdirSync(examples, { recursive: true, encoding: "utf8" })
    .filter((path) => path.split(/[\\/]/).pop() === "piship.lock")
    .map((path) => join(examples, path))
    .sort();
}

/** The manifest path as a person at the repository root would type it. */
function inRepository(path: string): string {
  return relative(root, path).replaceAll("\\", "/");
}

describe("the committed example locks", () => {
  // Pi's seam table is static data; computing the digest needs no distribution
  // build.
  const current = seamEvidence(PI_VERSION);

  it("finds every committed example lock", () => {
    expect(lockFiles().map(inRepository)).toEqual(
      expect.arrayContaining([
        "examples/demo-company/piship.lock",
        "examples/developer/piship.lock",
        "examples/enterprise-reference/piship.lock",
        "examples/enterprise-reference/sandbox/piship.lock",
        "examples/personal/local-model/piship.lock",
        "examples/personal/piship.lock",
      ]),
    );
  });

  it("record the current runtime seam table digest", () => {
    for (const lockPath of lockFiles()) {
      const manifest = inRepository(join(dirname(lockPath), "piship.yaml"));
      const command = `piship lock ${manifest}`;
      const stale = `${inRepository(lockPath)} is stale; run \`${command}\` to regenerate it.`;
      const lock = JSON.parse(readFileSync(lockPath, "utf8")) as Lock;
      expect(lock.enforcement?.digest, stale).toBe(current.digest);
      expect(lock.enforcement?.pi, stale).toBe(PI_VERSION);
    }
  });
});
