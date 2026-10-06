// The footprint budget check: what counts as a regression, and that the pull
// request gate runs it. The measurement itself (a build and an install of each
// distribution) is scripts/benchmark-footprint.mjs --deterministic.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error The check is a plain ES module script.
import { compareBudgets, METRICS, SCHEMA } from "../scripts/check-budgets.mjs";

const ROOT = process.env.PISHIP_BUILD_INPUT as string;
const budget = {
  personal: {
    payloadFiles: 100,
    installedFiles: 102,
    archiveBytes: 10_000_000,
  },
};
const measure = (patch: Record<string, number>) => ({
  personal: {
    payloadFiles: 100,
    installedFiles: 102,
    archiveBytes: 10_000_000,
    ...patch,
  },
});

describe("footprint budgets", () => {
  it("passes a figure within the tolerance and fails one beyond it", () => {
    expect(compareBudgets(measure({}), budget, 0.1).failures).toEqual([]);
    // Exactly 10% over is within the tolerance; one file more is not.
    expect(
      compareBudgets(measure({ payloadFiles: 110 }), budget, 0.1).failures,
    ).toEqual([]);
    const over = compareBudgets(measure({ payloadFiles: 111 }), budget, 0.1);
    expect(over.failures).toHaveLength(1);
    expect(over.failures[0]).toMatchObject({
      name: "personal",
      metric: "payloadFiles",
      value: 111,
      budget: 100,
    });
    expect(
      compareBudgets(measure({ archiveBytes: 11_500_000 }), budget, 0.1)
        .failures[0],
    ).toMatchObject({ metric: "archiveBytes" });
  });

  it("reports a figure well under its budget without failing", () => {
    const result = compareBudgets(measure({ installedFiles: 60 }), budget, 0.1);
    expect(result.failures).toEqual([]);
    expect(result.improvements).toEqual([
      expect.objectContaining({ metric: "installedFiles", value: 60 }),
    ]);
  });

  it("names a distribution that has no budget", () => {
    const result = compareBudgets(
      {
        ...measure({}),
        developer: { payloadFiles: 1, installedFiles: 1, archiveBytes: 1 },
      },
      budget,
      0.1,
    );
    expect(result.missing).toEqual(["developer"]);
    expect(result.failures).toEqual([]);
  });

  it("budgets counts and bytes only, never a timing", () => {
    expect(METRICS).toEqual(["payloadFiles", "installedFiles", "archiveBytes"]);
  });

  it("records a budget for each distribution on a platform, in the committed file", () => {
    const file = JSON.parse(
      readFileSync(join(ROOT, "scripts", "performance-budgets.json"), "utf8"),
    ) as {
      schema: string;
      tolerance: number;
      platforms: Record<string, Record<string, Record<string, number>>>;
    };
    expect(file.schema).toBe(SCHEMA);
    expect(file.tolerance).toBe(0.1);
    for (const [platform, distributions] of Object.entries(file.platforms)) {
      expect(Object.keys(distributions).sort(), platform).toEqual(
        expect.arrayContaining(["managed", "personal"]),
      );
      for (const metrics of Object.values(distributions))
        for (const metric of METRICS)
          expect(metrics[metric], platform).toBeGreaterThan(0);
    }
  });

  it("runs on every pull request, in the CI check job", () => {
    const ci = readFileSync(
      join(ROOT, ".github", "workflows", "ci.yml"),
      "utf8",
    );
    expect(ci).toMatch(/^ {6}- run: npm run check:budgets$/m);
    const scripts = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"))
      .scripts as Record<string, string>;
    expect(scripts["check:budgets"]).toBe("node scripts/check-budgets.mjs");
  });
});
