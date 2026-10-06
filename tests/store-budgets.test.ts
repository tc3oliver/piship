import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  evaluateInstallMetrics,
  evaluateStoreBudgets,
  readBudgets,
  // @ts-expect-error The budget script is plain JavaScript.
} from "../scripts/store-budgets.mjs";
import {
  decide,
  summarize,
  // @ts-expect-error The benchmark script is plain JavaScript.
} from "../scripts/benchmark-store.mjs";

const scenario = (median: number) => ({ median });
const report = (scenarios: Record<string, number>, defaultMode = "off") => ({
  config: { defaultMode, primitives: ["hardlink"], verifyModes: ["content"] },
  scenarios: Object.fromEntries(
    Object.entries(scenarios).map(([name, value]) => [name, scenario(value)]),
  ),
  primitives: { hardlink: { used: "hardlink" } },
});

describe("the store and install budgets", () => {
  const budgets = readBudgets();

  it("states the thresholds the release plan sets", () => {
    expect(budgets.rules).toMatchObject({
      explainAbovePercent: 5,
      blockAbovePercent: 10,
      statistic: "median",
    });
    expect(budgets.installMetrics.distributions).toEqual([
      "personal",
      "managed",
      "developer",
    ]);
    expect(
      budgets.installMetrics.metrics.map(
        (metric: { label: string }) => metric.label,
      ),
    ).toEqual(
      expect.arrayContaining([
        "payload files",
        "installed files",
        "archive bytes",
        "install",
        "update",
        "first startup",
        "warm startup",
        "cold build",
        "warm build",
      ]),
    );
  });

  it("blocks a placement mode that costs more than writing the files", () => {
    const slow = report({
      direct: 100,
      "direct.remove": 100,
      "hardlink.fresh": 150,
      "hardlink.warm": 90,
      "hardlink.update": 101,
      "hardlink.remove": 105,
    });
    const found = evaluateStoreBudgets(slow, budgets, { mode: "hardlink" });
    expect(found.map((finding: { name: string }) => finding.name)).toEqual([
      "hardlink.fresh",
      "hardlink.update",
    ]);
    expect(
      found.every((finding: { level: string }) => finding.level === "block"),
    ).toBe(true);
    // With the store off there is no mode to hold to a budget.
    expect(evaluateStoreBudgets(slow, budgets)).toEqual([]);
    // The product's own object check is the one held to the budget.
    const checked = report({
      direct: 100,
      "hardlink+content.fresh": 150,
      "hardlink+size.fresh": 105,
    });
    expect(
      evaluateStoreBudgets(checked, budgets, { mode: "hardlink" }),
    ).toEqual([expect.objectContaining({ name: "hardlink+content.fresh" })]);
    // An unmeasured mode is not guessed at.
    expect(evaluateStoreBudgets(slow, budgets, { mode: "clone" })).toEqual([]);
  });

  it("explains a median regression above 5% and blocks one above 10% against a baseline", () => {
    const before = report({ direct: 100, "hardlink.warm": 100 });
    const after = (direct: number, warm: number) =>
      evaluateStoreBudgets(report({ direct, "hardlink.warm": warm }), budgets, {
        baseline: before,
      });
    expect(after(104, 100)).toEqual([]);
    expect(after(106, 100)).toEqual([
      expect.objectContaining({ name: "direct", level: "explain" }),
    ]);
    expect(after(100, 111)).toEqual([
      expect.objectContaining({ name: "hardlink.warm", level: "block" }),
    ]);
  });

  it("compares install, update, startup, build, and size metrics of two benchmark reports", () => {
    const run = (install: number, files: number, startup: number) => ({
      elapsedMs: { install, warmProcessStartup: startup },
      filesystem: { payloadFiles: files, archiveBytes: 1000 },
      authoring: { warmBuildMs: [10, 12, 11] },
    });
    expect(
      evaluateInstallMetrics(run(100, 120, 500), run(100, 120, 500), budgets),
    ).toEqual([]);
    const worse = evaluateInstallMetrics(
      run(120, 120, 530),
      run(100, 120, 500),
      budgets,
    );
    expect(worse).toEqual([
      expect.objectContaining({ name: "install", level: "block" }),
      expect.objectContaining({ name: "warm startup", level: "explain" }),
    ]);
    // More files on the personal distribution because a developer one got
    // smaller is a regression too.
    expect(
      evaluateInstallMetrics(run(100, 200, 500), run(100, 120, 500), budgets),
    ).toEqual([
      expect.objectContaining({ name: "payload files", level: "block" }),
    ]);
  });

  it("summarizes samples by median and nearest-rank P95, and decides by the stated rule", () => {
    expect(summarize([5, 1, 3, 2, 4])).toMatchObject({
      median: 3,
      p95: 5,
      min: 1,
      max: 5,
    });
    const good = report({
      direct: 100,
      "direct.remove": 100,
      "hardlink.fresh": 110,
      "hardlink.warm": 40,
      "hardlink.update": 60,
      "hardlink.remove": 100,
    });
    expect(decide(good).winner).toBe("hardlink");
    const bad = report({
      direct: 100,
      "direct.remove": 100,
      "hardlink.fresh": 300,
      "hardlink.warm": 200,
      "hardlink.update": 200,
      "hardlink.remove": 100,
    });
    expect(decide(bad).winner).toMatch(/^none/);
    // A primitive the volume replaced with another is not the one measured.
    const fallback = { ...good, primitives: { hardlink: { used: "copy" } } };
    expect(decide(fallback).winner).toMatch(/^none/);
  });

  it("is valid JSON beside its script", () => {
    expect(
      JSON.parse(
        readFileSync(
          fileURLToPath(
            new URL("../scripts/store-budgets.json", import.meta.url),
          ),
          "utf8",
        ),
      ).schema,
    ).toBe("piship-store-budgets/v1");
  });
});
