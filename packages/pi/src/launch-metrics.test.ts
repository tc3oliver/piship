import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { METRICS_FILE } from "@piship/audit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { launchMetrics, saveMetrics } from "./launch-metrics.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-launch-metrics-"));
});
afterEach(() => rmSync(temp, { recursive: true, force: true }));

const metadata = (extra: object) =>
  ({
    app: { version: "1.2.3" },
    runtime: { pishipVersion: "0.1.0" },
    ...extra,
  }) as unknown as Parameters<typeof launchMetrics>[0];

describe("launch metrics", () => {
  it("records the distribution, PiShip, Pi, and Node versions at startup", () => {
    const metrics = launchMetrics(metadata({ access: {} }), temp, "1.0.2");
    saveMetrics(metrics);
    const saved = JSON.parse(readFileSync(join(temp, METRICS_FILE), "utf8"));
    expect(saved.versions).toMatchObject({
      distribution: "1.2.3",
      piship: "0.1.0",
      pi: "1.0.2",
      node: process.versions.node,
    });
  });

  it("keeps counts already on disk and keeps none for a plain personal distribution", () => {
    const first = launchMetrics(metadata({ governance: {} }), temp, "1.0.2");
    first?.recordPolicyDenial("tool.execute");
    saveMetrics(first);
    const second = launchMetrics(metadata({ governance: {} }), temp, "1.0.2");
    expect(second?.snapshot().policyDenials).toEqual({ "tool.execute": 1 });
    expect(launchMetrics(metadata({}), temp, "1.0.2")).toBeUndefined();
  });

  it("never throws when the metrics cannot be saved", () => {
    const metrics = launchMetrics(metadata({ access: {} }), temp, "1.0.2");
    // A file where the logs directory should be makes the save fail.
    writeFileSync(join(temp, "logs"), "");
    expect(() => saveMetrics(metrics)).not.toThrow();
    saveMetrics(undefined);
  });
});
