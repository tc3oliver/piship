import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LocalMetrics, METRICS_SCHEMA } from "./index.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-metrics-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});
const now = () => new Date("2026-09-28T10:00:00.000Z");

/** Every string leaf in the stored file must be an identifier, code, or time. */
function stringLeaves(value: unknown, output: string[] = []): string[] {
  if (typeof value === "string") output.push(value);
  else if (value && typeof value === "object")
    for (const [key, item] of Object.entries(value)) {
      output.push(key);
      stringLeaves(item, output);
    }
  return output;
}

describe("LocalMetrics", () => {
  it("records metadata-only signals and saves them owner-only", () => {
    const metrics = new LocalMetrics(temp, { now });
    metrics.recordPolicyDenial("shell.execute");
    metrics.recordPolicyDenial("shell.execute");
    metrics.recordPolicyDenial("filesystem.read");
    metrics.recordMcpHealth("docs", "healthy");
    metrics.recordMcpHealth("docs", "failed");
    metrics.recordSandbox("enforced", "linux-bubblewrap");
    metrics.recordStartupFailure("SANDBOX_UNAVAILABLE");
    metrics.recordStartupLatency(412.4);
    metrics.recordStartupLatency(200);
    metrics.save();

    const path = join(temp, "logs", "metrics.json");
    const stored = JSON.parse(readFileSync(path, "utf8"));
    expect(stored).toEqual({
      schema: METRICS_SCHEMA,
      updatedAt: "2026-09-28T10:00:00.000Z",
      policyDenials: { "shell.execute": 2, "filesystem.read": 1 },
      mcpHealth: {
        docs: {
          state: "failed",
          healthy: 1,
          degraded: 0,
          failed: 1,
          updatedAt: "2026-09-28T10:00:00.000Z",
        },
      },
      sandbox: {
        level: "enforced",
        adapter: "linux-bubblewrap",
        updatedAt: "2026-09-28T10:00:00.000Z",
      },
      startupFailures: { SANDBOX_UNAVAILABLE: 1 },
      startupLatency: {
        count: 2,
        lastMs: 200,
        minMs: 200,
        maxMs: 412,
        totalMs: 612,
      },
    });
    if (process.platform !== "win32") {
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(statSync(join(temp, "logs")).mode & 0o777).toBe(0o700);
    }

    const reloaded = LocalMetrics.load(temp, { now });
    reloaded.recordPolicyDenial("shell.execute");
    expect(reloaded.snapshot().policyDenials["shell.execute"]).toBe(3);
    expect(reloaded.snapshot().startupLatency?.count).toBe(2);
  });

  it("never stores content-like strings", () => {
    const metrics = new LocalMetrics(temp, { now });
    metrics.recordPolicyDenial("cat ~/.ssh/id_rsa");
    metrics.recordPolicyDenial("summarize my secret plan");
    metrics.recordMcpHealth("/home/alice/project/server.mjs", "healthy");
    metrics.recordMcpHealth("docs server with spaces", "healthy");
    metrics.recordMcpHealth("docs", "exploded" as never);
    metrics.recordSandbox("enforced", "/usr/bin/bwrap --ro-bind / /");
    metrics.recordStartupFailure("Error: token sk-abcdef1234567 rejected");
    metrics.recordStartupLatency(Number.NaN);
    metrics.save();
    const text = readFileSync(join(temp, "logs", "metrics.json"), "utf8");
    expect(text).not.toMatch(/ssh|secret plan|home|alice|bwrap|sk-|spaces/);
    const snapshot = JSON.parse(text);
    expect(snapshot.policyDenials).toEqual({});
    expect(snapshot.mcpHealth).toEqual({});
    expect(snapshot.sandbox).toEqual({
      level: "enforced",
      updatedAt: "2026-09-28T10:00:00.000Z",
    });
    expect(snapshot.startupFailures).toEqual({ UNKNOWN: 1 });
    expect(snapshot).not.toHaveProperty("startupLatency");
    for (const leaf of stringLeaves(snapshot))
      expect(leaf).toMatch(/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$/);
  });

  it("drops tampered or content-bearing entries when loading", () => {
    const path = join(temp, "logs", "metrics.json");
    new LocalMetrics(temp, { now }).save();
    writeFileSync(
      path,
      JSON.stringify({
        schema: METRICS_SCHEMA,
        updatedAt: "2026-09-28T09:00:00.000Z",
        policyDenials: {
          "shell.execute": 2,
          "rm -rf /": 5,
          "tool.execute": -1,
        },
        mcpHealth: {
          docs: {
            state: "healthy",
            healthy: 1,
            degraded: 0,
            failed: 0,
            updatedAt: "2026-09-28T09:00:00.000Z",
          },
          "the prompt was": { state: "healthy" },
        },
        sandbox: {
          level: "enforced",
          adapter: "/opt/secret path",
          updatedAt: "x",
        },
        startupFailures: { AUDIT_UNAVAILABLE: 1, "free text": 2 },
        extra: "prompt body",
      }),
    );
    const snapshot = LocalMetrics.load(temp, { now }).snapshot();
    expect(snapshot.policyDenials).toEqual({ "shell.execute": 2 });
    expect(Object.keys(snapshot.mcpHealth)).toEqual(["docs"]);
    expect(snapshot).not.toHaveProperty("sandbox");
    expect(snapshot.startupFailures).toEqual({ AUDIT_UNAVAILABLE: 1 });
    expect(JSON.stringify(snapshot)).not.toContain("prompt body");
  });

  it("starts empty when the file is missing or corrupt", () => {
    expect(LocalMetrics.load(temp, { now }).snapshot().policyDenials).toEqual(
      {},
    );
    new LocalMetrics(temp, { now }).save();
    writeFileSync(join(temp, "logs", "metrics.json"), "{not json");
    expect(LocalMetrics.load(temp, { now }).snapshot().startupFailures).toEqual(
      {},
    );
  });
});
