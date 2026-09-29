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

  it("counts lifecycle outcomes by kind and error code only", () => {
    const metrics = new LocalMetrics(temp, { now });
    expect(metrics.snapshot()).not.toHaveProperty("lifecycle");
    metrics.recordLifecycle("check", "ok");
    metrics.recordLifecycle("update", "ok");
    metrics.recordLifecycle("update", "INTEGRITY_FAILED");
    metrics.recordLifecycle("rollback", "ok");
    metrics.recordLifecycle("rollback", "channel https://updates.acme/x");
    metrics.recordLifecycle("install" as never, "ok");
    metrics.save();
    const reloaded = LocalMetrics.load(temp, { now });
    expect(reloaded.snapshot().lifecycle).toEqual({
      "check:ok": 1,
      "update:ok": 1,
      "update:INTEGRITY_FAILED": 1,
      "rollback:ok": 1,
      "rollback:UNKNOWN": 1,
    });
    const path = join(temp, "logs", "metrics.json");
    const stored = JSON.parse(readFileSync(path, "utf8"));
    stored.lifecycle = {
      "update:ok": 2,
      "update:ok:extra": 1,
      "install:ok": 1,
      "update:https://x": 1,
    };
    writeFileSync(path, JSON.stringify(stored));
    expect(LocalMetrics.load(temp, { now }).snapshot().lifecycle).toEqual({
      "update:ok": 2,
    });
  });

  it("records identity and credential latency by fixed operation", () => {
    const metrics = new LocalMetrics(temp, { now });
    expect(metrics.snapshot()).not.toHaveProperty("latency");
    metrics.recordIdentityLatency(120.6);
    metrics.recordIdentityLatency(80);
    metrics.recordCredentialLatency("acquire", 40);
    metrics.recordCredentialLatency("refresh", 15);
    metrics.recordCredentialLatency("refresh", 25);
    metrics.recordLatency("identity", -1);
    metrics.recordLatency("identity", Number.POSITIVE_INFINITY);
    metrics.recordLatency("token sk-abc" as never, 5);
    metrics.recordCredentialLatency("revoke" as never, 5);
    metrics.save();
    const expected = {
      identity: { count: 2, lastMs: 80, minMs: 80, maxMs: 121, totalMs: 201 },
      "credential.acquire": {
        count: 1,
        lastMs: 40,
        minMs: 40,
        maxMs: 40,
        totalMs: 40,
      },
      "credential.refresh": {
        count: 2,
        lastMs: 25,
        minMs: 15,
        maxMs: 25,
        totalMs: 40,
      },
    };
    expect(metrics.snapshot().latency).toEqual(expected);
    expect(LocalMetrics.load(temp, { now }).snapshot().latency).toEqual(
      expected,
    );
  });

  it("records gateway reachability as the last result, its time, and counts", () => {
    let clock = new Date("2026-09-28T10:00:00.000Z");
    const metrics = new LocalMetrics(temp, { now: () => clock });
    expect(metrics.snapshot()).not.toHaveProperty("gateway");
    metrics.recordGatewayReachability(true);
    clock = new Date("2026-09-28T10:05:00.000Z");
    metrics.recordGatewayReachability(false, "NETWORK_DENIED");
    expect(metrics.snapshot().gateway).toEqual({
      reachable: false,
      code: "NETWORK_DENIED",
      reachableCount: 1,
      unreachableCount: 1,
      checkedAt: "2026-09-28T10:05:00.000Z",
      lastReachableAt: "2026-09-28T10:00:00.000Z",
    });
    clock = new Date("2026-09-28T10:06:00.000Z");
    metrics.recordGatewayReachability(
      false,
      "connect ECONNREFUSED https://gateway.acme.example/v1",
    );
    expect(metrics.snapshot().gateway?.code).toBe("UNKNOWN");
    clock = new Date("2026-09-28T10:07:00.000Z");
    metrics.recordGatewayReachability(true);
    metrics.save();
    const expected = {
      reachable: true,
      reachableCount: 2,
      unreachableCount: 2,
      checkedAt: "2026-09-28T10:07:00.000Z",
      lastReachableAt: "2026-09-28T10:07:00.000Z",
    };
    expect(metrics.snapshot().gateway).toEqual(expected);
    expect(LocalMetrics.load(temp, { now }).snapshot().gateway).toEqual(
      expected,
    );
  });

  it("records model catalog freshness without model data", () => {
    let clock = new Date("2026-09-28T09:00:00.000Z");
    const metrics = new LocalMetrics(temp, { now: () => clock });
    expect(metrics.snapshot()).not.toHaveProperty("modelCatalog");
    metrics.recordModelCatalogFetch(3);
    clock = new Date("2026-09-28T10:00:00.000Z");
    metrics.recordModelCatalogFetch(4);
    metrics.recordModelCatalogFetch(-1);
    metrics.recordModelCatalogFetch(1.5);
    metrics.save();
    const expected = { fetchedAt: "2026-09-28T10:00:00.000Z", models: 4 };
    expect(metrics.snapshot().modelCatalog).toEqual(expected);
    expect(LocalMetrics.load(temp, { now }).snapshot().modelCatalog).toEqual(
      expected,
    );
  });

  it("counts resource and provider load failures separately by error code", () => {
    const metrics = new LocalMetrics(temp, { now });
    expect(metrics.snapshot()).not.toHaveProperty("resourceLoadFailures");
    expect(metrics.snapshot()).not.toHaveProperty("providerLoadFailures");
    metrics.recordLoadFailure("resource", "INTEGRITY_FAILED");
    metrics.recordLoadFailure("resource", "INTEGRITY_FAILED");
    metrics.recordLoadFailure("resource", "ENOENT /home/alice/AGENTS.md");
    metrics.recordLoadFailure("provider", "CONFIG_INVALID");
    metrics.recordLoadFailure("extension" as never, "CONFIG_INVALID");
    metrics.save();
    const reloaded = LocalMetrics.load(temp, { now }).snapshot();
    expect(reloaded.resourceLoadFailures).toEqual({
      INTEGRITY_FAILED: 2,
      UNKNOWN: 1,
    });
    expect(reloaded.providerLoadFailures).toEqual({ CONFIG_INVALID: 1 });
    expect(reloaded.startupFailures).toEqual({});
  });

  it("records runtime and distribution versions only as semantic versions", () => {
    const metrics = new LocalMetrics(temp, { now });
    expect(metrics.snapshot()).not.toHaveProperty("versions");
    metrics.recordVersions({
      distribution: "1.1.0",
      piship: "0.1.0",
      pi: "0.87.1",
      node: "22.19.0",
    });
    metrics.recordVersions({
      distribution: "1.2.0 built from /home/alice",
      piship: "0.1.0",
      pi: "0.87.1",
    });
    metrics.recordVersions({
      distribution: "1.2.0",
      piship: "0.1.0",
      pi: "0.87.1",
      node: "v22",
    });
    metrics.save();
    const expected = {
      distribution: "1.1.0",
      piship: "0.1.0",
      pi: "0.87.1",
      node: "22.19.0",
      updatedAt: "2026-09-28T10:00:00.000Z",
    };
    expect(metrics.snapshot().versions).toEqual(expected);
    expect(LocalMetrics.load(temp, { now }).snapshot().versions).toEqual(
      expected,
    );
    metrics.recordVersions({
      distribution: "2.0.0-rc.1",
      piship: "0.2.0",
      pi: "0.88.0",
    });
    expect(metrics.snapshot().versions).toEqual({
      distribution: "2.0.0-rc.1",
      piship: "0.2.0",
      pi: "0.88.0",
      updatedAt: "2026-09-28T10:00:00.000Z",
    });
  });

  it("records the last workspace verification as enums and a time only", () => {
    const metrics = new LocalMetrics(temp, { now });
    expect(metrics.snapshot()).not.toHaveProperty("workspace");
    metrics.recordWorkspace(
      "shared",
      "synchronized",
      "verified",
      "2026-09-28T09:30:00Z",
    );
    metrics.save();
    const expected = {
      declared: "shared",
      effective: "synchronized",
      verification: "verified",
      checkedAt: "2026-09-28T09:30:00Z",
    };
    expect(metrics.snapshot().workspace).toEqual(expected);
    expect(LocalMetrics.load(temp, { now }).snapshot().workspace).toEqual(
      expected,
    );
    // A later result replaces it; anything PiShip does not define is UNKNOWN,
    // and a time that is not an RFC 3339 UTC time becomes the record time.
    metrics.recordWorkspace(
      "/home/alice/project/.git/piship-workspace",
      "mounted at https://sandbox.acme.example",
      "token 0123456789abcdef0123456789abcdef",
      "yesterday at /tmp/x",
    );
    metrics.save();
    const text = readFileSync(join(temp, "logs", "metrics.json"), "utf8");
    expect(JSON.parse(text).workspace).toEqual({
      declared: "UNKNOWN",
      effective: "UNKNOWN",
      verification: "UNKNOWN",
      checkedAt: "2026-09-28T10:00:00.000Z",
    });
    expect(text).not.toMatch(
      /alice|piship-workspace|acme|https|0123456789|tmp/,
    );
    for (const leaf of stringLeaves(JSON.parse(text).workspace))
      expect(leaf).toMatch(
        /^(declared|effective|verification|checkedAt|UNKNOWN|shared|synchronized|snapshot|not-required|pending|verified|unverifiable|failed|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z)$/,
      );
  });

  it("drops tampered workspace entries when loading", () => {
    const path = join(temp, "logs", "metrics.json");
    new LocalMetrics(temp, { now }).save();
    const write = (workspace: unknown) =>
      writeFileSync(
        path,
        JSON.stringify({
          schema: METRICS_SCHEMA,
          updatedAt: "2026-09-28T09:00:00.000Z",
          policyDenials: {},
          mcpHealth: {},
          startupFailures: {},
          workspace,
        }),
      );
    write({
      declared: "shared",
      effective: "/home/alice/secret",
      verification: "verified",
      checkedAt: "2026-09-28T09:00:00Z",
      reason: "the sandbox did not see /home/alice",
    });
    expect(LocalMetrics.load(temp, { now }).snapshot().workspace).toEqual({
      declared: "shared",
      effective: "UNKNOWN",
      verification: "verified",
      checkedAt: "2026-09-28T09:00:00Z",
    });
    write({ declared: "shared", effective: "shared", checkedAt: "never" });
    expect(LocalMetrics.load(temp, { now }).snapshot()).not.toHaveProperty(
      "workspace",
    );
    write("shared");
    expect(LocalMetrics.load(temp, { now }).snapshot()).not.toHaveProperty(
      "workspace",
    );
  });

  it("drops tampered observability entries when loading", () => {
    const path = join(temp, "logs", "metrics.json");
    new LocalMetrics(temp, { now }).save();
    writeFileSync(
      path,
      JSON.stringify({
        schema: METRICS_SCHEMA,
        updatedAt: "2026-09-28T09:00:00.000Z",
        policyDenials: {},
        mcpHealth: {},
        startupFailures: {},
        latency: {
          identity: { count: 1, lastMs: 5, minMs: 5, maxMs: 5, totalMs: 5 },
          "credential.acquire": { count: -1 },
          "token sk-abc": {
            count: 1,
            lastMs: 5,
            minMs: 5,
            maxMs: 5,
            totalMs: 5,
          },
        },
        gateway: {
          reachable: false,
          code: "https://gateway.acme.example rejected bearer sk-abc",
          reachableCount: 0,
          unreachableCount: 1,
          checkedAt: "2026-09-28T09:00:00.000Z",
          lastReachableAt: "yesterday",
        },
        modelCatalog: { fetchedAt: "2026-09-28T09:00:00.000Z", models: "gpt" },
        resourceLoadFailures: { CONFIG_INVALID: 1, "/home/alice": 1 },
        providerLoadFailures: { "prompt text": 3 },
        versions: {
          distribution: "1.0.0",
          piship: "0.1.0",
          pi: "secret",
          updatedAt: "2026-09-28T09:00:00.000Z",
        },
      }),
    );
    const snapshot = LocalMetrics.load(temp, { now }).snapshot();
    expect(snapshot.latency).toEqual({
      identity: { count: 1, lastMs: 5, minMs: 5, maxMs: 5, totalMs: 5 },
    });
    expect(snapshot.gateway).toEqual({
      reachable: false,
      code: "UNKNOWN",
      reachableCount: 0,
      unreachableCount: 1,
      checkedAt: "2026-09-28T09:00:00.000Z",
    });
    expect(snapshot).not.toHaveProperty("modelCatalog");
    expect(snapshot.resourceLoadFailures).toEqual({ CONFIG_INVALID: 1 });
    expect(snapshot).not.toHaveProperty("providerLoadFailures");
    expect(snapshot).not.toHaveProperty("versions");
    expect(JSON.stringify(snapshot)).not.toMatch(/sk-|alice|acme|prompt/);
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
