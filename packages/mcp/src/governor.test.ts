import { spawn as spawnChild } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PiShipError, SecretValue } from "@piship/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFixtureHttpServer } from "./testing/fixture-http.mjs";
import {
  defaultProcessRuntime,
  McpGovernor,
  type McpGovernorOptions,
} from "./index.js";
import type {
  ChildHandle,
  McpAuditEvent,
  McpAuthorize,
  McpServerConfig,
  ProcessRuntime,
  SpawnRequest,
} from "./types.js";

// On Windows libuv always adds these to a child's environment, whatever the
// parent passes, so they cannot be filtered and are not counted here.
const WINDOWS_REQUIRED = new Set([
  "HOMEDRIVE",
  "HOMEPATH",
  "LOGONSERVER",
  "PATH",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "USERDOMAIN",
  "USERNAME",
  "USERPROFILE",
  "WINDIR",
]);
const osAdded = (name: string) =>
  name === "LC_CTYPE" ||
  name === "__CF_USER_TEXT_ENCODING" ||
  (process.platform === "win32" && WINDOWS_REQUIRED.has(name.toUpperCase()));

const testingDir = fileURLToPath(new URL("./testing/", import.meta.url));
const cleanup: (() => unknown)[] = [];
afterEach(async () => {
  for (const item of cleanup.splice(0).reverse()) await item();
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-mcp-"));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function readRecord(file: string): Record<string, unknown>[] {
  try {
    return readFileSync(file, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  } catch {
    return [];
  }
}

/** A plain child_process spawner standing in for the sandbox. */
function localSpawn(request: SpawnRequest): ChildHandle {
  const child = spawnChild(request.file, [...request.args], {
    cwd: request.cwd,
    env: { ...request.env },
    stdio: [request.stdin, "pipe", "pipe"],
  });
  if (request.onStderr) child.stderr?.on("data", request.onStderr);
  const exited = new Promise<{
    code: number | null;
    signal: string | null;
    timedOut: boolean;
    cancelled: boolean;
  }>((resolve) =>
    child.once("close", (code, signal) =>
      resolve({ code, signal, timedOut: false, cancelled: false }),
    ),
  );
  return {
    pid: child.pid,
    stdin: child.stdin,
    stdout: child.stdout,
    exited,
    terminate: () => {
      child.kill("SIGKILL");
    },
  };
}

const localRuntime: ProcessRuntime = {
  spawn: localSpawn,
  filterEnvironment: (env, allow, set) => {
    const output: Record<string, string> = {};
    for (const name of allow) {
      const value = env[name];
      if (value !== undefined) output[name] = value;
    }
    return { ...output, ...set };
  },
  sanitizeStderr: (text) => text,
};

function stdioServer(
  id: string,
  overrides: Partial<McpServerConfig> = {},
): McpServerConfig {
  return {
    id,
    transport: "stdio",
    module: "./fixture-server.mjs",
    args: [],
    env: { allow: [], set: {} },
    credential: "none",
    timeoutMs: 5000,
    startupTimeoutMs: 5000,
    retry: { attempts: 1 },
    required: false,
    tools: { allow: [], deny: [] },
    ...overrides,
  };
}

function httpServer(
  id: string,
  url: string,
  overrides: Partial<McpServerConfig> = {},
): McpServerConfig {
  return {
    ...stdioServer(id),
    transport: "streamable-http",
    module: undefined as unknown as string,
    url,
    ...overrides,
  };
}

const allowAll: McpAuthorize = async () => ({ allowed: true, reason: "ok" });

interface Harness {
  governor: McpGovernor;
  audit: McpAuditEvent[];
  spawned: SpawnRequest[];
}

function harness(
  options: Partial<McpGovernorOptions> & {
    servers: McpServerConfig[];
    runtime?: ProcessRuntime;
  },
): Harness {
  const audit: McpAuditEvent[] = [];
  const spawned: SpawnRequest[] = [];
  const runtime = options.runtime ?? localRuntime;
  const governor = new McpGovernor({
    authorize: allowAll,
    distributionDir: testingDir,
    workspace: tempDir(),
    fetch: (url, init) => fetch(url, init),
    audit: (event) => audit.push(event),
    retryDelayMs: 10,
    graceMs: 500,
    ...options,
    processRuntime: {
      ...runtime,
      spawn: (request) => {
        spawned.push(request);
        return runtime.spawn(request);
      },
    },
  });
  cleanup.push(() => governor.close());
  return { governor, audit, spawned };
}

describe("McpGovernor over stdio", () => {
  it("starts a server, lists paginated tools, filters them, and calls", async () => {
    const record = join(tempDir(), "calls.jsonl");
    const { governor, audit } = harness({
      servers: [
        stdioServer("docs", {
          args: ["--record", record, "--name", "acme-docs"],
          expectedServerName: "acme-docs",
          tools: { allow: ["search", "get_*"], deny: ["delete_document"] },
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report).toMatchObject({
      id: "docs",
      state: "healthy",
      protocolVersion: "2025-06-18",
      serverName: "acme-docs",
      tools: ["mcp__docs__search", "mcp__docs__get_document"],
    });
    expect(report?.withheld).toEqual([
      "delete_document",
      "slow",
      "echo_env",
      "big",
    ]);
    const tools = governor.tools();
    expect(tools.map((t) => t.name)).toEqual([
      "mcp__docs__search",
      "mcp__docs__get_document",
    ]);
    const search = tools[0];
    expect(search?.inputSchema).toMatchObject({ type: "object" });
    await expect(search?.call({ query: "billing" })).resolves.toEqual({
      text: "results for billing",
      isError: false,
      truncated: false,
    });
    const doc = await tools[1]?.call({ id: "7" });
    expect(doc?.text).toBe(
      "document 7\n[image content: image/png, 8 bytes omitted]",
    );
    const calls = readRecord(record).filter((r) => r.type === "call");
    expect(calls.map((c) => c.name)).toEqual(["search", "get_document"]);
    expect(audit.map((e) => e.event)).toEqual([
      "mcp.server.start",
      "mcp.call",
      "mcp.call",
    ]);
    expect(audit[1]).toMatchObject({
      resource: "docs:search",
      decision: "allowed",
      detail: { outcome: "ok" },
    });
    expect(JSON.stringify(audit)).not.toContain("billing");
  });

  it("never sends a tool call that policy denies", async () => {
    const record = join(tempDir(), "calls.jsonl");
    const authorize = vi.fn<McpAuthorize>(async (request) =>
      request.resource === "docs:delete_document"
        ? {
            allowed: false,
            reason: "deletes need review",
            decision: {
              effect: "deny",
              policyId: "acme@3",
              ruleId: "acme.mcp.delete",
              enforcement: "control-plane",
              action: "mcp.tool.call",
              resource: request.resource,
              layer: "distribution-enforced",
            },
          }
        : { allowed: true, reason: "ok" },
    );
    const { governor, audit } = harness({
      authorize,
      servers: [stdioServer("docs", { args: ["--record", record] })],
    });
    await governor.start();
    const remove = governor
      .tools()
      .find((t) => t.name === "mcp__docs__delete_document");
    const error = await remove
      ?.call({ id: "1" })
      .catch((e: unknown) => e as PiShipError);
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({ code: "MCP_DENIED" });
    expect(authorize).toHaveBeenLastCalledWith({
      action: "mcp.tool.call",
      resource: "docs:delete_document",
    });
    expect(readRecord(record).filter((r) => r.type === "call")).toEqual([]);
    expect(audit.at(-1)).toMatchObject({
      event: "mcp.denied",
      resource: "docs:delete_document",
      decision: "denied",
      policy: "acme@3",
      rule: "acme.mcp.delete",
      enforcement: "control-plane",
    });
    // An authorizer that throws also denies.
    authorize.mockImplementation(async () => {
      throw new Error("policy engine down");
    });
    await expect(
      governor.tools()[0]?.call({ query: "x" }),
    ).rejects.toMatchObject({ code: "MCP_DENIED" });
    expect(readRecord(record).filter((r) => r.type === "call")).toEqual([]);
  });

  it("does not expose or send tools denied by the server tool list", async () => {
    const record = join(tempDir(), "calls.jsonl");
    const { governor } = harness({
      servers: [
        stdioServer("docs", {
          args: ["--record", record],
          tools: { allow: [], deny: ["delete_*"] },
        }),
      ],
    });
    await governor.start();
    const names = governor.tools().map((t) => t.tool);
    expect(names).not.toContain("delete_document");
    expect(names).toContain("search");
    expect(readRecord(record).filter((r) => r.type === "call")).toEqual([]);
  });

  it("never spawns a denied server and reports it", async () => {
    const authorize = vi.fn<McpAuthorize>(async (request) => ({
      allowed: request.resource !== "blocked",
      reason: "server not approved",
    }));
    const { governor, spawned, audit } = harness({
      authorize,
      servers: [stdioServer("blocked"), stdioServer("docs")],
    });
    const reports = await governor.start();
    expect(reports.map((r) => [r.id, r.state])).toEqual([
      ["blocked", "denied"],
      ["docs", "healthy"],
    ]);
    expect(reports[0]).toMatchObject({
      reason: "server not approved",
      tools: [],
    });
    expect(spawned).toHaveLength(1);
    expect(spawned[0]?.args.at(0)).toContain("fixture-server.mjs");
    expect(audit[0]).toMatchObject({
      event: "mcp.denied",
      resource: "blocked",
      detail: { action: "mcp.server.start" },
    });
  });

  it("fails start without spawning anything when a required server is denied", async () => {
    const { governor, spawned } = harness({
      authorize: async (request) => ({
        allowed: request.resource !== "core",
        reason: "no",
      }),
      servers: [stdioServer("docs"), stdioServer("core", { required: true })],
    });
    await expect(governor.start()).rejects.toMatchObject({
      code: "MCP_DENIED",
    });
    expect(spawned).toEqual([]);
  });

  it("fails start and closes the others when a required server fails", async () => {
    const record = join(tempDir(), "calls.jsonl");
    const { governor } = harness({
      servers: [
        stdioServer("docs", { args: ["--record", record] }),
        stdioServer("core", { required: true, args: ["--exit", "2"] }),
      ],
    });
    await expect(governor.start()).rejects.toMatchObject({
      code: "MCP_UNHEALTHY",
    });
    expect(governor.tools()).toEqual([]);
    const pid = readRecord(record).find((r) => r.type === "start")
      ?.pid as number;
    await vi.waitFor(() => expect(alive(pid)).toBe(false));
  });

  it("marks an optional server failed without failing start", async () => {
    const { governor } = harness({
      servers: [
        stdioServer("docs"),
        stdioServer("extra", { args: ["--exit", "2"] }),
      ],
    });
    const reports = await governor.start();
    expect(reports.map((r) => [r.id, r.state])).toEqual([
      ["docs", "healthy"],
      ["extra", "failed"],
    ]);
    expect(reports[1]?.reason).toMatch(/exited \(code 2\)/);
    expect(governor.tools().every((t) => t.server === "docs")).toBe(true);
  });

  it("fails on an expectedServerName mismatch", async () => {
    const { governor } = harness({
      servers: [
        stdioServer("docs", {
          args: ["--name", "impostor"],
          expectedServerName: "acme-docs",
          retry: { attempts: 3 },
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report).toMatchObject({ state: "failed" });
    expect(report?.reason).toMatch(
      /identified as impostor, expected acme-docs/,
    );
  });

  it("rejects an unsupported protocol version and accepts 2024-11-05", async () => {
    const { governor } = harness({
      servers: [
        stdioServer("future", { args: ["--protocol", "2030-01-01"] }),
        stdioServer("old", { args: ["--protocol", "2024-11-05"] }),
      ],
    });
    const reports = await governor.start();
    expect(reports[0]).toMatchObject({ state: "failed" });
    expect(reports[0]?.reason).toMatch(
      /unsupported protocol version 2030-01-01/,
    );
    expect(reports[1]).toMatchObject({
      state: "healthy",
      protocolVersion: "2024-11-05",
    });
  });

  it("retries a failed start but never a tool call", async () => {
    const dir = tempDir();
    const counter = join(dir, "starts");
    const record = join(dir, "calls.jsonl");
    const { governor, spawned } = harness({
      servers: [
        stdioServer("flaky", {
          args: ["--fail-first", `${counter}:1`, "--record", record],
          retry: { attempts: 2 },
          timeoutMs: 150,
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report?.state).toBe("healthy");
    expect(spawned).toHaveLength(2);
    const slow = governor.tools().find((t) => t.tool === "slow");
    await expect(slow?.call({ ms: 2000 })).rejects.toMatchObject({
      code: "MCP_UNHEALTHY",
    });
    await vi.waitFor(() =>
      expect(readRecord(record).some((r) => r.type === "cancelled")).toBe(true),
    );
    expect(
      readRecord(record).filter((r) => r.type === "call" && r.name === "slow"),
    ).toHaveLength(1);
    expect(governor.health()[0]).toMatchObject({
      state: "degraded",
      reason: "tool slow timed out after 150 ms",
    });
  });

  it("does not retry beyond the configured attempts", async () => {
    const counter = join(tempDir(), "starts");
    const { governor, spawned } = harness({
      servers: [
        stdioServer("flaky", {
          args: ["--fail-first", `${counter}:5`],
          retry: { attempts: 2 },
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report?.state).toBe("failed");
    expect(spawned).toHaveLength(2);
  });

  it("times out a server that never initializes", async () => {
    const { governor } = harness({
      servers: [
        stdioServer("hang", {
          args: ["--hang-initialize"],
          startupTimeoutMs: 200,
        }),
      ],
    });
    const started = Date.now();
    const [report] = await governor.start();
    expect(report?.state).toBe("failed");
    expect(report?.reason).toMatch(/did not answer initialize within/);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("cancels a tool call through its AbortSignal", async () => {
    const record = join(tempDir(), "calls.jsonl");
    const { governor, audit } = harness({
      servers: [stdioServer("docs", { args: ["--record", record] })],
    });
    await governor.start();
    const slow = governor.tools().find((t) => t.tool === "slow");
    const controller = new AbortController();
    const pending = slow?.call({ ms: 5000 }, controller.signal);
    setTimeout(() => controller.abort(), 50);
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    await vi.waitFor(() =>
      expect(readRecord(record).filter((r) => r.type === "cancelled")).toEqual([
        { type: "cancelled", requestId: expect.any(Number) },
      ]),
    );
    expect(audit.at(-1)).toMatchObject({
      event: "mcp.call",
      detail: { outcome: "cancelled" },
    });
    expect(governor.health()[0]?.state).toBe("healthy");
  });

  it("redacts and bounds stderr in failure reports", async () => {
    const token = "sk-live-abcdefghijklmnop";
    const { governor } = harness({
      runtime: defaultProcessRuntime(),
      servers: [
        stdioServer("noisy", {
          args: [
            "--stderr",
            `boot failed with key ${token}\n${"noise ".repeat(2000)}`,
            "--exit",
            "3",
          ],
          // The exit must win: a loaded Windows runner can take longer than
          // the default startup deadline to start node and write stderr.
          startupTimeoutMs: 30_000,
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report?.state).toBe("failed");
    expect(report?.reason).toMatch(/exited \(code 3\)/);
    expect(report?.reason).toContain("stderr");
    expect((report?.reason ?? "").length).toBeLessThanOrEqual(1203);
    expect(JSON.stringify(governor.health())).not.toContain(token);
  }, 40_000);

  it("keeps the secret out of a short stderr tail", async () => {
    const token = "sk-live-abcdefghijklmnop";
    const { governor } = harness({
      runtime: defaultProcessRuntime(),
      servers: [
        stdioServer("noisy", {
          args: ["--stderr", `boot failed with key ${token}`, "--exit", "3"],
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report?.reason).toContain("boot failed with key [REDACTED]");
    expect(report?.reason).not.toContain(token);
  });

  it("closes idempotently and stops the child", async () => {
    const record = join(tempDir(), "calls.jsonl");
    const { governor } = harness({
      runtime: defaultProcessRuntime(),
      servers: [stdioServer("docs", { args: ["--record", record] })],
    });
    const [report] = await governor.start();
    expect(report?.state, report?.reason).toBe("healthy");
    const pid = readRecord(record).find((r) => r.type === "start")
      ?.pid as number;
    expect(alive(pid)).toBe(true);
    await Promise.all([governor.close(), governor.close()]);
    await governor.close();
    await vi.waitFor(() => expect(alive(pid)).toBe(false));
    expect(governor.tools()).toEqual([]);
  });
});

describe("McpGovernor with the sandbox process runtime", () => {
  it("passes only the filtered environment to the child", async () => {
    const { governor, spawned } = harness({
      runtime: defaultProcessRuntime(),
      env: {
        PATH: process.env.PATH ?? "",
        LANG: "C.UTF-8",
        ACME_API_TOKEN: "opaque-value-123456",
        UNRELATED: "x",
      },
      servers: [
        stdioServer("docs", {
          env: {
            allow: ["LANG", "ACME_API_TOKEN"],
            set: { DOCS_MODE: "demo" },
          },
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report?.state, report?.reason).toBe("healthy");
    const echo = governor.tools().find((t) => t.tool === "echo_env");
    const names = JSON.parse((await echo?.call({}))?.text ?? "[]") as string[];
    expect(names).toContain("LANG");
    expect(names).toContain("DOCS_MODE");
    expect(names).not.toContain("ACME_API_TOKEN");
    expect(names).not.toContain("UNRELATED");
    if (process.platform !== "win32") expect(names).not.toContain("PATH");
    expect(JSON.stringify(spawned)).not.toContain("opaque-value-123456");
  });
});

describe("McpGovernor environment filtering (test runtime)", () => {
  it("never inherits variables outside allow and set", async () => {
    const { governor } = harness({
      env: { LANG: "C", UNRELATED: "x", HOME: "/nowhere" },
      servers: [
        stdioServer("docs", {
          env: { allow: ["LANG"], set: { DOCS_MODE: "demo" } },
        }),
      ],
    });
    await governor.start();
    const echo = governor.tools().find((t) => t.tool === "echo_env");
    const names = JSON.parse((await echo?.call({}))?.text ?? "[]") as string[];
    expect(names.filter((n) => !osAdded(n))).toEqual(["DOCS_MODE", "LANG"]);
  });
});

describe("McpGovernor over Streamable HTTP", () => {
  for (const mode of ["json", "sse"] as const) {
    it(`initializes, keeps the session, and calls tools (${mode})`, async () => {
      const fixture = await startFixtureHttpServer({
        mode,
        serverName: "tickets",
      });
      cleanup.push(() => fixture.close());
      const { governor, spawned } = harness({
        servers: [
          httpServer("tickets", fixture.url, {
            expectedServerName: "tickets",
            tools: { allow: [], deny: ["delete_document"] },
          }),
        ],
      });
      const [report] = await governor.start();
      expect(report).toMatchObject({
        state: "healthy",
        transport: "streamable-http",
      });
      expect(spawned).toEqual([]);
      const search = governor.tools().find((t) => t.tool === "search");
      await expect(search?.call({ query: "q" })).resolves.toMatchObject({
        text: "results for q",
      });
      await governor.close();
      const [init, ...rest] = fixture.requests;
      expect(init).toMatchObject({
        method: "initialize",
        accept: "application/json, text/event-stream",
        sessionId: undefined,
        protocolVersion: undefined,
      });
      expect(rest.map((r) => r.method)).toEqual([
        "notifications/initialized",
        "tools/list",
        "tools/list",
        "tools/list",
        "tools/call",
      ]);
      for (const request of rest)
        expect(request).toMatchObject({
          sessionId: fixture.sessionId,
          protocolVersion: "2025-06-18",
        });
      expect(fixture.deleted).toEqual([fixture.sessionId]);
      expect(fixture.calls.map((c: { name: string }) => c.name)).toEqual([
        "search",
      ]);
    });
  }

  it("sends the runtime bearer and never leaks it", async () => {
    const token = "runtime-bearer-7f3a9c2e1d";
    const fixture = await startFixtureHttpServer({ bearer: token });
    cleanup.push(() => fixture.close());
    const good = harness({
      credential: async () => new SecretValue(token),
      credentialOrigins: [fixture.url],
      servers: [httpServer("tickets", fixture.url, { credential: "runtime" })],
    });
    expect((await good.governor.start())[0]?.state).toBe("healthy");
    expect(fixture.requests.every((r) => r.authorized === true)).toBe(true);

    const wrong = "wrong-bearer-0a1b2c3d4e";
    const bad = harness({
      credential: async () => wrong,
      credentialOrigins: [new URL(fixture.url).origin],
      servers: [
        httpServer("tickets", fixture.url, {
          credential: "runtime",
          required: true,
          retry: { attempts: 2 },
        }),
      ],
    });
    const error = await bad.governor
      .start()
      .catch((e: unknown) => e as PiShipError);
    expect(error).toMatchObject({ code: "MCP_UNHEALTHY" });
    const surfaces = JSON.stringify([
      (error as PiShipError).toJSON(),
      String(error),
      bad.governor.health(),
      bad.audit,
      good.audit,
    ]);
    expect(surfaces).toContain("HTTP 401");
    expect(surfaces).not.toContain(token);
    expect(surfaces).not.toContain(wrong);
  });

  it("sends the runtime bearer only to the inference gateway origin", async () => {
    const credential = vi.fn(async () => "gateway-bearer-5e6f7a8b9c");
    const fixture = await startFixtureHttpServer({});
    cleanup.push(() => fixture.close());
    const other = new URL(fixture.url);
    other.hostname = "localhost";
    for (const credentialOrigins of [
      ["https://gateway.acme.example/v1"],
      [],
      undefined,
    ]) {
      const { governor } = harness({
        credential,
        ...(credentialOrigins ? { credentialOrigins } : {}),
        servers: [
          httpServer("tickets", fixture.url, { credential: "runtime" }),
        ],
      });
      const [report] = await governor.start();
      expect(report).toMatchObject({ state: "failed" });
      expect(report?.reason).toContain("runtime credential is only sent to");
    }
    // The same port on another host name is another origin: still refused.
    const { governor } = harness({
      credential,
      credentialOrigins: [other.origin],
      servers: [
        httpServer("tickets", fixture.url, {
          credential: "runtime",
          required: true,
        }),
      ],
    });
    await expect(governor.start()).rejects.toMatchObject({
      code: "MCP_UNHEALTHY",
    });
    expect(credential).not.toHaveBeenCalled();
    expect(fixture.requests).toEqual([]);
  });

  it("does not bind the credential to a server without credential: runtime", async () => {
    const credential = vi.fn(async () => "never-sent-credential-1234");
    const fixture = await startFixtureHttpServer({});
    cleanup.push(() => fixture.close());
    const { governor } = harness({
      credential,
      servers: [httpServer("open", fixture.url)],
    });
    await governor.start();
    expect(credential).not.toHaveBeenCalled();
  });

  it("fails a runtime-credential server when no credential is available", async () => {
    const { governor } = harness({
      servers: [
        httpServer("tickets", "http://127.0.0.1:9/mcp", {
          credential: "runtime",
        }),
      ],
    });
    const [report] = await governor.start();
    expect(report).toMatchObject({ state: "failed" });
    expect(report?.reason).toMatch(/runtime credential/);
  });

  it("resolves the url just before connecting", async () => {
    const fixture = await startFixtureHttpServer({});
    cleanup.push(() => fixture.close());
    const resolveUrl = vi.fn((server: McpServerConfig) =>
      (server.url ?? "").replace(`\${TICKETS_URL}`, fixture.url),
    );
    const { governor } = harness({
      resolveUrl,
      servers: [httpServer("tickets", `\${TICKETS_URL}`, { required: true })],
    });
    const [report] = await governor.start();
    expect(report?.state).toBe("healthy");
    expect(resolveUrl).toHaveBeenCalledWith(
      expect.objectContaining({ id: "tickets", url: `\${TICKETS_URL}` }),
    );
    expect(fixture.requests.length).toBeGreaterThan(0);
  });

  it("fails an unresolvable url: CONFIG_UNAVAILABLE when required, unhealthy when optional", async () => {
    const resolveUrl = () => {
      throw new Error("Runtime variable TICKETS_URL is not set");
    };
    const optional = harness({
      resolveUrl,
      servers: [
        httpServer("tickets", `\${TICKETS_URL}`, { retry: { attempts: 3 } }),
      ],
    });
    const [report] = await optional.governor.start();
    expect(report).toMatchObject({ state: "failed", required: false });
    expect(report?.reason).toContain("TICKETS_URL is not set");
    // Starting the server was attempted once: the environment will not change.
    expect(optional.audit).toContainEqual(
      expect.objectContaining({
        event: "mcp.server.start",
        detail: expect.objectContaining({ state: "failed", attempts: 1 }),
      }),
    );
    const required = harness({
      resolveUrl,
      servers: [httpServer("tickets", `\${TICKETS_URL}`, { required: true })],
    });
    const error = await required.governor
      .start()
      .catch((e: unknown) => e as PiShipError);
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({ code: "CONFIG_UNAVAILABLE" });
    expect((error as PiShipError).message).toContain("TICKETS_URL is not set");
  });

  it("does not follow redirects", async () => {
    const fixture = await startFixtureHttpServer({ redirect: true });
    cleanup.push(() => fixture.close());
    const { governor } = harness({
      servers: [httpServer("moved", fixture.url)],
    });
    const [report] = await governor.start();
    expect(report?.reason).toMatch(/redirects are not followed/);
  });

  it("rejects an unsupported protocol version over HTTP", async () => {
    const fixture = await startFixtureHttpServer({
      protocolVersion: "2023-01-01",
    });
    cleanup.push(() => fixture.close());
    const { governor } = harness({
      servers: [httpServer("old", fixture.url)],
    });
    const [report] = await governor.start();
    expect(report?.state).toBe("failed");
    expect(report?.reason).toMatch(/unsupported protocol version/);
  });
});

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
