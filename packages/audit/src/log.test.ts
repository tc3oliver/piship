import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NO_CONTENT_CAPTURE, PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AUDIT_FAILURE_MATRIX,
  type AuditConfig,
  AuditLog,
  type AuditSinkConfig,
  describeAuditStatus,
  formatAuditFailureMatrix,
} from "./index.js";

const posix = process.platform !== "win32";
/** A `${NAME}` runtime reference. */
const ref = (name: string) => `$\{${name}}`;
let temp: string;
let server: Server | undefined;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-audit-"));
});
afterEach(async () => {
  rmSync(temp, { recursive: true, force: true });
  if (server) await new Promise((resolve) => server?.close(resolve));
  server = undefined;
});

function config(
  sinks: AuditSinkConfig[],
  maxEvents = 100,
  flushIntervalMs = 0,
): AuditConfig {
  return {
    enabled: true,
    sinks,
    buffer: { maxEvents, flushIntervalMs },
    capture: NO_CONTENT_CAPTURE,
  };
}

interface Collector {
  url: string;
  batches: { schema: string; events: { event: string }[] }[];
  requests: { method?: string; contentType?: string }[];
  /** Status to answer with; 0 destroys the socket. */
  status: number;
  delayMs: number;
}

async function startCollector(): Promise<Collector> {
  const collector: Collector = {
    url: "",
    batches: [],
    requests: [],
    status: 200,
    delayMs: 0,
  };
  server = createServer(
    (request: IncomingMessage, response: ServerResponse) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        const answer = () => {
          collector.requests.push({
            ...(request.method ? { method: request.method } : {}),
            ...(request.headers["content-type"]
              ? { contentType: request.headers["content-type"] }
              : {}),
          });
          if (collector.status === 0) {
            request.socket.destroy();
            return;
          }
          if (collector.status >= 200 && collector.status < 300)
            collector.batches.push(
              JSON.parse(Buffer.concat(chunks).toString()),
            );
          response.statusCode = collector.status;
          if (collector.status === 302)
            response.setHeader("location", "http://127.0.0.1:1/elsewhere");
          response.end();
        };
        if (collector.delayMs) setTimeout(answer, collector.delayMs);
        else answer();
      });
    },
  );
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  collector.url = `http://127.0.0.1:${port}/ingest?route=audit`;
  return collector;
}

function events(collector: Collector): string[] {
  return collector.batches.flatMap((batch) =>
    batch.events.map((item) => item.event),
  );
}

describe("AuditLog file sink", () => {
  it("appends one JSON line per event with owner-only permissions", async () => {
    const log = await AuditLog.open({
      config: config([{ id: "local", type: "file", required: true }]),
      distribution: "acmecode",
      stateDir: temp,
    });
    log.emit({ event: "session.start", user: "alice", session: "s1" });
    log.emit({
      event: "tool.denied",
      user: "alice",
      session: "s1",
      resource: "bash",
    });
    await log.flush();
    const path = join(temp, "logs", "audit.jsonl");
    const lines = readFileSync(path, "utf8").trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    const parsed = lines.map((line) => JSON.parse(line));
    expect(parsed.map((item) => item.event)).toEqual([
      "session.start",
      "tool.denied",
    ]);
    expect(parsed[0]).toMatchObject({
      schema: "piship-audit/v1",
      distribution: "acmecode",
    });
    if (posix) {
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(statSync(join(temp, "logs")).mode & 0o777).toBe(0o700);
    }
    log.emit({ event: "session.end", user: "alice", session: "s1" });
    const status = await log.close();
    expect(readFileSync(path, "utf8").trimEnd().split("\n")).toHaveLength(3);
    expect(status.sinks[0]).toMatchObject({
      delivered: 3,
      pending: 0,
      dropped: 0,
    });
  });

  it("tightens permissions on an existing log file", async () => {
    if (!posix) return;
    const path = join(temp, "logs", "audit.jsonl");
    const log = await AuditLog.open({
      config: config([{ id: "local", type: "file", required: false }]),
      distribution: "acmecode",
      stateDir: temp,
    });
    await log.close();
    writeFileSync(path, "", { mode: 0o644 });
    const { chmodSync } = await import("node:fs");
    chmodSync(path, 0o644);
    const reopened = await AuditLog.open({
      config: config([{ id: "local", type: "file", required: false }]),
      distribution: "acmecode",
      stateDir: temp,
    });
    expect(statSync(path).mode & 0o777).toBe(0o600);
    await reopened.close();
  });

  it("fails launch when a required file sink cannot be opened", async () => {
    const blocked = join(temp, "blocked");
    writeFileSync(blocked, "not a directory");
    await expect(
      AuditLog.open({
        config: config([{ id: "local", type: "file", required: true }]),
        distribution: "acmecode",
        stateDir: blocked,
      }),
    ).rejects.toMatchObject({ code: "AUDIT_UNAVAILABLE" });
  });

  it("starts degraded when an optional file sink cannot be opened", async () => {
    const blocked = join(temp, "blocked");
    writeFileSync(blocked, "not a directory");
    const log = await AuditLog.open({
      config: config([{ id: "local", type: "file", required: false }]),
      distribution: "acmecode",
      stateDir: blocked,
    });
    expect(log.status().state).toBe("degraded");
    log.emit({ event: "session.start", user: null, session: null });
    await log.flush();
    expect(log.status().sinks[0]).toMatchObject({ dropped: 1, pending: 0 });
    expect(() => log.assertAvailable()).not.toThrow();
    await log.close();
  });
});

describe("AuditLog http sink", () => {
  it("batches events as piship-audit-batch/v1 JSON through the injected fetch", async () => {
    const collector = await startCollector();
    const calls: string[] = [];
    const log = await AuditLog.open({
      config: config([
        { id: "company", type: "http", url: ref("AUDIT_URL"), required: true },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch: (url, init) => {
        calls.push(String(url));
        return fetch(url, init);
      },
      resolveUrl: (template) =>
        template === ref("AUDIT_URL") ? collector.url : template,
    });
    // Readiness probe: one empty batch at open.
    expect(collector.batches).toEqual([
      { schema: "piship-audit-batch/v1", events: [] },
    ]);
    log.emit({ event: "session.start", user: "alice", session: "s1" });
    log.emit({ event: "model.request", user: "alice", session: "s1" });
    log.emit({ event: "session.end", user: "alice", session: "s1" });
    await log.flush();
    expect(collector.batches).toHaveLength(2);
    expect(collector.batches[1]?.schema).toBe("piship-audit-batch/v1");
    expect(events(collector)).toEqual([
      "session.start",
      "model.request",
      "session.end",
    ]);
    expect(collector.requests.every((item) => item.method === "POST")).toBe(
      true,
    );
    expect(collector.requests[1]?.contentType).toBe("application/json");
    expect(calls.every((url) => url === collector.url)).toBe(true);
    expect(log.status()).toMatchObject({ state: "ok" });
    await log.close();
  });

  it("flushes periodically on the configured interval", async () => {
    const collector = await startCollector();
    const log = await AuditLog.open({
      config: config(
        [{ id: "company", type: "http", url: collector.url, required: false }],
        100,
        20,
      ),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    log.emit({ event: "session.start", user: null, session: null });
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(events(collector)).toEqual(["session.start"]);
    await log.close();
  });

  it("rejects credentials in the sink url and unresolved references", async () => {
    await expect(
      AuditLog.open({
        config: config([
          {
            id: "company",
            type: "http",
            url: "https://user:pw@audit.example/ingest",
            required: true,
          },
        ]),
        distribution: "acmecode",
        stateDir: temp,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    await expect(
      AuditLog.open({
        config: config([
          { id: "company", type: "http", url: ref("MISSING"), required: true },
        ]),
        distribution: "acmecode",
        stateDir: temp,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "AUDIT_UNAVAILABLE" });
  });

  it("fails launch when a required http sink is unreachable at open", async () => {
    const collector = await startCollector();
    collector.status = 503;
    const error = await AuditLog.open({
      config: config([
        { id: "company", type: "http", url: collector.url, required: true },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    expect((error as Error).message).toContain("HTTP 503");
    expect((error as Error).message).not.toContain("route=audit");
  });

  it("treats redirects as failures and never follows them", async () => {
    const collector = await startCollector();
    collector.status = 302;
    await expect(
      AuditLog.open({
        config: config([
          { id: "company", type: "http", url: collector.url, required: true },
        ]),
        distribution: "acmecode",
        stateDir: temp,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    expect(collector.requests).toHaveLength(1);
  });

  it("drops and counts events when an optional sink is down, and keeps working", async () => {
    const collector = await startCollector();
    const states: string[] = [];
    const log = await AuditLog.open({
      config: config([
        { id: "local", type: "file", required: false },
        { id: "company", type: "http", url: collector.url, required: false },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
      onStateChange: (state) => states.push(state),
    });
    collector.status = 500;
    log.emit({ event: "tool.request", user: null, session: null });
    log.emit({ event: "tool.allowed", user: null, session: null });
    await log.flush();
    const status = log.status();
    expect(status.state).toBe("degraded");
    const http = status.sinks.find((sink) => sink.id === "company");
    expect(http).toMatchObject({ state: "degraded", dropped: 2, pending: 0 });
    expect(http?.lastError).toContain("HTTP 500");
    expect(status.sinks.find((sink) => sink.id === "local")).toMatchObject({
      state: "ok",
      delivered: 2,
    });
    expect(() => log.assertAvailable()).not.toThrow();
    expect(describeAuditStatus(status).join("\n")).toContain("dropped 2");

    collector.status = 200;
    log.emit({ event: "tool.denied", user: null, session: null });
    await log.flush();
    expect(events(collector)).toEqual(["tool.denied"]);
    expect(log.status().state).toBe("ok");
    expect(states).toEqual(["degraded", "ok"]);
    await log.close();
  });

  it("retains events for a required sink during an outage and delivers them on recovery", async () => {
    const collector = await startCollector();
    const log = await AuditLog.open({
      config: config(
        [{ id: "company", type: "http", url: collector.url, required: true }],
        10,
      ),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    collector.status = 0;
    for (let index = 0; index < 4; index += 1)
      log.emit({
        event: "mcp.call",
        user: null,
        session: null,
        resource: `docs:t${index}`,
      });
    await log.flush();
    expect(log.status()).toMatchObject({
      state: "degraded",
      sinks: [{ state: "degraded", pending: 4, dropped: 0 }],
    });
    expect(() => log.assertAvailable()).not.toThrow();
    collector.status = 200;
    await log.flush();
    expect(events(collector)).toHaveLength(4);
    expect(log.status()).toMatchObject({
      state: "ok",
      sinks: [{ state: "ok", pending: 0, dropped: 0, delivered: 4 }],
    });
    await log.close();
  });

  it("enters failed when a required sink stays down until the buffer is full", async () => {
    const collector = await startCollector();
    const log = await AuditLog.open({
      config: config(
        [{ id: "company", type: "http", url: collector.url, required: true }],
        5,
      ),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    collector.status = 503;
    for (let index = 0; index < 5; index += 1)
      log.emit({ event: "tool.request", user: null, session: null });
    await log.flush();
    expect(log.status().state).toBe("degraded");
    log.emit({ event: "tool.request", user: null, session: null });
    expect(log.status()).toMatchObject({
      state: "failed",
      sinks: [{ state: "failed", pending: 5, dropped: 1 }],
    });
    expect(() => log.assertAvailable()).toThrow(PiShipError);
    try {
      log.assertAvailable();
    } catch (error) {
      expect(error).toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    }
    expect(describeAuditStatus(log.status()).join("\n")).toMatch(/fail closed/);
    // Emission itself never throws.
    expect(() =>
      log.emit({ event: "tool.denied", user: null, session: null }),
    ).not.toThrow();
    // Recovery drains the buffer and clears the failure.
    collector.status = 200;
    await log.flush();
    expect(log.status().state).toBe("ok");
    expect(() => log.assertAvailable()).not.toThrow();
    await log.close();
  });

  it("close() flushes pending events and respects its deadline", async () => {
    const collector = await startCollector();
    const log = await AuditLog.open({
      config: config([
        { id: "company", type: "http", url: collector.url, required: true },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    log.emit({ event: "session.end", user: null, session: null });
    const flushed = await log.close(2_000);
    expect(flushed.sinks[0]).toMatchObject({ delivered: 1, pending: 0 });
    expect(events(collector)).toEqual(["session.end"]);
    // Emission after close is ignored.
    log.emit({ event: "session.start", user: null, session: null });
    expect(log.status().sinks[0]?.pending).toBe(0);

    const slow = await AuditLog.open({
      config: config([
        { id: "company", type: "http", url: collector.url, required: true },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    collector.delayMs = 2_000;
    slow.emit({ event: "session.end", user: null, session: null });
    const started = Date.now();
    const status = await slow.close(100);
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(status.sinks[0]?.delivered).toBe(0);
    expect(status.sinks[0]?.pending).toBe(1);
  });
});

describe("AuditLog disabled and emission safety", () => {
  it("is a no-op with state disabled", async () => {
    const log = await AuditLog.open({
      config: { ...config([]), enabled: false },
      distribution: "acmecode",
      stateDir: temp,
    });
    log.emit({ event: "session.start", user: null, session: null });
    await log.flush();
    expect(log.status()).toEqual({ state: "disabled", sinks: [], rejected: 0 });
    expect(() => log.assertAvailable()).not.toThrow();
    expect(describeAuditStatus(log.status())).toEqual(["audit: disabled"]);
    await log.close();
  });

  it("counts malformed emissions instead of throwing", async () => {
    const log = await AuditLog.open({
      config: config([{ id: "local", type: "file", required: false }]),
      distribution: "acmecode",
      stateDir: temp,
    });
    expect(() =>
      log.emit({ event: "made.up" as never, user: null, session: null }),
    ).not.toThrow();
    expect(() => log.emit(null as never)).not.toThrow();
    expect(log.status().rejected).toBe(2);
    await log.close();
  });

  it("documents the failure matrix", () => {
    expect(AUDIT_FAILURE_MATRIX.length).toBeGreaterThan(4);
    const text = formatAuditFailureMatrix();
    expect(text).toContain("AUDIT_UNAVAILABLE");
    expect(text.split("\n")).toHaveLength(AUDIT_FAILURE_MATRIX.length);
  });
});
