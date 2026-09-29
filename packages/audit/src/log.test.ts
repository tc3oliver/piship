import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
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
  AUDIT_ROTATION,
  type AuditConfig,
  AuditLog,
  type AuditSinkConfig,
  auditLogFiles,
  describeAuditStatus,
  formatAuditFailureMatrix,
  requiredAuditLoss,
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

describe("AuditLog file sink retention", () => {
  const sink = [{ id: "local", type: "file", required: false }] as const;
  const lines = (path: string) =>
    existsSync(path)
      ? readFileSync(path, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as { resource: string })
      : [];

  it("uses fixed defaults of 10 MB and five rotated files", () => {
    expect(AUDIT_ROTATION).toEqual({ maxBytes: 10 * 1024 * 1024, files: 5 });
  });

  it("rotates by size, keeps the configured files, and never loses a retained line", async () => {
    const log = await AuditLog.open({
      config: config([...sink], 1000),
      distribution: "acmecode",
      stateDir: temp,
      rotation: { maxBytes: 600, files: 2 },
    });
    // Each flush is one append of about 250 bytes.
    for (let index = 0; index < 12; index += 1) {
      log.emit({ event: "resource.load", resource: `r${index}` });
      await log.flush();
    }
    await log.close();
    const base = join(temp, "logs", "audit.jsonl");
    expect(auditLogFiles(temp, { maxBytes: 600, files: 2 })).toEqual([
      base,
      `${base}.1`,
      `${base}.2`,
    ]);
    expect(existsSync(`${base}.3`)).toBe(false);
    for (const path of [base, `${base}.1`, `${base}.2`])
      expect(statSync(path).size).toBeLessThanOrEqual(600);
    // Oldest to newest, the retained events are contiguous and end with the last.
    const kept = [`${base}.2`, `${base}.1`, base].flatMap((path) =>
      lines(path).map((line) => Number(line.resource.slice(1))),
    );
    expect(kept.at(-1)).toBe(11);
    expect(kept).toEqual(
      Array.from({ length: kept.length }, (_, i) => 12 - kept.length + i),
    );
    if (posix)
      for (const path of [base, `${base}.1`])
        expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("does not rotate twice when another writer already rotated", async () => {
    // Nine rotated files hold more than the twelve events written, so no event
    // leaves through retention however the two writers interleave. A writer
    // that loses the rotation lock appends anyway, so how many events each
    // file holds depends on timing; only the properties below do not.
    // Taken over once seen unchanged for the stale interval (monotonic),
    // however old its mtime looks.
    const rotation = { maxBytes: 400, files: 9, lockStaleMs: 100 };
    const open = () =>
      AuditLog.open({
        config: config([...sink], 1000),
        distribution: "acmecode",
        stateDir: temp,
        rotation,
      });
    const [first, second] = await Promise.all([open(), open()]);
    for (let round = 0; round < 6; round += 1) {
      first.emit({ event: "resource.load", resource: `a${round}` });
      second.emit({ event: "resource.load", resource: `b${round}` });
      await Promise.all([first.flush(), second.flush()]);
    }
    await Promise.all([first.close(), second.close()]);
    const base = join(temp, "logs", "audit.jsonl");
    const files = auditLogFiles(temp, rotation);
    const all = files.flatMap((path) =>
      lines(path).map((line) => line.resource),
    );
    expect(all.sort()).toEqual(
      [0, 1, 2, 3, 4, 5].flatMap((i) => [`a${i}`, `b${i}`]).sort(),
    );
    // An event is about 156 bytes against a 400 byte limit, so a file is
    // rotated only once it holds two events. A second rotation of the file
    // another writer just started would leave a rotated file with one.
    for (const path of files.slice(1))
      expect(lines(path).length).toBeGreaterThanOrEqual(2);
    expect(existsSync(`${base}.rotate.lock`)).toBe(false);
  });

  it("takes over a stale rotation lock once, even with concurrent writers", async () => {
    mkdirSync(join(temp, "logs"), { recursive: true });
    const base = join(temp, "logs", "audit.jsonl");
    const lock = `${base}.rotate.lock`;
    writeFileSync(lock, "crashed\n");
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock, old, old);
    // Taken over once seen unchanged for the stale interval (monotonic),
    // however old its mtime looks.
    const rotation = { maxBytes: 400, files: 9, lockStaleMs: 100 };
    const open = () =>
      AuditLog.open({
        config: config([...sink], 1000),
        distribution: "acmecode",
        stateDir: temp,
        rotation,
      });
    const writers = await Promise.all([open(), open(), open()]);
    for (let round = 0; round < 3; round += 1) {
      for (const [index, log] of writers.entries())
        log.emit({ event: "resource.load", resource: `w${index}-${round}` });
      await Promise.all(writers.map((log) => log.flush()));
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
    await Promise.all(writers.map((log) => log.close()));
    // Rotated despite the abandoned lock; no lock or takeover file is left.
    expect(existsSync(`${base}.1`)).toBe(true);
    expect(
      readdirSync(join(temp, "logs")).filter((name) => name.includes("lock")),
    ).toEqual([]);
    const all = auditLogFiles(temp, rotation).flatMap((path) =>
      lines(path).map((line) => line.resource),
    );
    expect(all.sort()).toEqual(
      [0, 1, 2].flatMap((w) => [0, 1, 2].map((r) => `w${w}-${r}`)).sort(),
    );
  });

  it("appends without rotating while a live rotation lock is held", async () => {
    mkdirSync(join(temp, "logs"), { recursive: true });
    const base = join(temp, "logs", "audit.jsonl");
    writeFileSync(`${base}.rotate.lock`, "1\n");
    const log = await AuditLog.open({
      config: config([...sink], 1000),
      distribution: "acmecode",
      stateDir: temp,
      rotation: { maxBytes: 300, files: 2 },
    });
    for (let index = 0; index < 3; index += 1) {
      log.emit({ event: "resource.load", resource: `r${index}` });
      await log.flush();
    }
    await log.close();
    expect(existsSync(`${base}.1`)).toBe(false);
    expect(lines(base).map((line) => line.resource)).toEqual([
      "r0",
      "r1",
      "r2",
    ]);
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

  it("resends a batch the collector stored but did not acknowledge with the same event ids", async () => {
    // Fault injection: the collector stores the first batch, then fails the
    // request (as a timeout after the write would); PiShip retries it.
    const received: { id: string; event: string }[][] = [];
    let failures = 1;
    const log = await AuditLog.open({
      config: config([
        {
          id: "company",
          type: "http",
          url: "https://audit.example/ingest",
          required: true,
        },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch: async (_url, init) => {
        received.push(JSON.parse(String(init?.body)).events);
        if (received.length > 1 && failures-- > 0)
          return new Response(null, { status: 504 });
        return new Response(null, { status: 200 });
      },
    });
    log.emit({ event: "tool.request", user: null, session: null });
    log.emit({ event: "tool.allowed", user: null, session: null });
    await log.flush();
    expect(log.status().sinks[0]).toMatchObject({ pending: 2, delivered: 0 });
    await log.flush();
    expect(log.status().sinks[0]).toMatchObject({ pending: 0, delivered: 2 });
    await log.close();
    const [, first, second] = received;
    expect(second).toEqual(first);
    // A receiver that keeps one row per id stores each event once.
    const stored = new Map(
      received.flat().map((event) => [event.id, event.event]),
    );
    expect([...stored.values()]).toEqual(["tool.request", "tool.allowed"]);
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
    expect(requiredAuditLoss(flushed)).toBeUndefined();
    // Emission after close is never delivered, so it counts as dropped.
    log.emit({ event: "session.start", user: null, session: null });
    expect(log.status()).toMatchObject({
      state: "failed",
      sinks: [{ pending: 0, dropped: 1 }],
    });
    expect(requiredAuditLoss(log.status())).toMatchObject({
      code: "AUDIT_UNAVAILABLE",
    });

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
    expect(requiredAuditLoss(status, "The session ended")?.message).toMatch(
      /^The session ended: 1 audit event\(s\) were not delivered to required audit sink company \(1 pending, 0 dropped/,
    );
  });

  it("close() retries a required sink that fails during shutdown until the deadline", async () => {
    const collector = await startCollector();
    const log = await AuditLog.open({
      config: config([
        { id: "company", type: "http", url: collector.url, required: true },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    // Fault injection: the collector is down when the final flush starts and
    // comes back a moment later.
    collector.status = 503;
    log.emit({ event: "session.end", user: null, session: null });
    setTimeout(() => {
      collector.status = 200;
    }, 300);
    const status = await log.close(3_000);
    expect(status.sinks[0]).toMatchObject({ delivered: 1, pending: 0 });
    expect(requiredAuditLoss(status)).toBeUndefined();
    expect(events(collector)).toEqual(["session.end"]);
  });

  it("reports a required sink that stays down through close without leaking its url", async () => {
    const collector = await startCollector();
    const log = await AuditLog.open({
      config: config([
        { id: "company", type: "http", url: collector.url, required: true },
        { id: "local", type: "file", required: false },
      ]),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    collector.status = 500;
    log.emit({ event: "tool.allowed", user: null, session: null });
    log.emit({ event: "session.end", user: null, session: null });
    const started = Date.now();
    const status = await log.close(1_000);
    expect(Date.now() - started).toBeLessThan(4_000);
    // Retried until the deadline, not just once.
    expect(collector.requests.length).toBeGreaterThan(2);
    expect(status.sinks).toMatchObject([
      { id: "company", pending: 2, delivered: 0 },
      { id: "local", pending: 0, delivered: 2 },
    ]);
    const loss = requiredAuditLoss(status);
    expect(loss).toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    expect(loss?.message).toContain("2 audit event(s)");
    expect(loss?.message).toContain("HTTP 500");
    expect(JSON.stringify(loss?.toJSON())).not.toContain("route=audit");
  });

  it("does not report optional sinks that drop events as a required loss", async () => {
    const collector = await startCollector();
    collector.status = 0;
    const log = await AuditLog.open({
      config: config(
        [{ id: "company", type: "http", url: collector.url, required: false }],
        2,
      ),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    for (let index = 0; index < 4; index += 1)
      log.emit({ event: "tool.request", user: null, session: null });
    const status = await log.close(500);
    expect(status.sinks[0]?.dropped).toBe(4);
    expect(requiredAuditLoss(status)).toBeUndefined();
  });

  it("reports events a full required buffer dropped, even after the sink recovers", async () => {
    const collector = await startCollector();
    const log = await AuditLog.open({
      config: config(
        [{ id: "company", type: "http", url: collector.url, required: true }],
        2,
      ),
      distribution: "acmecode",
      stateDir: temp,
      fetch,
    });
    collector.status = 503;
    for (let index = 0; index < 3; index += 1)
      log.emit({ event: "tool.request", user: null, session: null });
    collector.status = 200;
    const status = await log.close(2_000);
    expect(status.sinks[0]).toMatchObject({ pending: 0, dropped: 1 });
    expect(requiredAuditLoss(status)?.message).toContain("1 dropped");
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
