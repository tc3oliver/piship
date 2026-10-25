import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { NO_CONTENT_CAPTURE, PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AUDIT_SPOOL_DIRECTORY,
  type AuditConfig,
  type AuditFetch,
  AuditLog,
  type AuditLogOptions,
} from "./index.js";

const posix = process.platform !== "win32";
let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-spool-"));
});
afterEach(() => {
  if (posix) for (const path of spoolFiles()) chmodSync(dirname(path), 0o700);
  rmSync(temp, { recursive: true, force: true });
});

interface Collector {
  fetch: AuditFetch;
  /** Every event of every batch received, delivered or not. */
  received: { id: string; resource?: string }[];
  /** Status to answer non-empty batches with (the readiness probe always passes). */
  status: number;
}

function collector(): Collector {
  const state: Collector = {
    received: [],
    status: 200,
    fetch: async (_url, init) => {
      const { events } = JSON.parse(String(init?.body));
      if (!events.length) return new Response(null, { status: 200 });
      if (state.status !== 200)
        return new Response(null, { status: state.status });
      state.received.push(...events);
      return new Response(null, { status: 200 });
    },
  };
  return state;
}

function config(required = true, maxEvents = 100): AuditConfig {
  return {
    enabled: true,
    sinks: [
      { id: "company", type: "http", url: "https://audit.example/e", required },
    ],
    buffer: { maxEvents, flushIntervalMs: 0 },
    capture: NO_CONTENT_CAPTURE,
  };
}

function open(
  target: Collector,
  options: Partial<AuditLogOptions> = {},
): Promise<AuditLog> {
  return AuditLog.open({
    config: config(),
    distribution: "acmecode",
    stateDir: temp,
    fetch: target.fetch,
    ...options,
  });
}

function emit(log: AuditLog, resource: string): void {
  log.emit({ event: "mcp.call", user: null, session: null, resource });
}

function spoolFiles(): string[] {
  const root = join(temp, AUDIT_SPOOL_DIRECTORY);
  if (!existsSync(root)) return [];
  return readdirSync(root).flatMap((key) =>
    readdirSync(join(root, key)).map((name) => join(root, key, name)),
  );
}

/** The ID of a process that has exited. */
function deadPid(): number {
  const { pid } = spawnSync(process.execPath, ["-e", ""]);
  return pid as number;
}

/** Make a spool look as if `pid` (on this host) wrote it and then died or lives on. */
function reown(path: string, pid: number): string {
  const target = join(
    dirname(path),
    basename(path).replace(/^\d+/, String(pid)),
  );
  renameSync(path, target);
  return target;
}

/** Emit `resources` while the collector is down and abandon the log, as a crash would. */
async function crashWith(resources: string[]): Promise<string> {
  const target = collector();
  const log = await open(target);
  target.status = 503;
  for (const resource of resources) emit(log, resource);
  await log.flush();
  expect(log.status().sinks[0]?.pending).toBe(resources.length);
  const file = spoolFiles().find((path) =>
    basename(path).startsWith(`${process.pid}-`),
  );
  return reown(file as string, deadPid());
}

describe("required HTTP sink spool", () => {
  it("replays a crashed process's events in order at the next launch and then removes them", async () => {
    await crashWith(["a", "b", "c"]);
    const target = collector();
    const log = await open(target);
    await log.flush();
    expect(target.received.map((event) => event.resource)).toEqual([
      "a",
      "b",
      "c",
    ]);
    emit(log, "d");
    await log.flush();
    expect(target.received.map((event) => event.resource)).toEqual([
      "a",
      "b",
      "c",
      "d",
    ]);
    const status = await log.close();
    expect(status.sinks[0]).toMatchObject({ pending: 0, delivered: 4 });
    expect(spoolFiles()).toEqual([]);
  });

  it("keeps undelivered events spooled at close and delivers them once", async () => {
    const down = collector();
    const first = await open(down);
    down.status = 503;
    emit(first, "kept");
    const status = await first.close(50);
    expect(status.sinks[0]?.pending).toBe(1);
    expect(spoolFiles()).toHaveLength(1);
    const up = collector();
    const second = await open(up);
    await second.close();
    expect(up.received.map((event) => event.resource)).toEqual(["kept"]);
    expect(spoolFiles()).toEqual([]);
  });

  it("delivers an event found in two spools once", async () => {
    const file = await crashWith(["x", "y"]);
    copyFileSync(
      file,
      file.replace(/-[0-9a-f]{16}\.jsonl$/, "-0000000000000000.jsonl"),
    );
    expect(spoolFiles()).toHaveLength(2);
    const target = collector();
    const log = await open(target);
    await log.close();
    expect(target.received.map((event) => event.resource)).toEqual(["x", "y"]);
    expect(new Set(target.received.map((event) => event.id)).size).toBe(2);
  });

  it("drops a last line torn by a crash and replays the rest", async () => {
    const file = await crashWith(["whole"]);
    appendFileSync(file, '{"schema":"piship-audit/v1","id":"to');
    const target = collector();
    const log = await open(target);
    await log.close();
    expect(target.received.map((event) => event.resource)).toEqual(["whole"]);
  });

  it("fails launch with AUDIT_UNAVAILABLE on a corrupt spool, and again until it is fixed", async () => {
    const file = await crashWith(["one", "two"]);
    const [first, second] = readFileSync(file, "utf8").split("\n");
    rmSync(file);
    appendFileSync(file, `${first}\nnot json\n${second}\n`);
    const target = collector();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const error = await open(target).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(PiShipError);
      expect((error as PiShipError).code).toBe("AUDIT_UNAVAILABLE");
      expect((error as PiShipError).message).toContain("corrupt at line 2");
    }
    expect(target.received).toEqual([]);
  });

  it("fails closed when the spool is full, never grows past its cap, and recovers once delivered", async () => {
    const target = collector();
    const log = await open(target, { spoolMaxBytes: 1024 });
    target.status = 503;
    for (let index = 0; index < 20; index += 1) emit(log, `r${index}`);
    const [file] = spoolFiles();
    expect(statSync(file as string).size).toBeLessThanOrEqual(1024);
    expect(log.status().state).toBe("failed");
    expect(() => log.assertAvailable()).toThrow(/spool cannot keep its events/);
    target.status = 200;
    await log.flush();
    expect(log.status().state).toBe("ok");
    expect(() => log.assertAvailable()).not.toThrow();
    // Each event stayed in memory, so none was lost while the spool was full.
    expect(target.received).toHaveLength(20);
    await log.close();
  });

  it.skipIf(!posix || process.getuid?.() === 0)(
    "fails closed when the spool cannot be written, later or at launch",
    async () => {
      const target = collector();
      const log = await open(target);
      const [file] = spoolFiles();
      const directory = dirname(file as string);
      rmSync(file as string);
      chmodSync(directory, 0o500);
      emit(log, "unwritten");
      expect(log.status().state).toBe("failed");
      expect(() => log.assertAvailable()).toThrow(/spool cannot keep/);
      chmodSync(directory, 0o700);
      await log.close(50);
      // A launch repairs the directory's mode, but not a file in its place.
      rmSync(directory, { recursive: true });
      appendFileSync(directory, "");
      const error = await open(collector()).catch((caught: unknown) => caught);
      expect((error as PiShipError).code).toBe("AUDIT_UNAVAILABLE");
      rmSync(directory);
    },
  );

  it.skipIf(!posix)("writes the spool 0600 in 0700 directories", async () => {
    const target = collector();
    const log = await open(target);
    target.status = 503;
    emit(log, "m");
    const [file] = spoolFiles();
    expect(statSync(file as string).mode & 0o777).toBe(0o600);
    expect(statSync(dirname(file as string)).mode & 0o777).toBe(0o700);
    expect(statSync(join(temp, AUDIT_SPOOL_DIRECTORY)).mode & 0o777).toBe(
      0o700,
    );
    await log.close(50);
  });

  it("never takes a spool whose owner is alive, and one launch wins a dead one", async () => {
    // The parent process stands in for a live PiShip sharing the state home.
    const live = reown(await crashWith(["live"]), process.ppid);
    await crashWith(["dead"]);
    const a = collector();
    const b = collector();
    const [first, second] = await Promise.all([open(a), open(b)]);
    await Promise.all([first.close(), second.close()]);
    expect(
      [...a.received, ...b.received].map((event) => event.resource),
    ).toEqual(["dead"]);
    expect(existsSync(live)).toBe(true);
  });

  it("never writes a secret or uncaptured content to the spool", async () => {
    const secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    const target = collector();
    const log = await open(target);
    target.status = 503;
    log.emit({
      event: "mcp.call",
      user: null,
      session: null,
      resource: `docs:${secret}`,
      detail: { note: `Bearer ${secret}`, token: secret, apiKey: secret },
      content: {
        prompt: `prompt ${secret} words`,
        command: "rm -rf workspace",
      },
    });
    const [file] = spoolFiles();
    const raw = readFileSync(file as string);
    expect(raw.length).toBeGreaterThan(0);
    expect(raw.includes(secret)).toBe(false);
    expect(raw.includes("prompt")).toBe(false);
    expect(raw.includes("rm -rf")).toBe(false);
    await log.close(50);
  });

  it("leaves an optional HTTP sink as before: no spool, failed batches dropped", async () => {
    const target = collector();
    const log = await AuditLog.open({
      config: config(false),
      distribution: "acmecode",
      stateDir: temp,
      fetch: target.fetch,
    });
    target.status = 503;
    emit(log, "gone");
    await log.flush();
    expect(log.status().sinks[0]).toMatchObject({
      state: "degraded",
      dropped: 1,
      pending: 0,
    });
    expect(existsSync(join(temp, AUDIT_SPOOL_DIRECTORY))).toBe(false);
    await log.close();
  });
});
