import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { NO_CONTENT_CAPTURE, PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AUDIT_SPOOL_DIRECTORY,
  AUDIT_SPOOL_LEASE_MS,
  type AuditConfig,
  type AuditFetch,
  AuditLog,
  type AuditLogOptions,
  auditSpools,
} from "./index.js";

// A seam on rename: a test stands in for a second launcher racing this one.
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, renameSync: vi.fn(actual.renameSync) };
});

const posix = process.platform !== "win32";
let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-spool-"));
});
afterEach(() => {
  vi.mocked(renameSync).mockRestore();
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
    replaySpool: true,
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
    // Under another sink ID the directory is an orphan, never replayed.
    expect(auditSpools(temp, ["renamed"])).toEqual([
      expect.objectContaining({ files: 1, stale: 0, quarantined: [] }),
    ]);
    expect(auditSpools(temp, ["renamed"])[0]).not.toHaveProperty("sink");
    expect(auditSpools(temp, ["company"])[0]?.sink).toBe("company");
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

  it("keeps a last line torn by a crash that is still a whole event", async () => {
    const file = await crashWith(["first"]);
    const [line] = readFileSync(file, "utf8").split("\n");
    const torn = JSON.parse(line as string);
    appendFileSync(
      file,
      JSON.stringify({ ...torn, id: "torn-but-whole", resource: "second" }),
    );
    const target = collector();
    const log = await open(target);
    await log.close();
    expect(target.received.map((event) => event.resource)).toEqual([
      "first",
      "second",
    ]);
  });

  it("sets a corrupt spool aside under a stable name, keeps its valid lines, and fails launch until it is removed", async () => {
    const file = await crashWith(["one", "two"]);
    const [first, second] = readFileSync(file, "utf8").split("\n");
    rmSync(file);
    appendFileSync(file, `${first}\nnot json\n${second}\n`);
    const quarantined = `${basename(file)}.corrupt`;
    const target = collector();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const error = await open(target).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(PiShipError);
      expect((error as PiShipError).code).toBe("AUDIT_UNAVAILABLE");
      expect((error as PiShipError).message).toContain(
        `${dirname(file)} holds a spool set aside as corrupt or over the cap, ${quarantined}`,
      );
    }
    expect(target.received).toEqual([]);
    expect(auditSpools(temp, ["company"])).toEqual([
      expect.objectContaining({ sink: "company", quarantined: [quarantined] }),
    ]);
    rmSync(join(dirname(file), quarantined));
    const log = await open(target);
    await log.close();
    expect(target.received.map((event) => event.resource)).toEqual([
      "one",
      "two",
    ]);
    expect(spoolFiles()).toEqual([]);
  });

  it.skipIf(!posix)(
    "never opens a FIFO planted as a spool, so a launch does not hang",
    async () => {
      const file = await crashWith(["kept"]);
      rmSync(file);
      expect(spawnSync("mkfifo", [file]).status).toBe(0);
      const target = collector();
      const log = await open(target);
      await log.close();
      expect(target.received).toEqual([]);
      rmSync(file);
    },
  );

  it("claims a spool not touched within the lease although its process ID is alive or its host differs", async () => {
    const stale = new Date(Date.now() - AUDIT_SPOOL_LEASE_MS - 60_000);
    // A live process ID (now an unrelated process), and an earlier hostname.
    const reused = reown(await crashWith(["reused"]), process.ppid);
    const renamed = await crashWith(["renamed"]);
    const otherHost = join(
      dirname(renamed),
      basename(renamed).replace(/^(\d+)-[0-9a-f]{12}-/, "$1-000000000000-"),
    );
    renameSync(renamed, otherHost);
    const target = collector();
    const fresh = await open(target);
    await fresh.close();
    expect(target.received).toEqual([]);
    for (const path of [reused, otherHost]) utimesSync(path, stale, stale);
    const log = await open(target);
    await log.close();
    expect(target.received.map((event) => event.resource).sort()).toEqual([
      "renamed",
      "reused",
    ]);
    expect(spoolFiles()).toEqual([]);
  });

  it("drops content the current audit.capture no longer admits from replayed events", async () => {
    const captured = {
      ...config(),
      capture: {
        ...NO_CONTENT_CAPTURE,
        promptContent: true,
        commandText: true,
      },
    };
    const down = collector();
    const first = await open(down, { config: captured });
    down.status = 503;
    first.emit({
      event: "mcp.call",
      user: null,
      session: null,
      resource: "narrowed",
      content: { prompt: "the prompt words", command: "make test" },
    });
    await first.flush();
    reown(spoolFiles()[0] as string, deadPid());
    const target = collector();
    const narrowed = {
      ...config(),
      capture: { ...NO_CONTENT_CAPTURE, commandText: true },
    };
    const log = await open(target, { config: narrowed });
    // The spool this launch rewrote holds none of it either.
    for (const path of spoolFiles())
      expect(readFileSync(path, "utf8")).not.toContain("the prompt words");
    await log.close();
    expect(target.received).toEqual([
      expect.objectContaining({
        resource: "narrowed",
        content: { command: "make test" },
      }),
    ]);
  });

  it("replays only a backlog within the cap at once and leaves the rest for the next launch", async () => {
    const big = Array.from({ length: 6 }, (_, index) => `big-${index}`);
    // Owned by a live process while the second crash runs, so it is not merged.
    const older = reown(await crashWith(big), process.ppid);
    await crashWith(big.map((name) => `${name}-again`));
    reown(older, deadPid());
    const [size] = spoolFiles().map((path) => statSync(path).size);
    const target = collector();
    const first = await open(target, {
      spoolMaxBytes: Math.ceil((size as number) * 1.5),
    });
    await first.close();
    expect(target.received).toHaveLength(6);
    expect(spoolFiles()).toHaveLength(1);
    const second = await open(target);
    await second.close();
    expect(target.received).toHaveLength(12);
    expect(spoolFiles()).toEqual([]);
  });

  it("rewrites the spool once per flush, not once per delivered batch", async () => {
    const target = collector();
    const log = await open(target, { config: config(true, 5000) });
    target.status = 503;
    for (let index = 0; index < 1200; index += 1) emit(log, `e${index}`);
    await log.flush();
    target.status = 200;
    const renames = vi.mocked(renameSync).mock.calls.length;
    await log.flush();
    expect(target.received).toHaveLength(1200);
    expect(vi.mocked(renameSync).mock.calls.length - renames).toBe(1);
    await log.close();
  });

  it("fails closed when a rewrite fails, keeps the old spool, and recovers on the next delivered batch", async () => {
    const target = collector();
    const log = await open(target);
    target.status = 503;
    emit(log, "before");
    await log.flush();
    const [file] = spoolFiles();
    // A directory where the rewrite's temporary goes makes the rewrite fail.
    mkdirSync(`${file}.tmp`);
    target.status = 200;
    await log.flush();
    expect(target.received.map((event) => event.resource)).toEqual(["before"]);
    expect(log.status().state).toBe("failed");
    expect(() => log.assertAvailable()).toThrow(/spool cannot keep/);
    // The old spool is still whole: a crash now would only resend "before".
    expect(readFileSync(file as string, "utf8")).toContain('"before"');
    rmSync(`${file}.tmp`, { recursive: true });
    emit(log, "after");
    await log.flush();
    expect(log.status().state).toBe("ok");
    expect(readFileSync(file as string, "utf8")).toBe("");
    await log.close();
  });

  it("only one of two racing launchers claims a spool: the other's rename fails with ENOENT and it skips the file", async () => {
    const file = await crashWith(["raced"]);
    // The other launcher, alive, renames the spool to a name of its own first.
    const other = join(
      dirname(file),
      basename(file).replace(/^\d+/, String(process.ppid)),
    );
    const actual = (await vi.importActual<typeof import("node:fs")>("node:fs"))
      .renameSync;
    vi.mocked(renameSync).mockImplementationOnce((from, to) => {
      actual(from, other);
      actual(from, to);
    });
    const target = collector();
    const log = await open(target);
    await log.close();
    expect(target.received).toEqual([]);
    expect(existsSync(other)).toBe(true);
    expect(existsSync(file)).toBe(false);
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
      target.status = 503;
      await log.close(50);
      // The event only in memory is in the spool after close.
      expect(readFileSync(spoolFiles()[0] as string, "utf8")).toContain(
        '"unwritten"',
      );
      rmSync(spoolFiles()[0] as string);
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
  it("in a short command, replays nothing and records its own events despite a set-aside spool", async () => {
    const crashed = await crashWith(["crashed"]);
    appendFileSync(join(dirname(crashed), "1-a.jsonl.corrupt"), "x\n");
    const target = collector();
    const log = await open(target, { replaySpool: false });
    emit(log, "own");
    await log.close();
    expect(target.received.map((event) => event.resource)).toEqual(["own"]);
    expect(existsSync(crashed)).toBe(true);
  });

  it("does not count a replayed backlog against maxEvents, so new events are still taken", async () => {
    await crashWith(["r1", "r2", "r3"]);
    const target = collector();
    target.status = 503;
    const log = await open(target, { config: config(true, 2) });
    await log.flush();
    emit(log, "new");
    expect(log.status().sinks[0]).toMatchObject({ pending: 4, dropped: 0 });
    expect(() => log.assertAvailable()).not.toThrow();
    target.status = 200;
    await log.close();
    expect(target.received.map((event) => event.resource)).toEqual([
      "r1",
      "r2",
      "r3",
      "new",
    ]);
  });

  it("sets a spool over the cap aside unread and names it in the error", async () => {
    const file = await crashWith(["x", "y", "z"]);
    const error = await open(collector(), {
      spoolMaxBytes: statSync(file).size - 1,
    }).catch((caught: unknown) => caught);
    expect((error as PiShipError).code).toBe("AUDIT_UNAVAILABLE");
    expect((error as PiShipError).message).toContain(
      `${basename(file)}.corrupt`,
    );
    expect(existsSync(`${file}.corrupt`)).toBe(true);
  });

  it("claims a spool whose mtime is far in the future", async () => {
    const file = reown(await crashWith(["ahead"]), process.ppid);
    const ahead = new Date(Date.now() + 10 * 60_000);
    utimesSync(file, ahead, ahead);
    const target = collector();
    const log = await open(target);
    await log.close();
    expect(target.received.map((event) => event.resource)).toEqual(["ahead"]);
  });

  it("skips a spool another process holds open (EBUSY) and claims it later", async () => {
    const file = await crashWith(["busy"]);
    vi.mocked(renameSync).mockImplementationOnce(() => {
      throw Object.assign(new Error("resource busy"), { code: "EBUSY" });
    });
    const target = collector();
    const first = await open(target);
    await first.close();
    expect(target.received).toEqual([]);
    expect(existsSync(file)).toBe(true);
    const second = await open(target);
    await second.close();
    expect(target.received.map((event) => event.resource)).toEqual(["busy"]);
  });

  it("renews its spool on a heartbeat, writes it again once taken, and stops at close", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      const target = collector();
      const log = await open(target);
      target.status = 503;
      emit(log, "beat");
      const [file] = spoolFiles() as [string];
      const old = new Date(Date.now() - AUDIT_SPOOL_LEASE_MS);
      utimesSync(file, old, old);
      vi.advanceTimersByTime(60_000);
      expect(statSync(file).mtimeMs).toBeGreaterThan(old.getTime() + 60_000);
      // Taken by a launch past the lease: the next beat writes it again.
      const taken = reown(file, process.ppid);
      vi.advanceTimersByTime(60_000);
      expect(readFileSync(file, "utf8")).toContain('"beat"');
      expect(readFileSync(taken, "utf8")).toContain('"beat"');
      expect(vi.getTimerCount()).toBe(1);
      await log.close(50);
      expect(vi.getTimerCount()).toBe(0);
      rmSync(taken);
    } finally {
      vi.useRealTimers();
    }
  });

  it("after its spool is taken, writes only its own pending events and never touches the taker's file", async () => {
    const target = collector();
    const log = await open(target);
    target.status = 503;
    emit(log, "a");
    emit(log, "b");
    await log.flush();
    const [file] = spoolFiles() as [string];
    const taken = reown(file, process.ppid);
    const takenContent = readFileSync(taken, "utf8");
    target.status = 200;
    await log.flush();
    expect(target.received.map((event) => event.resource)).toEqual(["a", "b"]);
    expect(readFileSync(file, "utf8")).toBe("");
    target.status = 503;
    emit(log, "c");
    await log.flush();
    const own = readFileSync(file, "utf8");
    expect(own).toContain('"c"');
    expect(own).not.toContain('"a"');
    expect(readFileSync(taken, "utf8")).toBe(takenContent);
    await log.close(50);
    rmSync(taken);
  });
});
