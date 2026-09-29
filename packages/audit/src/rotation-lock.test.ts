import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { NO_CONTENT_CAPTURE } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  deadPid,
  livePid,
  stopLiveProcesses,
} from "../../../tests/helpers/processes.js";
import { AuditLog, type AuditRotation } from "./index.js";

let temp: string;
/** Added to the wall clock; monotonic time (performance.now) runs on. */
let offset = 0;
const realNow = Date.now.bind(Date);

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-rotation-lock-"));
  offset = 0;
  vi.spyOn(Date, "now").mockImplementation(() => realNow() + offset);
});
afterEach(() => {
  vi.restoreAllMocks();
  stopLiveProcesses();
  rmSync(temp, { recursive: true, force: true });
});

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

function open(rotation: AuditRotation) {
  return AuditLog.open({
    config: {
      enabled: true,
      sinks: [{ id: "local", type: "file", required: false }],
      buffer: { maxEvents: 1000, flushIntervalMs: 0 },
      capture: NO_CONTENT_CAPTURE,
    },
    distribution: "acmecode",
    stateDir: temp,
    rotation,
  });
}

function resources(path: string): string[] {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => (JSON.parse(line) as { resource: string }).resource);
}

describe("audit rotation lock over a changing wall clock", () => {
  it("never lets a second writer take a live rotation lock when the wall clock jumps forward", async () => {
    mkdirSync(join(temp, "logs"), { recursive: true });
    const base = join(temp, "logs", "audit.jsonl");
    const lock = `${base}.rotate.lock`;
    // Another process is rotating right now; its lock was created a moment ago.
    writeFileSync(lock, `${livePid()}-live-rotator\n`);
    offset = 10 * 60_000;
    const log = await open({ maxBytes: 300, files: 2 });
    for (let index = 0; index < 5; index += 1) {
      log.emit({ event: "resource.load", resource: `r${index}` });
      await log.flush();
      await sleep(20);
    }
    await log.close();
    // The lock looks ten minutes old against the jumped clock, but it was
    // not seen unchanged for the stale interval: nothing was rotated.
    expect(readFileSync(lock, "utf8")).toMatch(/^\d+-live-rotator\n$/);
    expect(existsSync(`${base}.1`)).toBe(false);
    expect(resources(base)).toEqual(["r0", "r1", "r2", "r3", "r4"]);
  });

  it("takes over an abandoned rotation lock after the stale interval, whatever its mtime says", async () => {
    mkdirSync(join(temp, "logs"), { recursive: true });
    const base = join(temp, "logs", "audit.jsonl");
    const lock = `${base}.rotate.lock`;
    writeFileSync(lock, `${livePid()}-crashed-rotator\n`);
    // Written under a clock that ran an hour ahead, then went back.
    const ahead = new Date(realNow() + 60 * 60_000);
    utimesSync(lock, ahead, ahead);
    offset = -2 * 60 * 60_000;
    const log = await open({ maxBytes: 300, files: 9, lockStaleMs: 100 });
    for (let index = 0; index < 6; index += 1) {
      log.emit({ event: "resource.load", resource: `r${index}` });
      await log.flush();
      await sleep(60);
    }
    await log.close();
    expect(existsSync(`${base}.1`)).toBe(true);
    expect(
      readdirSync(join(temp, "logs")).filter((name) => name.includes("lock")),
    ).toEqual([]);
    const all = [9, 8, 7, 6, 5, 4, 3, 2, 1]
      .map((index) => `${base}.${index}`)
      .concat(base)
      .filter((path) => existsSync(path))
      .flatMap(resources);
    expect(all).toEqual(["r0", "r1", "r2", "r3", "r4", "r5"]);
  });

  it("keeps watching a lock whose holder makes progress", async () => {
    mkdirSync(join(temp, "logs"), { recursive: true });
    const base = join(temp, "logs", "audit.jsonl");
    const lock = `${base}.rotate.lock`;
    const slow = `${livePid()}-slow-rotator\n`;
    writeFileSync(lock, slow);
    const log = await open({ maxBytes: 300, files: 2, lockStaleMs: 100 });
    for (let index = 0; index < 6; index += 1) {
      // The holder is still at work: its lock changes between appends.
      const beat = new Date(realNow() + index);
      utimesSync(lock, beat, beat);
      offset += 5 * 60_000;
      log.emit({ event: "resource.load", resource: `r${index}` });
      await log.flush();
      await sleep(60);
    }
    await log.close();
    expect(readFileSync(lock, "utf8")).toBe(slow);
    expect(existsSync(`${base}.1`)).toBe(false);
  });
});

/** Every event, oldest file first. */
function allResources(base: string, files: number): string[] {
  return Array.from({ length: files }, (_, index) => `${base}.${files - index}`)
    .concat(base)
    .filter((path) => existsSync(path))
    .flatMap(resources);
}

/** Six events through a log whose files hold two each; each flushed alone. */
async function writeSix(rotation: AuditRotation, pause = 0) {
  const log = await open(rotation);
  for (let index = 0; index < 6; index += 1) {
    log.emit({ event: "resource.load", resource: `r${index}` });
    await log.flush();
    if (pause) await sleep(pause);
  }
  await log.close();
}

/** The token a rotator on this host writes: `<pid>-<host id>-<random>`. */
const hostId = () =>
  createHash("sha256").update(hostname()).digest("hex").slice(0, 12);

describe("audit rotation lock left by a rotator that is gone", () => {
  function lockFile(): { base: string; lock: string } {
    mkdirSync(join(temp, "logs"), { recursive: true });
    const base = join(temp, "logs", "audit.jsonl");
    return { base, lock: `${base}.rotate.lock` };
  }
  const leftovers = () =>
    readdirSync(join(temp, "logs")).filter((name) => name.includes("lock"));
  const HOUR = 60 * 60_000;

  it.each([
    ["an earlier PiShip's token", () => `${deadPid()}-0123456789abcdef\n`],
    ["this host's token", () => `${deadPid()}-${hostId()}-0123456789abcdef\n`],
  ])(
    "takes over at once a lock whose process no longer exists (%s), with no earlier look at it",
    async (_name, token) => {
      const { base, lock } = lockFile();
      // Written a moment ago, and the default 30 s stale interval is far off:
      // nothing but the missing process says it is abandoned.
      writeFileSync(lock, token());
      await writeSix({ maxBytes: 300, files: 9 });
      expect(existsSync(`${base}.1`)).toBe(true);
      expect(leftovers()).toEqual([]);
      expect(allResources(base, 9)).toEqual([
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
      ]);
    },
  );

  it("takes over at once a lock whose process ID an unrelated live process now has, once the lock is over an hour old", async () => {
    const { base, lock } = lockFile();
    writeFileSync(lock, `${livePid()}-${hostId()}-0123456789abcdef\n`);
    const old = new Date(realNow() - HOUR - 60_000);
    utimesSync(lock, old, old);
    await writeSix({ maxBytes: 300, files: 9 });
    expect(existsSync(`${base}.1`)).toBe(true);
    expect(leftovers()).toEqual([]);
    expect(allResources(base, 9)).toEqual(["r0", "r1", "r2", "r3", "r4", "r5"]);
  });

  it("leaves a live process's lock alone within the hour, whatever the wall clock does", async () => {
    const { base, lock } = lockFile();
    const token = `${livePid()}-${hostId()}-0123456789abcdef\n`;
    writeFileSync(lock, token);
    const recent = new Date(realNow() - 30 * 60_000);
    utimesSync(lock, recent, recent);
    offset = 20 * 60_000;
    await writeSix({ maxBytes: 300, files: 9 });
    expect(readFileSync(lock, "utf8")).toBe(token);
    expect(existsSync(`${base}.1`)).toBe(false);
    expect(resources(base)).toEqual(["r0", "r1", "r2", "r3", "r4", "r5"]);
  });

  it("does not read a process ID of another host as a dead process", async () => {
    const { base, lock } = lockFile();
    // The process ID means nothing here, so only the stale interval applies.
    const token = `${deadPid()}-${"0".repeat(12)}-0123456789abcdef\n`;
    writeFileSync(lock, token);
    await writeSix({ maxBytes: 300, files: 9 });
    expect(readFileSync(lock, "utf8")).toBe(token);
    expect(existsSync(`${base}.1`)).toBe(false);
  });

  // Permissions and what a directory at a file's path does differ on
  // Windows, and a root user reads a mode 000 file.
  describe.runIf(process.platform !== "win32" && process.getuid?.() !== 0)(
    "a lock that cannot be read",
    () => {
      it("is taken over by its mtime alone after the stale interval, never while it changes", async () => {
        const { base, lock } = lockFile();
        writeFileSync(lock, `${livePid()}-root-owned\n`);
        chmodSync(lock, 0o000);
        await writeSix({ maxBytes: 300, files: 9, lockStaleMs: 100 }, 60);
        expect(existsSync(`${base}.1`)).toBe(true);
        expect(leftovers()).toEqual([]);
        expect(allResources(base, 9)).toEqual([
          "r0",
          "r1",
          "r2",
          "r3",
          "r4",
          "r5",
        ]);
      });

      it("is left alone while its mtime keeps changing", async () => {
        const { base, lock } = lockFile();
        writeFileSync(lock, `${livePid()}-root-owned\n`);
        chmodSync(lock, 0o000);
        const log = await open({ maxBytes: 300, files: 2, lockStaleMs: 100 });
        for (let index = 0; index < 6; index += 1) {
          const beat = new Date(realNow() + index);
          utimesSync(lock, beat, beat);
          log.emit({ event: "resource.load", resource: `r${index}` });
          await log.flush();
          await sleep(60);
        }
        await log.close();
        expect(existsSync(lock)).toBe(true);
        expect(existsSync(`${base}.1`)).toBe(false);
      });

      it("is never taken over when it is a directory", async () => {
        const { base, lock } = lockFile();
        mkdirSync(lock);
        const old = new Date(realNow() - 5 * HOUR);
        utimesSync(lock, old, old);
        await writeSix({ maxBytes: 300, files: 9, lockStaleMs: 100 }, 60);
        expect(lstatSync(lock).isDirectory()).toBe(true);
        expect(existsSync(`${base}.1`)).toBe(false);
        expect(resources(base)).toEqual(["r0", "r1", "r2", "r3", "r4", "r5"]);
      });
    },
  );
});
