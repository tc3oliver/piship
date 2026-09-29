import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NO_CONTENT_CAPTURE } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
    writeFileSync(lock, "4242-live-rotator\n");
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
    expect(readFileSync(lock, "utf8")).toBe("4242-live-rotator\n");
    expect(existsSync(`${base}.1`)).toBe(false);
    expect(resources(base)).toEqual(["r0", "r1", "r2", "r3", "r4"]);
  });

  it("takes over an abandoned rotation lock after the stale interval, whatever its mtime says", async () => {
    mkdirSync(join(temp, "logs"), { recursive: true });
    const base = join(temp, "logs", "audit.jsonl");
    const lock = `${base}.rotate.lock`;
    writeFileSync(lock, "4242-crashed-rotator\n");
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
    writeFileSync(lock, "4242-slow-rotator\n");
    const log = await open({ maxBytes: 300, files: 2, lockStaleMs: 100 });
    for (let index = 0; index < 6; index += 1) {
      // The holder is still at work: its lock changes between appends.
      const beat = new Date(realNow() + index);
      utimesSync(lock, beat, beat);
      offset += 10 * 60_000;
      log.emit({ event: "resource.load", resource: `r${index}` });
      await log.flush();
      await sleep(60);
    }
    await log.close();
    expect(readFileSync(lock, "utf8")).toBe("4242-slow-rotator\n");
    expect(existsSync(`${base}.1`)).toBe(false);
  });
});
