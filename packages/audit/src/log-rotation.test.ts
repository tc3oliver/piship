import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NO_CONTENT_CAPTURE } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * File identity is not reliable on every platform: Windows reports inode
 * numbers that can collide once converted to a JavaScript number, and some
 * file systems report 0. This file makes every stat report the same inode, so
 * rotation must not depend on it, and can pause one writer's stat so two
 * writers interleave deterministically.
 */
const hooks = vi.hoisted(() => ({
  pauseNextHandleStat: undefined as
    | { reached: () => void; release: Promise<void> }
    | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const sameInode = <T extends { ino: number }>(stats: T): T =>
    Object.assign(stats, { ino: 1 });
  const open = async (...args: Parameters<typeof actual.open>) => {
    const handle = await actual.open(...args);
    const stat = handle.stat.bind(handle) as FileHandle["stat"];
    return Object.assign(handle, {
      stat: async (...options: Parameters<FileHandle["stat"]>) => {
        const stats = sameInode(await stat(...options));
        const pause = hooks.pauseNextHandleStat;
        if (pause) {
          hooks.pauseNextHandleStat = undefined;
          pause.reached();
          await pause.release;
        }
        return stats;
      },
    });
  };
  const stat = async (...args: Parameters<typeof actual.stat>) =>
    sameInode(await actual.stat(...args));
  return { ...actual, default: { ...actual, open, stat }, open, stat };
});

const { AuditLog, auditLogFiles } = await import("./index.js");

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-audit-rotation-"));
});
afterEach(() => {
  hooks.pauseNextHandleStat = undefined;
  rmSync(temp, { recursive: true, force: true });
});

const rotation = { maxBytes: 400, files: 3 };
const open = () =>
  AuditLog.open({
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
const resources = (path: string) =>
  existsSync(path)
    ? readFileSync(path, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => (JSON.parse(line) as { resource: string }).resource)
    : [];

describe("audit rotation without reliable file identity", () => {
  it("rotates a generation once when a second writer measured it before the first rotated", async () => {
    const [first, second] = await Promise.all([open(), open()]);
    // Two events of about 160 bytes: the next append crosses 400 bytes.
    for (const resource of ["x0", "x1"]) {
      first.emit({ event: "resource.load", resource });
      await first.flush();
    }
    const base = join(temp, "logs", "audit.jsonl");
    expect(resources(base)).toEqual(["x0", "x1"]);

    // The second writer measures the full generation, then waits.
    let reached!: () => void;
    const measured = new Promise<void>((resolve) => {
      reached = resolve;
    });
    let release!: () => void;
    hooks.pauseNextHandleStat = {
      reached,
      release: new Promise<void>((resolve) => {
        release = resolve;
      }),
    };
    second.emit({ event: "resource.load", resource: "b" });
    const pending = second.flush();
    await measured;

    // Meanwhile the first writer rotates that generation and appends.
    first.emit({ event: "resource.load", resource: "a" });
    await first.flush();
    expect(resources(`${base}.1`)).toEqual(["x0", "x1"]);
    expect(resources(base)).toEqual(["a"]);

    // The second writer resumes with a stale measurement. Every stat reports
    // the same inode, so only the generation shows that it already rotated.
    release();
    await pending;
    await Promise.all([first.close(), second.close()]);

    // One rotation: nothing was shifted a second time or dropped.
    expect(auditLogFiles(temp, rotation)).toEqual([base, `${base}.1`]);
    expect(resources(`${base}.1`)).toEqual(["x0", "x1"]);
    expect(resources(base)).toEqual(["a", "b"]);
    expect(existsSync(`${base}.2`)).toBe(false);
    expect(existsSync(`${base}.rotate.lock`)).toBe(false);
  });
});
