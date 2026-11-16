// Windows answers EPERM, not EEXIST, when a lock file is created while the
// previous holder's delete of it is still pending; the lock waits that out.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

const pending = vi.hoisted(() => ({ left: 0 }));
vi.mock("node:fs", async (original) => {
  const fs = await original<typeof import("node:fs")>();
  return {
    ...fs,
    openSync: ((...args: Parameters<typeof fs.openSync>) => {
      if (pending.left > 0) {
        pending.left -= 1;
        throw Object.assign(new Error("EPERM: operation not permitted"), {
          code: "EPERM",
        });
      }
      return fs.openSync(...args);
    }) as typeof fs.openSync,
  };
});

const { acquireLifecycleLock } = await import("./lifecycle-lock.js");
const dir = mkdtempSync(join(tmpdir(), "piship-lock-win-"));
const platform = Object.getOwnPropertyDescriptor(process, "platform");
afterEach(() => {
  if (platform) Object.defineProperty(process, "platform", platform);
  pending.left = 0;
});
process.on("exit", () => rmSync(dir, { recursive: true, force: true }));

const busy = () => new Error("busy");
const unavailable = () => new Error("unavailable");

it("waits out a pending delete on Windows", () => {
  Object.defineProperty(process, "platform", { value: "win32" });
  pending.left = 2;
  const hold = acquireLifecycleLock(join(dir, "a.lock"), busy, unavailable);
  expect(pending.left).toBe(0);
  hold.release();
});

it("still throws EPERM on Windows once it does not clear", () => {
  Object.defineProperty(process, "platform", { value: "win32" });
  pending.left = 1000;
  expect(() =>
    acquireLifecycleLock(join(dir, "b.lock"), busy, unavailable),
  ).toThrow(/EPERM/);
});

it("throws EPERM at once elsewhere", () => {
  Object.defineProperty(process, "platform", { value: "linux" });
  pending.left = 1;
  expect(() =>
    acquireLifecycleLock(join(dir, "c.lock"), busy, unavailable),
  ).toThrow(/EPERM/);
});
