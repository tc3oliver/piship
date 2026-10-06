import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import { renameWithRetry } from "./files.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-files-"));
  roots.push(dir);
  return dir;
}

function blocked(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`${code}: rename`), { code });
}

describe("renameWithRetry", () => {
  it("renames at once when nothing blocks it", () => {
    const dir = temp();
    mkdirSync(join(dir, "from"));
    writeFileSync(join(dir, "from", "file"), "x");
    renameWithRetry(join(dir, "from"), join(dir, "to"));
    expect(readFileSync(join(dir, "to", "file"), "utf8")).toBe("x");
  });

  it.each(["EPERM", "EBUSY", "EACCES"])(
    "retries %s on Windows with a growing wait, then succeeds",
    (code) => {
      const waits: number[] = [];
      let calls = 0;
      renameWithRetry("a", "b", {
        platform: "win32",
        rename: () => {
          if (++calls <= 3) throw blocked(code);
        },
        sleep: (ms) => waits.push(ms),
      });
      expect(calls).toBe(4);
      expect(waits).toEqual([25, 50, 100]);
    },
  );

  it("stops after a bounded time with an error that names the cause", () => {
    const waits: number[] = [];
    let calls = 0;
    let error: unknown;
    try {
      renameWithRetry("from-dir", "to-dir", {
        platform: "win32",
        rename: () => {
          calls++;
          throw blocked("EBUSY");
        },
        sleep: (ms) => waits.push(ms),
      });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PiShipError);
    const failure = error as PiShipError;
    expect(failure.code).toBe("UPDATE_FAILED");
    expect(failure.retryable).toBe(true);
    expect(failure.message).toContain("from-dir");
    expect(failure.message).toContain("EBUSY");
    expect(failure.userAction).toContain("nothing was changed");
    // About 1.6 s of waiting in total.
    expect(calls).toBe(waits.length + 1);
    expect(waits.reduce((sum, ms) => sum + ms, 0)).toBeLessThanOrEqual(2000);
    expect(waits.reduce((sum, ms) => sum + ms, 0)).toBeGreaterThan(1000);
  });

  it("does not retry other errors, or the same codes off Windows", () => {
    let calls = 0;
    expect(() =>
      renameWithRetry("a", "b", {
        platform: "win32",
        rename: () => {
          calls++;
          throw blocked("ENOENT");
        },
        sleep: () => {
          throw new Error("must not wait");
        },
      }),
    ).toThrow(/ENOENT/);
    expect(() =>
      renameWithRetry("a", "b", {
        platform: "linux",
        rename: () => {
          calls++;
          throw blocked("EPERM");
        },
        sleep: () => {
          throw new Error("must not wait");
        },
      }),
    ).toThrow(/EPERM/);
    expect(calls).toBe(2);
  });
});
