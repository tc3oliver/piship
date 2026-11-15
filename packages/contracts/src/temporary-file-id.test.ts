// A directory's identity is compared at full width. An NTFS file id is 64
// bits; as a number it loses its low bits, so a directory swapped in for the
// judged one, whose id differs only there, would pass as the same directory.
// The file system reports such ids for the paths a test names.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deadPid } from "../../../tests/helpers/processes.js";
import {
  TEMPORARY_OWNER_FILE,
  TEMPORARY_OWNER_SCHEMA,
  createTemporaryDirectory,
  readTemporaryOwner,
  reclaimTemporaryDirectories,
} from "./index.js";

/** Above 2^53, where a number keeps only every 16th value. */
const BASE = 75435293758483490n;
const ids = vi.hoisted(() => ({ byEnding: new Map<string, bigint>() }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    lstatSync: ((path: string, ...rest: unknown[]) => {
      const stat = (actual.lstatSync as (...args: unknown[]) => unknown)(
        path,
        ...rest,
      ) as { ino: number | bigint } | undefined;
      const id = [...ids.byEnding].find(([ending]) =>
        String(path).endsWith(ending),
      )?.[1];
      if (stat && id !== undefined)
        return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, {
          ino: typeof stat.ino === "bigint" ? id : Number(id),
        });
      return stat;
    }) as typeof actual.lstatSync,
  };
});

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "piship-temporary-file-id-"));
  ids.byEnding.clear();
});
afterEach(() => {
  ids.byEnding.clear();
  rmSync(root, { recursive: true, force: true });
});

describe("file ids", () => {
  it("does not remove a directory whose id differs from the judged one only in its low bits", () => {
    expect(Number(BASE + 1n)).toBe(Number(BASE));
    const name = "piship-verify-abc123";
    const path = join(root, name);
    mkdirSync(path);
    writeFileSync(join(path, "payload"), "payload");
    const probe = createTemporaryDirectory(root, "staging");
    const host = readTemporaryOwner(probe.path)?.owner.host;
    probe.remove();
    writeFileSync(
      join(path, TEMPORARY_OWNER_FILE),
      JSON.stringify({
        schema: TEMPORARY_OWNER_SCHEMA,
        kind: "verify",
        name,
        pid: deadPid(),
        instance: "0123456789abcdef",
        host,
        created: new Date().toISOString(),
      }),
    );
    // Judged with one id; after the move aside, the entry has the next one.
    ids.byEnding.set(name, BASE);
    const reclaimed = reclaimTemporaryDirectories(root, ["verify"], {
      remover: "portable",
      onStep: (step, at) => {
        if (step === "renamed") ids.byEnding.set(at, BASE + 1n);
      },
    });
    expect(reclaimed).toEqual({ removed: [], failed: [path] });
    expect(existsSync(join(path, "payload"))).toBe(true);
  });
});
