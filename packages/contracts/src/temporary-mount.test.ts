// The recovery never crosses a mount. A real mount needs privileges a test
// cannot assume, so the file system reports a different device for the path a
// test names, which is what `lstat` shows for a mount point.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
  findAbandonedTemporaryDirectories,
  readTemporaryOwner,
  reclaimTemporaryDirectories,
} from "./index.js";

const mounts = vi.hoisted(() => ({ paths: [] as string[] }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    lstatSync: ((path: string, ...rest: unknown[]) => {
      const stat = (actual.lstatSync as (...args: unknown[]) => unknown)(
        path,
        ...rest,
      ) as { dev: number } | undefined;
      if (stat && mounts.paths.some((mount) => String(path).endsWith(mount)))
        return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, {
          dev: stat.dev + 1,
        });
      return stat;
    }) as typeof actual.lstatSync,
  };
});

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "piship-temporary-mount-"));
  mounts.paths.length = 0;
});
afterEach(() => {
  mounts.paths.length = 0;
  rmSync(root, { recursive: true, force: true });
});

function stale(name: string): string {
  const path = join(root, name);
  mkdirSync(join(path, "x", "mounted"), { recursive: true });
  writeFileSync(join(path, "x", "mounted", "user-file"), "on another device");
  writeFileSync(join(path, "x", "payload"), "payload");
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
  return path;
}

describe("mount points", () => {
  it("does not descend into a mount point inside an abandoned directory", () => {
    const path = stale("piship-verify-abc123");
    // The directory is moved aside before it is removed: match by ending.
    mounts.paths.push(join("x", "mounted"));
    const result = reclaimTemporaryDirectories(root, ["verify"], {
      remover: "portable",
    });
    expect(result).toEqual({ removed: [], failed: [path] });
    expect(readFileSync(join(path, "x", "mounted", "user-file"), "utf8")).toBe(
      "on another device",
    );
    // Still recognised, so it is reported and retried, not forgotten.
    expect(existsSync(join(path, TEMPORARY_OWNER_FILE))).toBe(true);
    expect(
      findAbandonedTemporaryDirectories(root, ["verify"]).map(
        (item) => item.path,
      ),
    ).toEqual([path]);
  });

  it("does not remove a directory that is itself a mount point", () => {
    const path = stale("piship-verify-abc123");
    mounts.paths.push(path);
    expect(
      reclaimTemporaryDirectories(root, ["verify"], { remover: "portable" }),
    ).toEqual({ removed: [], failed: [] });
    expect(existsSync(join(path, "x", "payload"))).toBe(true);
  });

  it("removes the same directory once nothing in it is a mount point", () => {
    const path = stale("piship-verify-abc123");
    expect(reclaimTemporaryDirectories(root, ["verify"]).removed).toEqual([
      path,
    ]);
  });
});
