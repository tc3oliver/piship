import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { freeBytes, SessionOutputStore, ShellOutput } from "./shell-output.js";

const posix = process.platform !== "win32";
let root = "";
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-shell-output-")));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const lines = (count: number) =>
  Buffer.from(
    Array.from(
      { length: count },
      (_, i) => `line ${i} ${"x".repeat(40)}\n`,
    ).join(""),
  );

describe("SessionOutputStore", () => {
  it("creates no directory until output needs persisting", async () => {
    const store = new SessionOutputStore({ root });
    const output = new ShellOutput(store);
    output.append(Buffer.from("small\n"));
    output.finish();
    expect(output.snapshot().fullOutputPath).toBeUndefined();
    await output.close();
    expect(store.dir).toBeUndefined();
    await store.dispose();
  });

  it("stops persisting at the free-space reserve and says so", async () => {
    const store = new SessionOutputStore({
      root,
      reserveBytes: Number.MAX_SAFE_INTEGER,
    });
    const output = new ShellOutput(store);
    output.append(lines(4000));
    output.finish();
    const snapshot = output.snapshot();
    expect(snapshot.truncation.truncated).toBe(true);
    expect(snapshot.fullOutputPath).toBeUndefined();
    expect(output.file?.failure).toBe("temporary disk nearly full");
    await output.close();
    await store.dispose();
  });

  it("caps one file at the free space above the reserve", async () => {
    const free = freeBytes(root);
    if (free === undefined) return;
    // About 1 MiB of room; the command writes 3 MiB.
    const store = new SessionOutputStore({
      root,
      reserveBytes: free - 1024 * 1024,
    });
    const output = new ShellOutput(store);
    for (let i = 0; i < 3; i++) output.append(Buffer.alloc(1024 * 1024, 120));
    output.finish();
    const path = output.snapshot().fullOutputPath as string;
    await output.close();
    expect(output.file?.capped).toBe(true);
    expect(statSync(path).size).toBeLessThan(3 * 1024 * 1024);
    await store.dispose();
    expect(existsSync(path)).toBe(false);
  });

  it("removes only its own directory", async () => {
    const store = new SessionOutputStore({ root });
    const other = mkdtempSync(join(root, "piship-out-"));
    const output = new ShellOutput(store);
    output.append(lines(4000));
    output.finish();
    const path = output.snapshot().fullOutputPath as string;
    await output.close();
    expect(readFileSync(path, "utf8")).toContain("line 3999 ");
    await store.dispose();
    expect(existsSync(path)).toBe(false);
    expect(existsSync(other)).toBe(true);
    // A disposed store persists nothing more.
    const late = new ShellOutput(store);
    late.append(lines(4000));
    late.finish();
    expect(late.snapshot().fullOutputPath).toBeUndefined();
    expect(store.dir).toBeUndefined();
  });

  it.skipIf(!posix)("sweeps only provably abandoned store directories", () => {
    const make = (owner: unknown, mode = 0o700) => {
      const dir = mkdtempSync(join(root, "piship-out-"));
      if (owner !== undefined)
        writeFileSync(join(dir, "owner"), JSON.stringify(owner));
      chmodSync(dir, mode);
      return dir;
    };
    const exited = spawnSync(process.execPath, ["-e", ""]).pid;
    const dead = make({ pid: exited, host: hostname() });
    const live = make({ pid: process.ppid, host: hostname() });
    const self = make({ pid: process.pid, host: hostname() });
    const elsewhere = make({ pid: exited, host: `${hostname()}-other` });
    const noOwner = make(undefined);
    const shared = make({ pid: exited, host: hostname() }, 0o755);
    const plain = join(root, "piship-out-file");
    writeFileSync(plain, "");
    const unrelated = mkdtempSync(join(root, "unrelated-"));
    writeFileSync(
      join(unrelated, "owner"),
      JSON.stringify({ pid: exited, host: hostname() }),
    );
    SessionOutputStore.sweep(root);
    expect(existsSync(dead)).toBe(false);
    for (const kept of [
      live,
      self,
      elsewhere,
      noOwner,
      shared,
      plain,
      unrelated,
    ])
      expect(existsSync(kept), kept).toBe(true);
  });
});
