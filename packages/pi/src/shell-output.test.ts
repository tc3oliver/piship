import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  freeBytes,
  SessionOutputStore,
  ShellOutput,
  TEMP_DISK_RESERVE_BYTES,
  userBashBudget,
} from "./shell-output.js";

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

describe("user bash output adoption", () => {
  const keys = ["TMPDIR", "TMP", "TEMP"] as const;
  let saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    saved = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
    for (const key of keys) process.env[key] = root;
  });
  afterEach(() => {
    for (const key of keys)
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
  });
  const entry = (
    path: unknown,
    timestamp: unknown,
    role = "bashExecution",
  ) => ({
    type: "message",
    message: { role, fullOutputPath: path, timestamp },
  });

  it("removes only Pi's own temp files recorded during this session", async () => {
    const store = new SessionOutputStore();
    const now = Date.now();
    const file = (name: string) => {
      const path = join(root, name);
      writeFileSync(path, name);
      return path;
    };
    const mine = file("pi-bash-0123456789abcdef.log");
    const earlier = file("pi-bash-1111111111111111.log");
    const renamed = file("pi-bash-notpi.log");
    const toolResult = file("pi-bash-2222222222222222.log");
    mkdirSync(join(root, "nested"));
    const nested = join(root, "nested", "pi-bash-3333333333333333.log");
    writeFileSync(nested, "");
    const outside = mkdtempSync(join(tmpdir(), "..", "piship-outside-"));
    const target = join(outside, "keep.txt");
    writeFileSync(target, "keep");
    const link = join(root, "pi-bash-4444444444444444.log");
    if (posix) symlinkSync(target, link);
    try {
      store.adoptUserBashOutput([
        entry(mine, now),
        entry(earlier, store.openedAt - 1),
        entry(renamed, now),
        entry(toolResult, now, "toolResult"),
        entry(nested, now),
        entry(link, now),
        entry("pi-bash-5555555555555555.log", now),
        { type: "custom", message: undefined },
      ]);
      await store.dispose();
      expect(existsSync(mine)).toBe(false);
      for (const kept of [earlier, renamed, toolResult, nested, target])
        expect(existsSync(kept), kept).toBe(true);
      if (posix) expect(existsSync(link)).toBe(true);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe("userBashBudget", () => {
  const limit = 64 * 1024 * 1024;
  it("keeps the limit with room or no reading, and lowers it to the free space above the reserve", () => {
    expect(userBashBudget(limit, undefined)).toBe(limit);
    expect(userBashBudget(limit, 10 * 1024 ** 3)).toBe(limit);
    expect(userBashBudget(limit, TEMP_DISK_RESERVE_BYTES + 1024 * 1024)).toBe(
      1024 * 1024,
    );
    // Never below what writes no file: small commands still run.
    expect(userBashBudget(limit, 0)).toBe(32 * 1024);
  });
});
