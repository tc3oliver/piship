// PiShip-owned temporary directories: the ownership marker, and the recovery
// of what a hard termination left. Every scenario runs in a private root, so
// nothing here reads or removes anything in the machine's real temp directory.
import { spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  deadPid,
  livePid,
  stopLiveProcesses,
} from "../../../tests/helpers/processes.js";
import {
  TEMPORARY_HEARTBEAT_MS,
  TEMPORARY_LEASE_MS,
  TEMPORARY_OWNER_FILE,
  TEMPORARY_OWNER_SCHEMA,
  createTemporaryDirectory,
  findAbandonedTemporaryDirectories,
  readTemporaryOwner,
  reclaimTemporaryDirectories,
  type TemporaryDirectory,
  type TemporaryKind,
  type TemporaryOwner,
} from "./index.js";

const posix = process.platform !== "win32";
const notRoot = posix && process.getuid?.() !== 0;
const DAY = 24 * 60 * 60_000;

let root: string;
let dead: number;
let host: string | undefined;
const made: TemporaryDirectory[] = [];
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "piship-temporary-test-"));
  dead = deadPid();
});
afterEach(() => {
  vi.useRealTimers();
  stopLiveProcesses();
  for (const item of made.splice(0)) item.remove();
  // A test that made a directory unremovable restores it first.
  rmSync(root, { recursive: true, force: true });
});

function create(kind: TemporaryKind, label?: string): TemporaryDirectory {
  const item = createTemporaryDirectory(root, kind, label);
  made.push(item);
  return item;
}

/** The host token of this machine, as a marker records it. */
function localHost(): string {
  if (host === undefined) {
    const probe = createTemporaryDirectory(root, "staging");
    try {
      host = (readTemporaryOwner(probe.path) as { owner: TemporaryOwner }).owner
        .host;
    } finally {
      probe.remove();
    }
  }
  return host;
}

/**
 * A directory of a process that is not this one, as its marker would have
 * been written: the name has mkdtemp's shape, the record is complete.
 */
function plant(
  name: string,
  owner: Partial<TemporaryOwner> = {},
  options: { ageMs?: number; content?: boolean } = {},
): string {
  const path = join(root, name);
  mkdirSync(path, { mode: 0o700 });
  if (options.content !== false) {
    writeFileSync(join(path, "payload.bin"), "extracted payload");
    mkdirSync(join(path, "x", "nested"), { recursive: true });
    writeFileSync(join(path, "x", "nested", "file"), "nested");
  }
  const record: TemporaryOwner = {
    schema: TEMPORARY_OWNER_SCHEMA,
    kind: "verify",
    name,
    pid: dead,
    instance: "0123456789abcdef",
    host: localHost(),
    created: new Date().toISOString(),
    ...owner,
  };
  const marker = join(path, TEMPORARY_OWNER_FILE);
  writeFileSync(marker, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  if (options.ageMs !== undefined) {
    const then = new Date(Date.now() - options.ageMs);
    utimesSync(marker, then, then);
  }
  return path;
}

describe("createTemporaryDirectory", () => {
  it("makes a private directory with its marker written first", () => {
    const item = create("verify");
    expect(basename(item.path)).toMatch(/^piship-verify-[A-Za-z0-9]{6}$/);
    const found = readTemporaryOwner(item.path);
    expect(found?.owner).toEqual({
      schema: "piship-temporary-owner/v1",
      kind: "verify",
      name: basename(item.path),
      pid: process.pid,
      instance: item.instance,
      host: expect.stringMatching(/^[0-9a-f]{12}$/),
      created: expect.stringMatching(/^\d{4}-\d\d-\d\dT.*Z$/),
    });
    expect(item.instance).toMatch(/^[0-9a-f]{16}$/);
    expect(readdirSync(item.path)).toEqual([TEMPORARY_OWNER_FILE]);
    if (posix) {
      expect(lstatSync(item.path).mode & 0o777).toBe(0o700);
      expect(
        lstatSync(join(item.path, TEMPORARY_OWNER_FILE)).mode & 0o777,
      ).toBe(0o600);
    }
  });

  it("pins the marker format the recovery reads", () => {
    const item = create("build", "acmecode");
    const text = readFileSync(join(item.path, TEMPORARY_OWNER_FILE), "utf8");
    expect(TEMPORARY_OWNER_FILE).toBe(".piship-owner");
    expect(Object.keys(JSON.parse(text)).sort()).toEqual([
      "created",
      "host",
      "instance",
      "kind",
      "name",
      "pid",
      "schema",
    ]);
    // One record and a newline; a planted record has the same shape.
    expect(text.endsWith("}\n")).toBe(true);
    expect(text.length).toBeLessThan(400);
  });

  it("names each kind by its own prefix and label", () => {
    expect(basename(create("sandbox").path)).toMatch(
      /^piship-sandbox-[A-Za-z0-9]{6}$/,
    );
    expect(basename(create("probe").path)).toMatch(
      /^\.piship-probe-[A-Za-z0-9]{6}$/,
    );
    expect(basename(create("launch-check").path)).toMatch(
      /^piship-launch-check-[A-Za-z0-9]{6}$/,
    );
    expect(basename(create("release-test").path)).toMatch(
      /^piship-release-test-[A-Za-z0-9]{6}$/,
    );
    expect(basename(create("staging").path)).toMatch(
      /^\.staging-[A-Za-z0-9]{6}$/,
    );
    expect(basename(create("build", "acme-code").path)).toMatch(
      /^\.piship-acme-code-[A-Za-z0-9]{6}$/,
    );
    expect(basename(create("release", "acme-1.0.0+b1-linux-x64").path)).toMatch(
      /^\.piship-release-acme-1\.0\.0\+b1-linux-x64-[A-Za-z0-9]{6}$/,
    );
  });

  it("refuses a label that could change the name's shape, leaving nothing", () => {
    for (const [kind, label] of [
      ["build", undefined],
      ["build", "../escape"],
      ["build", "Upper"],
      ["release", "a/b"],
      ["release", ""],
    ] as const)
      expect(() => createTemporaryDirectory(root, kind, label)).toThrow(
        /Invalid label/,
      );
    expect(readdirSync(root)).toEqual([]);
  });

  it("removes the directory and stays removed", () => {
    const item = createTemporaryDirectory(root, "verify");
    writeFileSync(join(item.path, "file"), "x");
    item.remove();
    expect(existsSync(item.path)).toBe(false);
    item.remove();
  });
});

describe("reclaimTemporaryDirectories", () => {
  it("removes the directory of a dead owner with everything in it", () => {
    const stale = plant("piship-verify-abc123");
    const result = reclaimTemporaryDirectories(root, ["verify"]);
    expect(result).toEqual({ removed: [stale], failed: [] });
    expect(existsSync(stale)).toBe(false);
  });

  it("keeps the directory of a live process, whatever its age below the lease", () => {
    const running = plant(
      "piship-verify-abc123",
      { pid: livePid() },
      { ageMs: DAY - 60_000 },
    );
    expect(reclaimTemporaryDirectories(root, ["verify"])).toEqual({
      removed: [],
      failed: [],
    });
    expect(existsSync(join(running, "payload.bin"))).toBe(true);
  });

  it("keeps a directory this process holds even when its marker says the owner is gone", () => {
    const mine = create("verify");
    const marker = join(mine.path, TEMPORARY_OWNER_FILE);
    const owner = JSON.parse(readFileSync(marker, "utf8")) as TemporaryOwner;
    writeFileSync(marker, JSON.stringify({ ...owner, pid: dead }));
    expect(reclaimTemporaryDirectories(root, ["verify"]).removed).toEqual([]);
    expect(existsSync(mine.path)).toBe(true);
    // Once released it is an ordinary abandoned directory.
    mine.remove();
    expect(existsSync(mine.path)).toBe(false);
  });

  it("reclaims only the kinds asked for", () => {
    const verify = plant("piship-verify-abc123");
    const sandbox = plant("piship-sandbox-abc123", { kind: "sandbox" });
    const staging = plant(".staging-abc123", { kind: "staging" });
    expect(reclaimTemporaryDirectories(root, ["sandbox"]).removed).toEqual([
      sandbox,
    ]);
    expect(existsSync(verify)).toBe(true);
    expect(existsSync(staging)).toBe(true);
    expect(
      reclaimTemporaryDirectories(root, ["verify", "staging"]).removed.sort(),
    ).toEqual([staging, verify].sort());
  });

  it("finds without removing, for a diagnostic", () => {
    const stale = plant("piship-verify-abc123");
    plant("piship-verify-def456", { pid: livePid() });
    expect(findAbandonedTemporaryDirectories(root, ["verify"])).toEqual([
      stale,
    ]);
    expect(existsSync(stale)).toBe(true);
  });

  it("returns nothing for a root that is missing or not a directory", () => {
    expect(
      reclaimTemporaryDirectories(join(root, "missing"), ["verify"]),
    ).toEqual({ removed: [], failed: [] });
    writeFileSync(join(root, "file"), "x");
    expect(
      findAbandonedTemporaryDirectories(join(root, "file"), ["verify"]),
    ).toEqual([]);
  });

  describe("never touches what is not a marked directory of the kind", () => {
    it("leaves directories that only share part of a name", () => {
      const kept = [
        "piship-verify-notes",
        "piship-verify-abcdefg",
        "piship-verify-",
        "piship-verify",
        "my-piship-verify-abc123",
        "piship-verify-abc123.bak",
        "piship-verify-abc-12",
        "piship-verify-abc123-old",
      ].map((name) => {
        const path = join(root, name);
        mkdirSync(path);
        writeFileSync(join(path, "keep.txt"), "user data");
        return path;
      });
      reclaimTemporaryDirectories(root, ["verify", "sandbox", "staging"]);
      for (const path of kept)
        expect(readFileSync(join(path, "keep.txt"), "utf8")).toBe("user data");
    });

    it("leaves a directory with the exact name shape but no marker, however old", () => {
      const legacy = join(root, "piship-verify-abc123");
      mkdirSync(legacy, { mode: 0o700 });
      writeFileSync(join(legacy, "keep.txt"), "an older PiShip or a user");
      const then = new Date(Date.now() - 400 * DAY);
      utimesSync(legacy, then, then);
      reclaimTemporaryDirectories(root, ["verify"]);
      expect(readFileSync(join(legacy, "keep.txt"), "utf8")).toBe(
        "an older PiShip or a user",
      );
    });

    it("leaves a directory whose marker is unusable", () => {
      const cases: [string, string][] = [
        ["piship-verify-aaaaaa", ""],
        ["piship-verify-bbbbbb", "not json"],
        ["piship-verify-cccccc", "[]"],
        ["piship-verify-dddddd", JSON.stringify({ schema: "other/v1" })],
        ["piship-verify-eeeeee", `{"schema":"${TEMPORARY_OWNER_SCHEMA}"`],
        ["piship-verify-ffffff", "x".repeat(10_000)],
      ];
      for (const [name, text] of cases) {
        const path = join(root, name);
        mkdirSync(path);
        writeFileSync(join(path, "keep.txt"), "kept");
        writeFileSync(join(path, TEMPORARY_OWNER_FILE), text);
      }
      reclaimTemporaryDirectories(root, ["verify"]);
      for (const [name] of cases)
        expect(existsSync(join(root, name, "keep.txt"))).toBe(true);
    });

    it("leaves a directory whose marker names another directory or kind, or a bad field", () => {
      const other = plant("piship-verify-aaaaaa", {
        name: "piship-verify-zzzzzz",
      });
      const kind = plant("piship-verify-bbbbbb", { kind: "sandbox" });
      const pid = plant("piship-verify-cccccc", { pid: 0 });
      const badPid = plant("piship-verify-dddddd", { pid: -5 });
      const instance = plant("piship-verify-eeeeee", { instance: "short" });
      const host = plant("piship-verify-ffffff", { host: "not a token" });
      const created = plant("piship-verify-gggggg", { created: "never" });
      const unknown = plant("piship-verify-hhhhhh", {
        kind: "constructor" as TemporaryKind,
      });
      // A build marker on a name that is not the build shape.
      const shape = plant("piship-verify-iiiiii", { kind: "build" });
      const dirs = [
        other,
        kind,
        pid,
        badPid,
        instance,
        host,
        created,
        unknown,
        shape,
      ];
      reclaimTemporaryDirectories(root, [
        "verify",
        "sandbox",
        "build",
        "staging",
      ]);
      for (const path of dirs)
        expect(existsSync(join(path, "payload.bin"))).toBe(true);
    });

    it("leaves a file or an empty directory of the same name", () => {
      writeFileSync(join(root, "piship-verify-aaaaaa"), "a file");
      mkdirSync(join(root, "piship-verify-bbbbbb"));
      reclaimTemporaryDirectories(root, ["verify"], { now: Date.now() + 9e9 });
      expect(readFileSync(join(root, "piship-verify-aaaaaa"), "utf8")).toBe(
        "a file",
      );
      expect(existsSync(join(root, "piship-verify-bbbbbb"))).toBe(true);
    });

    it("leaves a marked directory whose marker was copied from another", () => {
      const original = plant("piship-verify-aaaaaa");
      const copy = join(root, "piship-verify-bbbbbb");
      mkdirSync(copy);
      writeFileSync(join(copy, "keep.txt"), "kept");
      writeFileSync(
        join(copy, TEMPORARY_OWNER_FILE),
        readFileSync(join(original, TEMPORARY_OWNER_FILE)),
      );
      reclaimTemporaryDirectories(root, ["verify"]);
      expect(existsSync(original)).toBe(false);
      expect(existsSync(join(copy, "keep.txt"))).toBe(true);
    });
  });

  describe("a process ID that is alive but is not the owner", () => {
    it("keeps the directory until the marker has not been refreshed for the lease", () => {
      const unrelated = livePid();
      const path = plant("piship-verify-abc123", { pid: unrelated });
      const marker = join(path, TEMPORARY_OWNER_FILE);
      const created = lstatSync(marker).mtimeMs;
      expect(
        reclaimTemporaryDirectories(root, ["verify"], {
          now: created + TEMPORARY_LEASE_MS - 1_000,
        }).removed,
      ).toEqual([]);
      expect(existsSync(path)).toBe(true);
      expect(
        reclaimTemporaryDirectories(root, ["verify"], {
          now: created + TEMPORARY_LEASE_MS + 1_000,
        }).removed,
      ).toEqual([path]);
    });

    it("keeps the directory of an owner that refreshes its marker", () => {
      const path = plant(
        "piship-verify-abc123",
        { pid: livePid() },
        { ageMs: 3 * DAY },
      );
      expect(findAbandonedTemporaryDirectories(root, ["verify"])).toEqual([
        path,
      ]);
      // What the owner's heartbeat does.
      const now = new Date();
      utimesSync(join(path, TEMPORARY_OWNER_FILE), now, now);
      expect(findAbandonedTemporaryDirectories(root, ["verify"])).toEqual([]);
    });

    it("does not treat a marker dated in the future as expired", () => {
      const path = plant("piship-verify-abc123", { pid: livePid() });
      expect(
        reclaimTemporaryDirectories(root, ["verify"], {
          now: Date.now() - 5 * DAY,
        }).removed,
      ).toEqual([]);
      expect(existsSync(path)).toBe(true);
    });
  });

  describe("another host or container", () => {
    it("does not read a dead-looking process ID as a dead owner", () => {
      const path = plant("piship-verify-abc123", { host: "0123456789ab" });
      expect(reclaimTemporaryDirectories(root, ["verify"]).removed).toEqual([]);
      expect(existsSync(path)).toBe(true);
      const marker = lstatSync(join(path, TEMPORARY_OWNER_FILE)).mtimeMs;
      expect(
        reclaimTemporaryDirectories(root, ["verify"], {
          now: marker + TEMPORARY_LEASE_MS + 1_000,
        }).removed,
      ).toEqual([path]);
    });
  });

  describe.runIf(posix)("links and ownership", () => {
    it("never follows a link with a reclaimable name", () => {
      // A stale directory the link points at, itself named so it is not scanned.
      const real = plant("not-scanned", { name: "piship-verify-linked" });
      symlinkSync(real, join(root, "piship-verify-linked"));
      reclaimTemporaryDirectories(root, ["verify"]);
      expect(
        lstatSync(join(root, "piship-verify-linked")).isSymbolicLink(),
      ).toBe(true);
      expect(existsSync(join(real, "payload.bin"))).toBe(true);
    });

    it("unlinks a link inside a directory without touching what it points to", () => {
      const stale = plant("piship-verify-abc123");
      const outside = join(root, "elsewhere");
      mkdirSync(join(outside, "deep"), { recursive: true });
      writeFileSync(join(outside, "deep", "keep.txt"), "user data");
      symlinkSync(outside, join(stale, "to-directory"));
      symlinkSync(join(outside, "deep", "keep.txt"), join(stale, "to-file"));
      symlinkSync(join(root, "missing"), join(stale, "dangling"));
      const result = reclaimTemporaryDirectories(root, ["verify"]);
      expect(result.removed).toEqual([stale]);
      expect(existsSync(stale)).toBe(false);
      expect(readFileSync(join(outside, "deep", "keep.txt"), "utf8")).toBe(
        "user data",
      );
    });

    it("keeps a directory whose marker is a link", () => {
      const stale = plant("piship-verify-abc123");
      const real = join(root, "marker-elsewhere");
      writeFileSync(real, readFileSync(join(stale, TEMPORARY_OWNER_FILE)));
      rmSync(join(stale, TEMPORARY_OWNER_FILE));
      symlinkSync(real, join(stale, TEMPORARY_OWNER_FILE));
      expect(reclaimTemporaryDirectories(root, ["verify"]).removed).toEqual([]);
      expect(existsSync(join(stale, "payload.bin"))).toBe(true);
    });

    it("keeps a directory that is not the current user's", () => {
      const stale = plant("piship-verify-abc123");
      const uid = process.getuid?.() as number;
      const getuid = vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
      try {
        expect(
          reclaimTemporaryDirectories(root, ["verify"], {
            now: Date.now() + 9e9,
          }),
        ).toEqual({ removed: [], failed: [] });
      } finally {
        getuid.mockRestore();
      }
      expect(existsSync(join(stale, "payload.bin"))).toBe(true);
      expect(reclaimTemporaryDirectories(root, ["verify"]).removed).toEqual([
        stale,
      ]);
    });

    it.runIf(notRoot)(
      "keeps a partly removed directory recognisable, and finishes it next time",
      () => {
        const stale = plant("piship-verify-abc123");
        const locked = join(stale, "x", "nested");
        chmodSync(locked, 0o500);
        try {
          const first = reclaimTemporaryDirectories(root, ["verify"]);
          expect(first).toEqual({ removed: [], failed: [stale] });
          // Its marker is still there, so it is still found.
          expect(findAbandonedTemporaryDirectories(root, ["verify"])).toEqual([
            stale,
          ]);
        } finally {
          chmodSync(locked, 0o700);
        }
        expect(reclaimTemporaryDirectories(root, ["verify"]).removed).toEqual([
          stale,
        ]);
        expect(existsSync(stale)).toBe(false);
      },
    );
  });
});

describe("the heartbeat of a directory this process holds", () => {
  it("refreshes the marker so it is never older than the lease, and stops when released", () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    const item = create("sandbox");
    const marker = join(item.path, TEMPORARY_OWNER_FILE);
    const old = new Date(Date.now() - 2 * DAY);
    utimesSync(marker, old, old);
    expect(vi.getTimerCount()).toBe(1);
    vi.advanceTimersByTime(TEMPORARY_HEARTBEAT_MS);
    expect(Date.now() - lstatSync(marker).mtimeMs).toBeLessThan(5_000);
    item.remove();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("uses one timer for every held directory and none after the last", () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    const a = create("verify");
    const b = create("launch-check");
    expect(vi.getTimerCount()).toBe(1);
    a.remove();
    expect(vi.getTimerCount()).toBe(1);
    b.remove();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not refresh a marker that is no longer its own", () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    const item = create("verify");
    const marker = join(item.path, TEMPORARY_OWNER_FILE);
    const owner = JSON.parse(readFileSync(marker, "utf8")) as TemporaryOwner;
    writeFileSync(
      marker,
      JSON.stringify({ ...owner, instance: "f".repeat(16) }),
    );
    const old = new Date(Date.now() - 2 * DAY);
    utimesSync(marker, old, old);
    vi.advanceTimersByTime(TEMPORARY_HEARTBEAT_MS);
    expect(Date.now() - lstatSync(marker).mtimeMs).toBeGreaterThan(DAY);
  });
});

describe("hard termination", () => {
  const contracts = pathToFileURL(
    fileURLToPath(new URL("../dist/index.js", import.meta.url)),
  ).href;
  /** A process that starts one directory of every kind, then waits to be killed. */
  const script = `
    const { createTemporaryDirectory } = await import(process.env.CONTRACTS);
    const { writeFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const made = [];
    for (const [kind, label] of [
      ["verify"], ["launch-check"], ["release-test"], ["sandbox"],
      ["staging"], ["build", "acme"], ["release", "acme-1.0.0-linux-x64"],
    ]) {
      const dir = createTemporaryDirectory(process.env.ROOT, kind, label);
      writeFileSync(join(dir.path, "tool-output.txt"), "private output");
      made.push(dir.path);
    }
    process.stdout.write(JSON.stringify(made) + "\\n");
    setInterval(() => {}, 1000);
  `;

  /** Start the process, wait until its directories exist, kill it with SIGKILL. */
  async function killedMidOperation(): Promise<string[]> {
    const child = spawn(
      process.execPath,
      ["--input-type=module", "-e", script],
      {
        env: { ...process.env, CONTRACTS: contracts, ROOT: root },
        stdio: ["ignore", "pipe", "inherit"],
      },
    );
    const made = await new Promise<string[]>((resolve, reject) => {
      let text = "";
      child.stdout.on("data", (chunk: Buffer) => {
        text += chunk.toString("utf8");
        if (text.includes("\n")) resolve(JSON.parse(text) as string[]);
      });
      child.on("error", reject);
      child.on("exit", () => reject(new Error("exited before it was ready")));
    });
    const exited = new Promise((resolve) => child.on("exit", resolve));
    child.kill("SIGKILL");
    await exited;
    return made;
  }

  const ALL: TemporaryKind[] = [
    "verify",
    "launch-check",
    "release-test",
    "sandbox",
    "staging",
    "build",
    "release",
  ];

  it("removes what a killed process left, at the next start", async () => {
    const left = await killedMidOperation();
    expect(left).toHaveLength(7);
    for (const path of left)
      expect(readFileSync(join(path, "tool-output.txt"), "utf8")).toBe(
        "private output",
      );
    expect(findAbandonedTemporaryDirectories(root, ALL).sort()).toEqual(
      left.slice().sort(),
    );
    const result = reclaimTemporaryDirectories(root, ALL);
    expect(result.failed).toEqual([]);
    expect(result.removed.sort()).toEqual(left.slice().sort());
    expect(readdirSync(root)).toEqual([]);
  });

  it("does not let leftovers grow across repeated interrupted runs", async () => {
    const counts: number[] = [];
    for (let run = 0; run < 3; run += 1) {
      await killedMidOperation();
      // The next run's own start.
      reclaimTemporaryDirectories(root, ALL);
      counts.push(readdirSync(root).length);
    }
    expect(counts).toEqual([0, 0, 0]);
    // Without the sweep the same runs pile up.
    for (let run = 0; run < 3; run += 1) await killedMidOperation();
    expect(readdirSync(root)).toHaveLength(21);
  });

  it("leaves the directories of a live concurrent process alone", async () => {
    const killed = await killedMidOperation();
    const child = spawn(
      process.execPath,
      ["--input-type=module", "-e", script],
      {
        env: { ...process.env, CONTRACTS: contracts, ROOT: root },
        stdio: ["ignore", "pipe", "inherit"],
      },
    );
    try {
      const live = await new Promise<string[]>((resolve, reject) => {
        let text = "";
        child.stdout.on("data", (chunk: Buffer) => {
          text += chunk.toString("utf8");
          if (text.includes("\n")) resolve(JSON.parse(text) as string[]);
        });
        child.on("error", reject);
      });
      const result = reclaimTemporaryDirectories(root, ALL);
      expect(result.removed.sort()).toEqual(killed.slice().sort());
      for (const path of live)
        expect(readFileSync(join(path, "tool-output.txt"), "utf8")).toBe(
          "private output",
        );
    } finally {
      child.kill("SIGKILL");
      await new Promise((resolve) => child.on("exit", resolve));
    }
    // Once that process is gone too, its directories are abandoned.
    expect(reclaimTemporaryDirectories(root, ALL).removed).toHaveLength(7);
  });
});
