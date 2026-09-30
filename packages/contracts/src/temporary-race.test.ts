// A process that can write a directory can forge a marker in it and, while a
// sweep runs, swap the directory (or one inside it) for a link to somewhere
// it cannot write itself. The sweep is PiShip's, unsandboxed: the removal must
// never reach through such a link. Each scenario swaps an entry at exactly the
// step a test names (the `onStep` seam), once with `rm` (where the system has
// one) and once with the portable walk, and checks that the victim directory
// outside the sweep's root, which the forger could not delete itself, is
// intact.
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deadPid } from "../../../tests/helpers/processes.js";
import {
  TEMPORARY_OWNER_FILE,
  TEMPORARY_OWNER_SCHEMA,
  createTemporaryDirectory,
  readTemporaryOwner,
  reclaimTemporaryDirectories,
  usesSystemRemover,
  type ReclaimOptions,
  type TemporaryKind,
  type TemporaryOwner,
} from "./index.js";

const posix = process.platform !== "win32";
const DAY = 24 * 60 * 60_000;

let base: string;
let root: string;
let victim: string;
let dead: number;
beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), "piship-temporary-race-"));
  // The root a sandboxed command can write (a workspace's dist/), and a
  // directory beside it that it cannot: the user's own files.
  root = join(base, "dist");
  victim = join(base, "victim");
  mkdirSync(root);
  mkdirSync(join(victim, "sub"), { recursive: true });
  writeFileSync(join(victim, "keep.txt"), "the user's file");
  writeFileSync(join(victim, "sub", "keep2.txt"), "the user's other file");
  dead = deadPid();
});
afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function host(): string {
  const probe = createTemporaryDirectory(base, "staging");
  try {
    return (readTemporaryOwner(probe.path) as { owner: TemporaryOwner }).owner
      .host;
  } finally {
    probe.remove();
  }
}

/**
 * A directory as a forger makes it: the right name shape, and a marker for a
 * dead owner, dated long ago, written by hand.
 */
function forge(
  name: string,
  kind: TemporaryKind,
  inside: (path: string) => void = () => {},
): string {
  const path = join(root, name);
  mkdirSync(join(path, "x", "deep"), { recursive: true });
  writeFileSync(join(path, "x", "deep", "file"), "forged tree");
  inside(path);
  const marker = join(path, TEMPORARY_OWNER_FILE);
  const owner: TemporaryOwner = {
    schema: TEMPORARY_OWNER_SCHEMA,
    kind,
    name,
    pid: dead,
    instance: "0123456789abcdef",
    host: host(),
    created: new Date(Date.now() - 400 * DAY).toISOString(),
  };
  writeFileSync(marker, JSON.stringify(owner));
  const then = new Date(Date.now() - 400 * DAY);
  utimesSync(marker, then, then);
  return path;
}

function victimIntact(): void {
  expect(readFileSync(join(victim, "keep.txt"), "utf8")).toBe(
    "the user's file",
  );
  expect(readFileSync(join(victim, "sub", "keep2.txt"), "utf8")).toBe(
    "the user's other file",
  );
}

/** Aside the entry at `path` and put a link to the victim where it was. */
function swapForLink(path: string): void {
  renameSync(path, `${path}.aside`);
  symlinkSync(victim, path);
}

// The scenarios below run with `rm` only where the system has one that
// passed PiShip's own check; on Linux and macOS it does.
it.runIf(process.platform === "linux" || process.platform === "darwin")(
  "finds a usable system remover on Linux and macOS",
  () => {
    expect(usesSystemRemover()).toBe(true);
  },
);

const removers: [string, ReclaimOptions["remover"]][] = [
  ["the system remover", undefined],
  ["the portable walk", "portable"],
];

describe.runIf(posix).each(removers)("with %s", (_name, remover) => {
  const reclaim = (
    options: ReclaimOptions = {},
    kinds: TemporaryKind[] = ["build"],
  ) =>
    reclaimTemporaryDirectories(root, kinds, {
      ...(remover ? { remover } : {}),
      ...options,
    });

  it("removes a forged directory, which is all a forged marker can ask for", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    const result = reclaim();
    expect(result).toEqual({ removed: [path], failed: [] });
    expect(readdirSync(root)).toEqual([]);
    victimIntact();
  });

  it("does not follow a link swapped in for the directory after it was judged", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    const result = reclaim({
      onStep: (step, at) => {
        if (step === "found") swapForLink(at);
      },
    });
    expect(result).toEqual({ removed: [], failed: [path] });
    victimIntact();
    // What was swapped in is left as it is; so is what it replaced.
    expect(lstatSync(path).isSymbolicLink()).toBe(true);
    expect(existsSync(join(`${path}.aside`, "x", "deep", "file"))).toBe(true);
  });

  it("does not follow a link swapped in after the directory was moved aside", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    const result = reclaim({
      onStep: (step, at) => {
        if (step !== "renamed") return;
        expect(basename(at)).toMatch(/^\.piship-reclaim-[0-9a-f]{16}$/);
        swapForLink(at);
      },
    });
    expect(result.removed).toEqual([]);
    expect(result.failed).toEqual([path]);
    victimIntact();
    // Put back under the name it was found under, link and all.
    expect(lstatSync(path).isSymbolicLink()).toBe(true);
  });

  it("stops at a different directory with the same name, whatever marker it has", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    let other = "";
    const result = reclaim({
      onStep: (step, at) => {
        if (step !== "found") return;
        // A second, real directory, with a marker as valid as the first's.
        renameSync(at, `${at}.aside`);
        mkdirSync(join(at, "x"), { recursive: true });
        writeFileSync(join(at, "x", "file"), "the replacement");
        writeFileSync(
          join(at, TEMPORARY_OWNER_FILE),
          readFileSync(join(`${at}.aside`, TEMPORARY_OWNER_FILE)),
        );
        other = at;
      },
    });
    expect(result).toEqual({ removed: [], failed: [path] });
    expect(readFileSync(join(other, "x", "file"), "utf8")).toBe(
      "the replacement",
    );
  });

  it("puts a different directory that took the moved one's place back under the name", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    const result = reclaim({
      onStep: (step, at) => {
        if (step !== "renamed") return;
        renameSync(at, `${at}.aside`);
        mkdirSync(join(at, "x"), { recursive: true });
        writeFileSync(join(at, "x", "file"), "the replacement");
      },
    });
    expect(result).toEqual({ removed: [], failed: [path] });
    expect(readFileSync(join(path, "x", "file"), "utf8")).toBe(
      "the replacement",
    );
  });

  it("finds a directory another sweep already removed gone, not failed", () => {
    forge(".piship-acme-AAAAAA", "build");
    let inner: ReturnType<typeof reclaimTemporaryDirectories> | undefined;
    const result = reclaim({
      onStep: (step) => {
        if (step === "found" && !inner)
          inner = reclaimTemporaryDirectories(
            root,
            ["build"],
            remover ? { remover } : {},
          );
      },
    });
    expect(inner?.removed).toHaveLength(1);
    expect(result).toEqual({ removed: [], failed: [] });
    expect(readdirSync(root)).toEqual([]);
  });

  it("unlinks a link inside the directory, however deep, without following it", () => {
    const path = forge(".piship-acme-AAAAAA", "build", (dir) => {
      symlinkSync(victim, join(dir, "x", "to-victim"));
      symlinkSync(join(victim, "sub"), join(dir, "x", "deep", "to-sub"));
      symlinkSync(join(victim, "keep.txt"), join(dir, "to-file"));
    });
    expect(reclaim()).toEqual({ removed: [path], failed: [] });
    victimIntact();
  });

  it("moves a sandbox session's tmp aside first, cutting the paths into it", () => {
    const path = forge("piship-sandbox-AAAAAA", "sandbox", (dir) => {
      mkdirSync(join(dir, "tmp", "work"), { recursive: true });
      writeFileSync(join(dir, "tmp", "work", "tool-output.txt"), "output");
    });
    let seen: string[] = [];
    const result = reclaim(
      {
        onStep: (step, at) => {
          if (step === "renamed") seen = readdirSync(at).sort();
        },
      },
      ["sandbox"],
    );
    expect(result).toEqual({ removed: [path], failed: [] });
    expect(seen.filter((name) => name === "tmp")).toEqual([]);
    expect(seen.some((name) => /^tmp-[0-9a-f]{16}$/.test(name))).toBe(true);
  });
});

describe.runIf(posix)("the portable walk", () => {
  const portable = (options: ReclaimOptions = {}) =>
    reclaimTemporaryDirectories(root, ["build"], {
      remover: "portable",
      ...options,
    });

  it("does not follow a subdirectory swapped for a link before it lists it", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    const result = portable({
      onStep: (step, at) => {
        // The walk is about to list `x`, which it just examined as a real
        // directory.
        if (step === "walk" && basename(at) === "x") swapForLink(at);
      },
    });
    expect(result.removed).toEqual([]);
    expect(result.failed).toEqual([path]);
    victimIntact();
  });

  it("does not follow a deep subdirectory swapped the same way", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    const result = portable({
      onStep: (step, at) => {
        if (step === "walk" && basename(at) === "deep") swapForLink(at);
      },
    });
    expect(result).toEqual({ removed: [], failed: [path] });
    victimIntact();
  });

  it("removes nothing, and keeps the marker, when it stops", () => {
    const path = forge(".piship-acme-AAAAAA", "build");
    portable({
      onStep: (step, at) => {
        if (step === "walk" && basename(at) === "deep") swapForLink(at);
      },
    });
    // Put back under its name with a readable marker: the next sweep, once the
    // swapped entry is gone, finishes the job.
    expect(readTemporaryOwner(path)?.owner.kind).toBe("build");
    rmSync(join(path, "x", "deep"));
    renameSync(join(path, "x", "deep.aside"), join(path, "x", "deep"));
    expect(portable()).toEqual({ removed: [path], failed: [] });
    victimIntact();
  });
});

describe.runIf(posix).each(removers)(
  "a removal killed after it moved the directory, with %s",
  (_name, remover) => {
    const reclaim = (options: ReclaimOptions = {}) =>
      reclaimTemporaryDirectories(root, ["build"], {
        ...(remover ? { remover } : {}),
        ...options,
      });
    /** What a process killed right after the rename leaves: the moved directory. */
    const killedAfterRename = (name: string) => {
      const path = forge(name, "build");
      reclaim({
        onStep: (step) => {
          if (step === "renamed") throw new Error("killed");
        },
      });
      const [moved] = readdirSync(root);
      expect(moved).toMatch(/^\.piship-reclaim-[0-9a-f]{16}$/);
      expect(existsSync(path)).toBe(false);
      return join(root, moved as string);
    };
    const IDLE = 11 * 60_000;

    it("is finished by a later sweep once the directory has been idle", () => {
      const moved = killedAfterRename(".piship-acme-AAAAAA");
      // A removal still at work on it changes it: not yet.
      expect(reclaim()).toEqual({ removed: [], failed: [] });
      expect(existsSync(join(moved, "x", "deep", "file"))).toBe(true);
      // `rm` removes in any order: the marker may be gone, and it is still found.
      rmSync(join(moved, TEMPORARY_OWNER_FILE));
      const result = reclaim({ now: Date.now() + IDLE });
      expect(result).toEqual({ removed: [moved], failed: [] });
      expect(readdirSync(root)).toEqual([]);
      victimIntact();
    });

    it("never follows a link swapped in for it", () => {
      const moved = killedAfterRename(".piship-acme-AAAAAA");
      const result = reclaim({
        now: Date.now() + IDLE,
        onStep: (step, at) => {
          if (step === "renamed") swapForLink(at);
        },
      });
      expect(result.removed).toEqual([]);
      expect(result.failed).toEqual([moved]);
      victimIntact();
    });

    it("leaves a link, a file, and another user's directory of that name", () => {
      const name = ".piship-reclaim-0123456789abcdef";
      symlinkSync(victim, join(root, name));
      reclaim({ now: Date.now() + IDLE });
      expect(lstatSync(join(root, name)).isSymbolicLink()).toBe(true);
      rmSync(join(root, name));
      writeFileSync(join(root, name), "a file");
      reclaim({ now: Date.now() + IDLE });
      expect(readFileSync(join(root, name), "utf8")).toBe("a file");
      rmSync(join(root, name));
      mkdirSync(join(root, name));
      const uid = process.getuid?.() as number;
      const getuid = vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
      try {
        reclaim({ now: Date.now() + IDLE });
      } finally {
        getuid.mockRestore();
      }
      expect(existsSync(join(root, name))).toBe(true);
    });
  },
);
