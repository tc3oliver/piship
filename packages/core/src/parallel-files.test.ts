import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  PARALLEL_MIN_FILES,
  removeTree,
  workerCount,
} from "./parallel-files.js";

const roots: string[] = [];
const temp = () => {
  const root = mkdtempSync(join(tmpdir(), "piship-parallel-"));
  roots.push(root);
  return root;
};
afterEach(() => {
  vi.unstubAllEnvs();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function fill(root: string, count: number): void {
  for (let index = 0; index < count; index++) {
    const file = join(root, `d${index % 6}`, `e${index % 4}`, `f${index}.txt`);
    mkdirSync(join(file, ".."), { recursive: true });
    writeFileSync(file, String(index));
  }
}

describe("workerCount", () => {
  it("keeps a few files on this thread and spreads many, never above eight", () => {
    expect(workerCount(PARALLEL_MIN_FILES - 1)).toBe(1);
    expect(workerCount(PARALLEL_MIN_FILES)).toBeGreaterThanOrEqual(1);
    expect(workerCount(100_000)).toBeLessThanOrEqual(8);
  });

  it("takes PISHIP_FILE_WORKERS for any size, where 1 turns threads off", () => {
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    expect(workerCount(10)).toBe(4);
    expect(workerCount(2)).toBe(2);
    expect(workerCount(100_000)).toBe(4);
    vi.stubEnv("PISHIP_FILE_WORKERS", "1");
    expect(workerCount(100_000)).toBe(1);
    vi.stubEnv("PISHIP_FILE_WORKERS", "64");
    expect(workerCount(100_000)).toBe(8);
    vi.stubEnv("PISHIP_FILE_WORKERS", "nonsense");
    expect(workerCount(10)).toBe(1);
  });
});

describe("removeTree", () => {
  it.each(["1", "4"])(
    "removes a tree, files and directories, with %s thread(s)",
    (workers) => {
      vi.stubEnv("PISHIP_FILE_WORKERS", workers);
      const root = join(temp(), "tree");
      fill(root, 90);
      removeTree(root);
      expect(existsSync(root)).toBe(false);
    },
  );

  it("is not an error when there is nothing to remove", () => {
    const root = temp();
    expect(() => removeTree(join(root, "missing"))).not.toThrow();
  });

  it("removes a link and never what it points at", () => {
    if (process.platform === "win32") return;
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    const outside = temp();
    writeFileSync(join(outside, "keep.txt"), "kept");
    const root = join(temp(), "tree");
    fill(root, 60);
    symlinkSync(outside, join(root, "d0", "link"));
    symlinkSync(join(outside, "keep.txt"), join(root, "d1", "file-link"));
    removeTree(root);
    expect(existsSync(root)).toBe(false);
    expect(readFileSync(join(outside, "keep.txt"), "utf8")).toBe("kept");
  });
});

describe("worker threads of a process started with flags", () => {
  const built = new URL("../dist/parallel-files.js", import.meta.url);

  it.skipIf(!existsSync(fileURLToPath(built)))(
    "still run their code when the process was started as `node --input-type=module -e`",
    () => {
      const root = join(temp(), "tree");
      fill(root, 40);
      const script = `import {removeTree, placeFilesInParallel} from ${JSON.stringify(built.href)};
        import {mkdirSync, writeFileSync, readFileSync} from "node:fs";
        const source = ${JSON.stringify(root)};
        const names = ["d0/e0/f0.txt", "d1/e1/f1.txt", "d2/e2/f2.txt", "d3/e3/f3.txt"];
        const target = source + "-copy";
        for (const name of names) mkdirSync(target + "/" + name.split("/").slice(0, 2).join("/"), {recursive: true});
        process.env.PISHIP_FILE_WORKERS = "2";
        const placed = placeFilesInParallel(2, source, target, names, names.map((n) => readFileSync(source + "/" + n).length), false);
        removeTree(source);
        console.log(JSON.stringify(placed), readFileSync(target + "/d1/e1/f1.txt", "utf8"));`;
      const result = spawnSync(
        process.execPath,
        ["--input-type=module", "-e", script],
        { encoding: "utf8", timeout: 60_000 },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout.trim()).toBe('{"linked":0,"copied":4} 1');
      expect(existsSync(root)).toBe(false);
    },
    90_000,
  );
});
