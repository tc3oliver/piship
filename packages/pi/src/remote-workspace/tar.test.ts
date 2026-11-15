import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { packTar } from "./tar.js";

describe("packTar", () => {
  it.skipIf(process.platform === "win32")(
    "round-trips names no ustar field holds through the system tar",
    async () => {
      const dir = await mkdtemp(join(tmpdir(), "piship-tar-"));
      try {
        const long = `${"n".repeat(140)}.txt`;
        const deep = `${"d/".repeat(90)}${"é".repeat(60)}.txt`;
        const entries = [long, deep, "short.txt"].map((path, i) => ({
          path,
          mode: 0o644,
          data: Buffer.from(`body ${i}`),
        }));
        await writeFile(join(dir, "a.tar"), packTar(entries));
        const out = join(dir, "out");
        spawnSync("mkdir", [out]);
        const run = spawnSync("tar", ["-xf", join(dir, "a.tar"), "-C", out]);
        expect(run.status, String(run.stderr)).toBe(0);
        for (const [i, entry] of entries.entries())
          expect(await readFile(join(out, entry.path), "utf8")).toBe(
            `body ${i}`,
          );
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
  );
});
