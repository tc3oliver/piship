// Replacing a bundled tool another session is running, as Windows behaves:
// the executable cannot be overwritten or deleted, only moved aside. The
// launch must still succeed, and a later launch removes what was moved aside.
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DistributionLock } from "@piship/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installSearchTools } from "./search-tools.js";

const busy = vi.hoisted(() => ({ paths: new Set<string>() }));

vi.mock("node:fs", async (original) => {
  const actual = await original<typeof import("node:fs")>();
  const refuse = (path: fs.PathLike) => {
    const error = new Error(`EBUSY: resource busy or locked, ${path}`);
    (error as NodeJS.ErrnoException).code = "EBUSY";
    throw error;
  };
  return {
    ...actual,
    // Overwriting a running executable fails; moving it aside works.
    renameSync: (from: fs.PathLike, to: fs.PathLike) =>
      busy.paths.has(String(to)) && actual.existsSync(to)
        ? refuse(to)
        : actual.renameSync(from, to),
    // Deleting a running executable (moved aside or not) fails.
    rmSync: (path: fs.PathLike, options?: fs.RmOptions) =>
      [...busy.paths].some((held) => String(path).startsWith(`${held}.`)) &&
      String(path).includes(".piship-replaced-")
        ? refuse(path)
        : actual.rmSync(path, options),
  };
});

const roots: string[] = [];
afterEach(() => {
  busy.paths.clear();
  for (const root of roots.splice(0))
    fs.rmSync(root, { recursive: true, force: true });
});

const sha = (content: string) =>
  `sha256-${createHash("sha256").update(content).digest("hex")}`;

describe("replacing a running bundled tool", () => {
  it("succeeds although the old executable cannot be deleted, and a later launch removes it", () => {
    const root = fs.mkdtempSync(join(tmpdir(), "piship-pi-busy-"));
    roots.push(root);
    const target = "win32-x64";
    const content = "rg 15.2.0 for win32-x64\n";
    fs.mkdirSync(join(root, "payload", "tools"), { recursive: true });
    fs.writeFileSync(join(root, "payload", "tools", "rg.exe"), content);
    const lock = {
      searchTools: {
        rg: {
          version: "15.2.0",
          source: "https://github.com/BurntSushi/ripgrep",
          targets: {
            [target]: {
              url: "https://github.com/BurntSushi/ripgrep/rg.zip",
              archive: sha("archive"),
              entry: "rg/rg.exe",
              binary: sha(content),
              size: content.length,
            },
          },
        },
      },
    } as unknown as Pick<DistributionLock, "searchTools">;
    const agentDir = join(root, "agent");
    const bin = join(agentDir, "bin");
    const rg = join(bin, "rg.exe");
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(rg, "an older rg another session runs\n", {
      mode: 0o755,
    });
    busy.paths.add(rg);

    installSearchTools(lock, join(root, "payload"), agentDir, target);
    expect(fs.readFileSync(rg, "utf8")).toBe(content);
    const leftover = fs
      .readdirSync(bin)
      .filter((name) => name.includes(".piship-replaced-"));
    expect(leftover).toHaveLength(1);

    // The other session has ended: the next launch removes it.
    busy.paths.clear();
    installSearchTools(lock, join(root, "payload"), agentDir, target);
    expect(fs.readdirSync(bin).sort()).toEqual([
      ".piship-search-tools.json",
      "rg.exe",
    ]);
  });
});
