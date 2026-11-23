import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { delimiter } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveGit } from "./git-run.js";

describe("resolveGit", () => {
  it("resolves git to an absolute PATH entry on Windows, ignoring relative entries", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-git-"));
    try {
      const bin = join(root, "bin");
      mkdirSync(bin);
      writeFileSync(join(bin, "git.exe"), "");
      writeFileSync(join(bin, "git.cmd"), "");
      const env = { PATH: ["", ".", bin].join(delimiter) };
      expect(resolveGit(env, "win32")).toBe(join(bin, "git.exe"));
      // A relative PATH entry (cwd) is never searched, and git.cmd is ignored.
      expect(() => resolveGit({ PATH: "." }, "win32")).toThrow(/not found/);
      writeFileSync(join(root, "git.cmd"), "");
      expect(() => resolveGit({ PATH: root }, "win32")).toThrow(/not found/);
      // Windows PATH entries may be quoted.
      expect(resolveGit({ PATH: `"${bin}"` }, "win32")).toBe(
        join(bin, "git.exe"),
      );
      expect(resolveGit(env, "linux")).toBe("git");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
