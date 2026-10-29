import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { grantCommandWords, simpleCommands } from "./shell-words.js";

describe("shared shell tokenizer", () => {
  it("keeps quoted separators as words and refuses executable syntax in grants", () => {
    expect(grantCommandWords('npm run "a;b"', "posix")).toEqual([
      "npm",
      "run",
      "a;b",
    ]);
    expect(grantCommandWords("pytest -k 'a or b|c'", "posix")).toEqual([
      "pytest",
      "-k",
      "a or b|c",
    ]);
    for (const input of [
      "npm test; id",
      "npm test && id",
      "npm test | sh",
      "npm test > result",
      "npm test $(id)",
      "npm test `id`",
      'npm run "$HOME"',
      "npm test\\; id",
      "npm test\n id",
      'npm run "unclosed',
    ])
      expect(grantCommandWords(input, "posix")).toBeUndefined();
    expect(grantCommandWords("git log --format=%H", "posix")).toEqual([
      "git",
      "log",
      "--format=%H",
    ]);
    expect(grantCommandWords("git log --format=%H", "win32")).toBeUndefined();
    expect(grantCommandWords("npm\u00a0test", "posix")).toBeUndefined();
    expect(grantCommandWords("npm run 'a&b'", "win32")).toBeUndefined();
    expect(grantCommandWords('npm run "a^&b"', "win32")).toBeUndefined();
    expect(grantCommandWords('npm run "a\\\" & whoami"', "win32")).toBeUndefined();
    expect(grantCommandWords("git diff 'src/a b.ts'", "win32")).toEqual([
      "git",
      "diff",
      "src/a b.ts",
    ]);
    expect(simpleCommands("git push origin main; echo ok").commands).toEqual([
      ["git", "push", "origin", "main"],
      ["echo", "ok"],
    ]);
  });

  it.skipIf(process.platform === "win32")(
    "matches bash word splitting for deterministic quoted arguments",
    () => {
      const probe = spawnSync("bash", ["-c", "true"], { encoding: "utf8" });
      if (probe.error) return;
      expect(probe.status).toBe(0);
      let seed = 271828;
      const next = () => {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        return seed;
      };
      const alphabet = "abc xyz;|&()";
      for (let trial = 0; trial < 100; trial++) {
        const value = Array.from(
          { length: 1 + (next() % 24) },
          () => alphabet[next() % alphabet.length],
        ).join("");
        const command = `npm run "${value}"`;
        const parsed = grantCommandWords(command, "posix");
        const bash = spawnSync(
          "bash",
          ["-c", `set -- ${command}; printf '%s\\0' "$@"`],
          { encoding: "utf8" },
        );
        expect(bash.status).toBe(0);
        expect(parsed).toEqual(bash.stdout.split("\0").slice(0, -1));
      }
    },
  );
});
