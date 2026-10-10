import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { branded, windowsArgv } from "./distribution.js";

// Arguments that break a naive `args.join(" ")`: argument boundaries,
// cmd.exe metacharacters, MSVCRT quoting rules. `%`-forms are covered
// separately: through a `.cmd` target's `%*` they hit the batch re-expansion
// (which deletes an undefined `%name%`), a case no escaping scheme settles;
// the model tests below pin down what the escaping does claim.
const HOSTILE: readonly string[] = [
  "a phrase with spaces",
  'notify "bob" & retry',
  'say "quoted" then \\ exit',
  "trailing backslash\\",
  "caret^here",
  "pipe|me",
  "redirect>out",
  "redirect<in",
  "(parens)",
  "!bang!",
  "",
  "semi;colon",
  "comma,sep",
  "back`tick",
  "single'quote",
  "star*glob?mark",
  "tab\tinside",
  'a\\"b',
];

// A second-command detector: if the cmd.exe escaping ever loses its grip on
// this argument, it runs as `echo PWNED > pwned.txt` in the spawn directory
// and leaves the file behind, which the real-spawn test asserts against.
const CANARY = "canary & echo PWNED > pwned.txt";

/**
 * cmd.exe phase 1: `%VAR%` expansion, which happens before any caret is
 * read. A name cmd does not find on a `/c` command line stays literal (in a
 * batch file it would be deleted; the model covers the `/c` line).
 */
function expandPercent(line: string, env: Record<string, string>): string {
  return line.replace(/%([^%]+)%/g, (match: string, name: string) =>
    Object.hasOwn(env, name) ? (env[name] as string) : match,
  );
}

/**
 * cmd.exe phase 2: caret processing, outside double quotes only. Returns
 * the command line the target's CRT parser sees, and how many unescaped
 * separators were live for cmd itself (each one could have started a second
 * command). Every quote an escaped argument carries is itself caret-escaped,
 * so cmd's quote state never toggles inside an argument.
 */
function caretDecode(line: string): { text: string; liveSeparators: number } {
  let text = "";
  let liveSeparators = 0;
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] as string;
    if (ch === '"') inQuotes = !inQuotes;
    else if (ch === "^" && !inQuotes && i + 1 < line.length) {
      text += line[++i];
      continue;
    } else if (!inQuotes && "&|<>()".includes(ch)) liveSeparators++;
    text += ch;
  }
  return { text, liveSeparators };
}

/** The MSVCRT rules (`CommandLineToArgvW`) the child program parses with. */
function crtParse(line: string): string[] {
  const argv: string[] = [];
  let current = "";
  let started = false;
  let inQuotes = false;
  let slashes = 0;
  for (const ch of line) {
    if (ch === "\\") {
      slashes++;
      continue;
    }
    if (ch === '"') {
      current += "\\".repeat(slashes >> 1);
      if (slashes % 2 === 1) current += '"';
      else inQuotes = !inQuotes;
      slashes = 0;
      started = true;
      continue;
    }
    current += "\\".repeat(slashes);
    slashes = 0;
    if ((ch === " " || ch === "\t") && !inQuotes) {
      if (started) argv.push(current);
      current = "";
      started = false;
      continue;
    }
    current += ch;
    started = true;
  }
  current += "\\".repeat(slashes);
  if (started) argv.push(current);
  return argv;
}

/** What cmd.exe does with the `windowsArgv` vector, in documented phases. */
function modelCmd(vector: string[], env: Record<string, string> = {}) {
  // `/s /c "line"` strips the first and the last quote and runs the rest.
  expect(vector.slice(0, 3)).toEqual(["/d", "/s", "/c"]);
  const quoted = vector[3] as string;
  expect(quoted.startsWith('"') && quoted.endsWith('"')).toBe(true);
  const inner = expandPercent(quoted.slice(1, -1), env);
  return caretDecode(inner);
}

describe("windowsArgv", () => {
  it("delivers hostile arguments intact to an executable target", () => {
    // The model splits the command token on the first space, as cmd's own
    // tokenizer would for a command with no escaped space; the harness only
    // runs commands from temporary directories, which have no spaces.
    const command = "C:\\apps\\acmecode\\bin\\agent.exe";
    const { text, liveSeparators } = modelCmd(windowsArgv(command, HOSTILE));
    expect(liveSeparators).toBe(0);
    expect(crtParse(text)).toEqual([command, ...HOSTILE]);
  });

  it("delivers hostile arguments intact through a .cmd shim's %*", () => {
    // A .cmd target parses twice: once for the `/c` line, once when the
    // batch re-expands `%*` into `node "<launcher>" %*`, so every
    // metacharacter needs two caret levels (npm's promise-spawn agrees).
    const command = "C:\\apps\\acmecode\\bin\\acmecode.cmd";
    const node = "C:\\nodejs\\node.exe";
    const launcher = "C:\\apps\\acmecode\\bin\\acmecode";
    // `50%PATH%` with a defined PATH proves the caret inside the escaped
    // name survives both stages and cmd never expands the variable. The
    // canary proves no separator in it goes live at either stage.
    const args = [...HOSTILE, "50%PATH%", CANARY];
    const phase1 = modelCmd(windowsArgv(command, args), {
      PATH: "C:\\expanded\\path",
    });
    expect(phase1.liveSeparators).toBe(0);
    expect(phase1.text.startsWith(command)).toBe(true);
    const tail = phase1.text.slice(command.length + 1);
    // `%*` substitution does not re-run percent expansion, so phase 2 is a
    // caret decode only.
    const phase2 = caretDecode(`"${node}" "${launcher}" ${tail}`);
    expect(phase2.liveSeparators).toBe(0);
    expect(crtParse(phase2.text)).toEqual([node, launcher, ...args]);
  });

  it("leaves %VAR% literal even when the variable is defined", () => {
    // `%VAR%` expansion runs before carets are read, but the caret lands
    // inside the variable name (`^%PATH^%` scans as `P^A^T^H^`), which no
    // variable is called, so cmd finds nothing to expand. A defined PATH
    // must not reach the child.
    const command = "C:\\bin\\agent.exe";
    const { text } = modelCmd(
      windowsArgv(command, ["50%PATH%", "%PATH%", "%PISHIP_NO_SUCH_VARIABLE%"]),
      { PATH: "C:\\expanded\\path" },
    );
    expect(crtParse(text)).toEqual([
      command,
      "50%PATH%",
      "%PATH%",
      "%PISHIP_NO_SUCH_VARIABLE%",
    ]);
  });

  it("produces no second command from separators", () => {
    const command = "C:\\bin\\agent.exe";
    const { text, liveSeparators } = modelCmd(
      windowsArgv(command, [
        "a & taskkill /f /im node.exe",
        "x | del C:\\*",
        "y > C:\\Windows\\System32\\evil",
        "z < input",
      ]),
    );
    expect(liveSeparators).toBe(0);
    expect(crtParse(text)).toEqual([
      command,
      "a & taskkill /f /im node.exe",
      "x | del C:\\*",
      "y > C:\\Windows\\System32\\evil",
      "z < input",
    ]);
  });

  it("leaves a plain argument vector readable", () => {
    expect(windowsArgv("C:\\bin\\agent.exe", ["doctor"])).toEqual([
      "/d",
      "/s",
      "/c",
      '"C:\\bin\\agent.exe ^"doctor^""',
    ]);
  });
});

describe("branded", () => {
  const temporary: string[] = [];
  afterAll(() => {
    for (const path of temporary.splice(0))
      rmSync(path, { recursive: true, force: true });
  });
  const scratch = () => {
    const dir = mkdtempSync(join(tmpdir(), "piship-distribution-test-"));
    temporary.push(dir);
    return dir;
  };

  it("gives the child exactly the arguments it was handed", async () => {
    // The child echoes its own argv back, so this is the real thing, not a
    // model. POSIX spawns directly; on Windows CI this same test goes
    // through cmd.exe with windowsArgv's escaping.
    const result = await branded(
      process.execPath,
      [
        "-e",
        "process.stdout.write(JSON.stringify(process.argv.slice(1)))",
        "50%PATH%",
        ...HOSTILE,
      ],
      { cwd: scratch(), env: { ...process.env } },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(["50%PATH%", ...HOSTILE]);
  });

  // The double caret level for a .cmd target only exists on Windows, but
  // this is where the real `cmd.exe` proves it, in the unit tier CI runs on
  // windows-latest. The fixture is the shim `piship build` writes.
  it.skipIf(process.platform !== "win32")(
    "gives a .cmd shim's child exactly the arguments",
    async () => {
      const dir = scratch();
      const script = join(dir, "argv-echo.cjs");
      writeFileSync(
        script,
        "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n",
      );
      const shim = join(dir, "echo.cmd");
      writeFileSync(
        shim,
        `@echo off\r\n"${process.execPath}" "${script}" %*\r\n`,
      );
      const args = ["50%PATH%", ...HOSTILE, CANARY];
      const result = await branded(shim, args, {
        cwd: dir,
        env: { ...process.env },
        timeoutMs: 30_000,
      });
      expect(result.status, result.stderr).toBe(0);
      // `%PATH%` is defined on every Windows runner: this is the real
      // proof that the caret inside the escaped name keeps cmd's
      // percent-expansion from touching it.
      expect(JSON.parse(result.stdout)).toEqual(args);
      // The canary argument must reach the child as data: had any `&` or
      // `>` gone live, cmd would have run the second command and left this
      // file in the working directory.
      expect(existsSync(join(dir, "pwned.txt"))).toBe(false);
    },
  );
});
