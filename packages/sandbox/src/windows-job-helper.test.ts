import { spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { spawnManaged } from "./process.js";
import {
  HELPER_SOURCE,
  helperDirectory,
  type RunSync,
  windowsJobHelper,
} from "./windows-job-helper.js";
import { windowsJobCommand, windowsJobSupervisor } from "./windows-job.js";

let root: string;
let state: string;
let windows: string;
let host: NodeJS.ProcessEnv;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "piship-job-helper-"));
  state = join(root, "state");
  windows = join(root, "Windows");
  mkdirSync(join(windows, "Microsoft.NET", "Framework64", "v4.0.30319"), {
    recursive: true,
  });
  writeFileSync(
    join(windows, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe"),
    "",
  );
  host = {
    SystemRoot: windows,
    WINDIR: windows,
    PISHIP_STATE_HOME: state,
    TEMP: join(root, "temp"),
  };
});

afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(root, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 100,
  });
});

/** A compiler that writes a file, and a helper that exits with `exit`. */
function fakeRun(options: { compile?: number; exit?: number } = {}): {
  run: RunSync;
  calls: string[];
  cwds: string[];
  compilerArgs: string[];
} {
  const calls: string[] = [];
  const cwds: string[] = [];
  const compilerArgs: string[] = [];
  const run: RunSync = (file, args, _env, _timeout, cwd) => {
    cwds.push(cwd);
    if (file.endsWith("csc.exe")) {
      calls.push("compile");
      compilerArgs.push(...args);
      const out = args.find((arg) => arg.startsWith("/out:"));
      if (out) writeFileSync(out.slice("/out:".length), "fake-exe-bytes");
      return { status: options.compile ?? 0 };
    }
    calls.push("run");
    return { status: options.exit ?? 3 };
  };
  return { run, calls, cwds, compilerArgs };
}

const target = {
  file: "node.exe",
  args: ["-v"],
  cwd: "C:\\work\\demo",
  env: { Path: "C:\\tools\\bin" },
};

describe("windowsJobHelper", () => {
  it("compiles once, proves it with a child, and reuses it", () => {
    const first = fakeRun();
    const path = windowsJobHelper({
      host,
      systemRoot: windows,
      run: first.run,
    });
    expect(path).toMatch(/jobhelper-[0-9a-f]{16}\.exe$/);
    expect(first.calls).toEqual(["compile", "run"]);
    const second = fakeRun();
    expect(
      windowsJobHelper({ host, systemRoot: windows, run: second.run }),
    ).toBe(path);
    expect(second.calls).toEqual([]);
  });

  it("disables the compiler's implicit csc.rsp configuration", () => {
    const { run, compilerArgs } = fakeRun();
    expect(windowsJobHelper({ host, systemRoot: windows, run })).toBeDefined();
    expect(compilerArgs[0]).toBe("/noconfig");
    expect(compilerArgs).toContain("/target:exe");
    expect(compilerArgs).toContain("/r:System.dll");
    expect(compilerArgs).toContain("/r:System.Core.dll");
    expect(compilerArgs).toContain("/r:System.Web.Extensions.dll");
  });

  it("runs the compiler and the check in the build directory, not the workspace", () => {
    const { run, cwds } = fakeRun();
    windowsJobHelper({ host, systemRoot: windows, run });
    expect(cwds).toHaveLength(2);
    for (const cwd of cwds) {
      expect(cwd).not.toBe(process.cwd());
      expect(cwd.startsWith(helperDirectory(host))).toBe(true);
    }
  });

  it("builds in its own directory under the state home", () => {
    windowsJobHelper({ host, systemRoot: windows, run: fakeRun().run });
    expect(helperDirectory(host).startsWith(join(state, ".job-helper"))).toBe(
      true,
    );
    expect(
      readdirSync(helperDirectory(host)).filter((n) => n.startsWith(".build")),
    ).toEqual([]);
  });

  it("rebuilds when the recorded bytes changed", () => {
    const path = windowsJobHelper({
      host,
      systemRoot: windows,
      run: fakeRun().run,
    }) as string;
    writeFileSync(path, "tampered");
    const again = fakeRun();
    const rebuilt = windowsJobHelper({
      host,
      systemRoot: windows,
      run: again.run,
    });
    expect(again.calls).toEqual(["compile", "run"]);
    expect(readFileSync(rebuilt as string, "utf8")).toBe("fake-exe-bytes");
  });

  it("removes an old unrecorded helper but keeps one a racing process just made", () => {
    const dir = helperDirectory(host);
    mkdirSync(dir, { recursive: true });
    const stale = join(dir, "jobhelper-0123456789abcdef.exe");
    const recent = join(dir, "jobhelper-fedcba9876543210.exe");
    writeFileSync(stale, "stale");
    writeFileSync(recent, "recent");
    const old = new Date(Date.now() - 60 * 60 * 1000);
    utimesSync(stale, old, old);
    windowsJobHelper({ host, systemRoot: windows, run: fakeRun().run });
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(recent)).toBe(true);
  });

  it("rebuilds from a corrupt record, and from one whose exe is gone", () => {
    const first = windowsJobHelper({
      host,
      systemRoot: windows,
      run: fakeRun().run,
    }) as string;
    const record = join(helperDirectory(host), "helper.json");
    writeFileSync(record, "{not json");
    const corrupt = fakeRun();
    expect(
      windowsJobHelper({ host, systemRoot: windows, run: corrupt.run }),
    ).toMatch(/jobhelper-[0-9a-f]{16}\.exe$/);
    expect(corrupt.calls).toEqual(["compile", "run"]);
    rmSync(first, { force: true });
    rmSync(
      join(
        helperDirectory(host),
        String(JSON.parse(readFileSync(record, "utf8")).exe),
      ),
      { force: true },
    );
    const missing = fakeRun();
    expect(
      windowsJobHelper({ host, systemRoot: windows, run: missing.run }),
    ).toMatch(/jobhelper-[0-9a-f]{16}\.exe$/);
    expect(missing.calls).toEqual(["compile", "run"]);
  });

  it("tries again once the 24 hour marker has expired", () => {
    expect(
      windowsJobHelper({
        host,
        systemRoot: windows,
        run: fakeRun({ exit: 1 }).run,
      }),
    ).toBeUndefined();
    const marker = join(helperDirectory(host), "unavailable.json");
    const old = new Date(Date.now() - 25 * 60 * 60 * 1000);
    utimesSync(marker, old, old);
    const retry = fakeRun();
    expect(
      windowsJobHelper({ host, systemRoot: windows, run: retry.run }),
    ).toMatch(/jobhelper-[0-9a-f]{16}\.exe$/);
    expect(retry.calls).toEqual(["compile", "run"]);
    expect(existsSync(marker)).toBe(false);
  });

  it("falls back when the state home cannot be written", () => {
    writeFileSync(state, "a file where the state home should be");
    const { run } = fakeRun();
    expect(
      windowsJobHelper({ host, systemRoot: windows, run }),
    ).toBeUndefined();
  });

  it("gives up without a compiler and writes nothing", () => {
    const empty = join(root, "Empty");
    mkdirSync(empty);
    const { run, calls } = fakeRun();
    expect(windowsJobHelper({ host, systemRoot: empty, run })).toBeUndefined();
    expect(calls).toEqual([]);
    expect(existsSync(state)).toBe(false);
  });

  it("does not use a helper that fails its check, and does not retry at once", () => {
    const failing = fakeRun({ exit: 1 });
    expect(
      windowsJobHelper({ host, systemRoot: windows, run: failing.run }),
    ).toBeUndefined();
    expect(failing.calls).toEqual(["compile", "run"]);
    const later = fakeRun();
    expect(
      windowsJobHelper({ host, systemRoot: windows, run: later.run }),
    ).toBeUndefined();
    expect(later.calls).toEqual([]);
  });

  it("does not use a helper that did not compile", () => {
    const { run, calls } = fakeRun({ compile: 1 });
    expect(
      windowsJobHelper({ host, systemRoot: windows, run }),
    ).toBeUndefined();
    expect(calls).toEqual(["compile"]);
  });

  it("can be refused", () => {
    windowsJobHelper({ host, systemRoot: windows, run: fakeRun().run });
    const { run, calls } = fakeRun();
    expect(
      windowsJobHelper({
        host: { ...host, PISHIP_WINDOWS_JOB_HELPER: "off" },
        systemRoot: windows,
        run,
      }),
    ).toBeUndefined();
    expect(calls).toEqual([]);
  });

  it("compiles ASCII source with the same Job Object code as the PowerShell supervisor", () => {
    // biome-ignore lint/suspicious/noControlCharactersInRegex: byte range check
    expect(HELPER_SOURCE).toMatch(/^[\x00-\x7f]*$/);
    expect(HELPER_SOURCE).toContain("public static int Run(ProcessStartInfo");
    expect(HELPER_SOURCE).toContain("static int Main()");
  });
});

describe("windowsJobSupervisor", () => {
  // The helper is built under a stand-in Windows directory; the supervisor
  // validates the real kind of path, so it gets one and finds the same record.
  const supervisorHost = (extra: NodeJS.ProcessEnv = {}) => ({
    SystemRoot: "C:\\Windows",
    WINDIR: "C:\\Windows",
    PISHIP_STATE_HOME: state,
    ...extra,
  });

  it("starts the compiled helper with the request and the child's PATH", () => {
    const path = windowsJobHelper({
      host,
      systemRoot: windows,
      run: fakeRun().run,
    }) as string;
    const command = windowsJobSupervisor(target, supervisorHost());
    expect(command.file).toBe(path);
    expect(command.args).toEqual([]);
    expect(Object.keys(command.env).sort()).toEqual([
      "PATH",
      "PISHIP_JOB_PARENT_PID",
      "PISHIP_JOB_REQUEST",
      "SystemRoot",
      "WINDIR",
    ]);
    expect(command.env.PATH).toBe("C:\\tools\\bin");
    expect(command.env.PISHIP_JOB_REQUEST).toBe(
      windowsJobCommand(target, supervisorHost()).env.PISHIP_JOB_REQUEST,
    );
  });

  it("falls back to PowerShell when there is no helper", () => {
    const off = supervisorHost({ PISHIP_WINDOWS_JOB_HELPER: "off" });
    expect(windowsJobSupervisor(target, off)).toEqual(
      windowsJobCommand(target, off),
    );
  });

  it("still fails closed without an absolute SystemRoot", () => {
    expect(() =>
      windowsJobSupervisor(target, { SystemRoot: "Windows" }),
    ).toThrow(/absolute SystemRoot/);
  });
});

// The real compiled helper, on a machine that has csc.exe.
describe.runIf(process.platform === "win32")(
  "the compiled Job Object helper, live",
  () => {
    beforeEach(() => {
      vi.stubEnv("PISHIP_STATE_HOME", state);
      // The suite turns the helper off for every other file (vitest.config.ts).
      vi.stubEnv("PISHIP_WINDOWS_JOB_HELPER", "on");
    });

    function run(
      script: string,
      stdin?: string,
    ): Promise<{ code: number | null; out: string; err: string }> {
      return new Promise((done) => {
        let out = "";
        let err = "";
        const child = spawnManaged({
          file: process.execPath,
          args: ["-e", script],
          cwd: process.cwd(),
          env: { PATH: process.env.PATH ?? "" },
          stdin: "pipe",
          onStdout: (chunk) => {
            out += chunk.toString("utf8");
          },
          onStderr: (chunk) => {
            err += chunk.toString("utf8");
          },
        });
        if (stdin !== undefined) child.stdin?.end(stdin);
        void child.exited.then((exit) => done({ code: exit.code, out, err }));
      });
    }

    it("compiles on first use and then runs a child with its exit code and streams", async () => {
      const result = await run(
        'process.stdin.on("data", d => { process.stderr.write("boom"); process.stdout.write("echo:" + d); process.exit(7); })',
        "hello",
      );
      expect(result).toMatchObject({ code: 7, out: "echo:hello", err: "boom" });
      const dir = helperDirectory(process.env);
      expect(readdirSync(dir).some((n) => n.endsWith(".exe"))).toBe(true);
    }, 60_000);

    it("kills the child when the helper is killed", async () => {
      await run("0");
      const { file, args, env } = windowsJobSupervisor({
        file: process.execPath,
        args: ["-e", "console.log(process.pid); setInterval(() => {}, 1000)"],
        cwd: process.cwd(),
        env: { PATH: process.env.PATH ?? "" },
      });
      expect(file).not.toMatch(/powershell/i);
      const supervisor = spawn(file, args, { env, windowsHide: true });
      let childPid: number | undefined;
      try {
        childPid = await new Promise<number>((done) =>
          supervisor.stdout.once("data", (chunk) =>
            done(Number(String(chunk))),
          ),
        );
        expect(() => process.kill(childPid as number, 0)).not.toThrow();
        spawn("taskkill", ["/pid", String(supervisor.pid), "/F"], {
          stdio: "ignore",
          windowsHide: true,
        }).on("error", () => {});
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline) {
          try {
            process.kill(childPid, 0);
            await new Promise((wait) => setTimeout(wait, 100));
          } catch {
            childPid = undefined;
            break;
          }
        }
      } finally {
        supervisor.kill();
        if (childPid !== undefined)
          try {
            process.kill(childPid);
          } catch {
            // already gone
          }
      }
      const alive = childPid !== undefined;
      expect(alive).toBe(false);
    }, 60_000);
  },
);
