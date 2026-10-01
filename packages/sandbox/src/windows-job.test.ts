import { afterEach, describe, expect, it, vi } from "vitest";
import { spawnManaged, spawnProcess } from "./process.js";
import { windowsJobCommand } from "./windows-job.js";

const target = {
  file: "node.exe",
  args: ["-v"],
  cwd: "C:\\work\\demo",
  env: { Path: "C:\\tools\\bin", DOCS_MODE: "demo" },
};

const host = {
  SystemRoot: "C:\\Windows",
  WINDIR: "C:\\Windows",
  TEMP: "C:\\Users\\dev\\AppData\\Local\\Temp",
  TMP: "C:\\Users\\dev\\AppData\\Local\\Temp",
  USERPROFILE: "C:\\Users\\dev",
  psmoduleanalysiscachepath:
    "C:\\PSModuleAnalysisCachePath\\ModuleAnalysisCache",
  PATH: "C:\\launcher\\bin",
  ComSpec: "C:\\Windows\\System32\\cmd.exe",
  ACMECODE_API_KEY: "fixture-launcher-key",
  GITHUB_TOKEN: "fixture-launcher-token",
};

function request(env: NodeJS.ProcessEnv): Record<string, unknown> {
  return JSON.parse(
    Buffer.from(env.PISHIP_JOB_REQUEST ?? "", "base64").toString("utf8"),
  );
}

describe("windowsJobCommand", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("starts the system PowerShell by absolute path", () => {
    const command = windowsJobCommand(target, host);
    expect(command.file).toBe(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    );
    expect(
      windowsJobCommand(target, { ...host, SystemRoot: "D:\\Win\\" }).file,
    ).toBe("D:\\Win\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  });

  it("gives the supervisor only the variables it needs", () => {
    const { env } = windowsJobCommand(target, host);
    expect(Object.keys(env).sort()).toEqual([
      "PATH",
      "PISHIP_JOB_REQUEST",
      "SystemRoot",
      "TEMP",
      "TMP",
      "WINDIR",
    ]);
    // Windows names match case-insensitively.
    expect(env.PSModuleAnalysisCachePath).toBeUndefined();
    expect(env.PATH).toBe("C:\\tools\\bin");
    expect(JSON.stringify(env)).not.toContain("fixture-launcher");
    expect(env.ComSpec).toBeUndefined();
    expect(env.USERPROFILE).toBeUndefined();
  });

  it("carries the child's approved environment in the request", () => {
    const { env } = windowsJobCommand(target, host);
    expect(request(env)).toEqual({
      ...target,
      env: {
        ...target.env,
        SystemRoot: "C:\\Windows",
        WINDIR: "C:\\Windows",
      },
    });
  });

  it("falls back to WINDIR, and fails closed without an absolute one", () => {
    expect(windowsJobCommand(target, { WINDIR: "C:\\Windows" }).file).toBe(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    );
    for (const bad of [
      {},
      { SystemRoot: "" },
      { SystemRoot: "Windows" },
      { SystemRoot: ".\\Windows" },
      { SystemRoot: "\\Windows" },
      { SystemRoot: "C:Windows" },
      { SystemRoot: "C:\\..\\work" },
    ])
      expect(() => windowsJobCommand(target, bad)).toThrow(
        /absolute SystemRoot/,
      );
  });

  it("does not start anything when SystemRoot cannot be resolved", async () => {
    vi.stubEnv("SystemRoot", "Windows");
    vi.stubEnv("WINDIR", "");
    const child = spawnProcess({
      file: "node.exe",
      cwd: process.cwd(),
      env: {},
      platform: "win32",
    });
    expect(child.pid).toBeUndefined();
    expect(await child.exited).toMatchObject({
      code: null,
      cancelled: false,
      error: expect.stringContaining("absolute SystemRoot"),
    });
  });
});

// The real supervisor: spawnManaged starts the system powershell.exe by
// absolute path, which compiles the Job Object helper and starts a real
// child. Launcher secrets reach neither the child nor any output.
describe.runIf(process.platform === "win32")(
  "the Windows Job Object supervisor, live",
  () => {
    afterEach(() => {
      vi.unstubAllEnvs();
    });

    it("runs a governed child to its marker and exit 0 with only the approved environment", async () => {
      vi.stubEnv("PISHIP_TEST_SECRET", "should-not-arrive-1");
      vi.stubEnv("GITHUB_TOKEN", "should-not-arrive-2");
      let stdout = "";
      let stderr = "";
      const started = Date.now();
      const child = spawnManaged({
        file: process.execPath,
        args: [
          "-e",
          'process.stdout.write("piship-windows-job-ok " + JSON.stringify(process.env) + "\\n")',
        ],
        cwd: process.cwd(),
        env: { PATH: process.env.PATH ?? "", DOCS_MODE: "demo" },
        onStdout: (chunk) => {
          stdout += chunk.toString("utf8");
        },
        onStderr: (chunk) => {
          stderr += chunk.toString("utf8");
        },
      });
      const result = await child.exited;
      const elapsed = Date.now() - started;
      const output = `stdout: ${stdout}\nstderr: ${stderr}`;
      expect(result, output).toMatchObject({ code: 0, timedOut: false });
      // PowerShell must not search every installed module for its cmdlets:
      // without a warm module analysis cache that took 20 to 30 seconds.
      expect(elapsed, output).toBeLessThan(2000);
      const line = stdout
        .split("\n")
        .find((entry) => entry.startsWith("piship-windows-job-ok "));
      expect(line, output).toBeDefined();
      const env = JSON.parse(
        (line as string).slice("piship-windows-job-ok ".length),
      ) as Record<string, string>;
      expect(env.DOCS_MODE).toBe("demo");
      const names = Object.keys(env).map((name) => name.toUpperCase());
      expect(names).not.toContain("PISHIP_TEST_SECRET");
      expect(names).not.toContain("GITHUB_TOKEN");
      // Only the approved variables, plus SystemRoot and WINDIR, which
      // CreateProcess needs in an explicit block.
      expect(names.sort()).toEqual(
        ["DOCS_MODE", "PATH", "SYSTEMROOT", "WINDIR"].sort(),
      );
      expect(stdout + stderr).not.toContain("should-not-arrive");
    });
  },
);
