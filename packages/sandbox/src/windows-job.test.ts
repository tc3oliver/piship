import { afterEach, describe, expect, it, vi } from "vitest";
import { spawnProcess } from "./process.js";
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
    expect(env.PATH).toBe("C:\\tools\\bin");
    expect(JSON.stringify(env)).not.toContain("fixture-launcher");
    expect(env.ComSpec).toBeUndefined();
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
