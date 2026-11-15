import { describe, expect, it } from "vitest";
import { gitRootFromExecPath, resolvePosixShell } from "./posix-shell.js";

const EXEC = "C:/Program Files/Git/mingw64/libexec/git-core\n";

describe("resolvePosixShell", () => {
  it("derives the Git root from git --exec-path", () => {
    expect(gitRootFromExecPath(EXEC)).toBe("C:\\Program Files\\Git");
  });

  it("uses /bin/sh off Windows", () => {
    expect(resolvePosixShell({ platform: "linux", pathEnv: "/x" })).toEqual({
      shell: "/bin/sh",
      path: "/x",
    });
  });

  it("finds Git's sh.exe and puts its unix tools first on Windows", () => {
    const found = resolvePosixShell({
      platform: "win32",
      pathEnv: "C:\\Windows\\System32",
      gitExecPath: () => EXEC,
      exists: (p) => p === "C:\\Program Files\\Git\\usr\\bin\\sh.exe",
    });
    expect(found?.shell).toBe("C:\\Program Files\\Git\\usr\\bin\\sh.exe");
    expect(found?.path).toBe(
      "C:\\Program Files\\Git\\usr\\bin;C:\\Program Files\\Git\\mingw64\\bin;C:\\Windows\\System32",
    );
  });

  it("falls back to bin/sh.exe, and is undefined without git or a shell", () => {
    expect(
      resolvePosixShell({
        platform: "win32",
        gitExecPath: () => EXEC,
        exists: (p) => p.endsWith("Git\\bin\\sh.exe"),
      })?.shell,
    ).toBe("C:\\Program Files\\Git\\bin\\sh.exe");
    expect(
      resolvePosixShell({
        platform: "win32",
        gitExecPath: () => EXEC,
        exists: () => false,
      }),
    ).toBeUndefined();
    expect(
      resolvePosixShell({ platform: "win32", gitExecPath: () => undefined }),
    ).toBeUndefined();
  });
});
