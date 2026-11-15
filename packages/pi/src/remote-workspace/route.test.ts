import { describe, expect, it } from "vitest";
import { mapSandboxPath, sandboxGoneMessage } from "../governed-tools.js";

const WD = "/home/user/workspace";

describe("mapSandboxPath", () => {
  it("maps the workdir and what is under it to the project root", () => {
    expect(mapSandboxPath(WD, WD, "/work/p", "linux")).toBe("/work/p");
    expect(mapSandboxPath(`${WD}/src/x.ts`, WD, "/work/p", "linux")).toBe(
      "/work/p/src/x.ts",
    );
    expect(mapSandboxPath(`${WD}/a/../b.ts`, WD, "/work/p", "linux")).toBe(
      "/work/p/b.ts",
    );
    expect(mapSandboxPath(`${WD}/`, WD, "/work/p", "linux")).toBe("/work/p");
  });

  it("maps on a path-segment boundary only and never escapes the workdir", () => {
    for (const path of [
      `${WD}2/x`,
      `${WD}-old/x`,
      "/home/user/x",
      `${WD}/../x`,
      `${WD}/a/../../x`,
      "relative/x",
      `${WD}/x\0y`,
    ])
      expect(mapSandboxPath(path, WD, "/work/p", "linux")).toBeUndefined();
  });

  it("leaves a path already inside the project to the host", () => {
    expect(
      mapSandboxPath(`${WD}/proj/x`, WD, `${WD}/proj`, "linux"),
    ).toBeUndefined();
  });

  it("maps a Windows host's path, which Pi has already resolved against the current drive", () => {
    const root = "C:\\Users\\me\\proj";
    expect(mapSandboxPath(`${WD}/src/x.ts`, WD, root, "win32")).toBe(
      "C:\\Users\\me\\proj\\src\\x.ts",
    );
    expect(
      mapSandboxPath("C:\\home\\user\\workspace\\src\\x.ts", WD, root, "win32"),
    ).toBe("C:\\Users\\me\\proj\\src\\x.ts");
    expect(mapSandboxPath(WD, WD, root, "win32")).toBe(root);
    // Inside the project, outside the workdir, or climbing out: not mapped.
    expect(
      mapSandboxPath("C:\\Users\\me\\proj\\x.ts", WD, root, "win32"),
    ).toBeUndefined();
    expect(
      mapSandboxPath("C:\\home\\user\\workspace2\\x", WD, root, "win32"),
    ).toBeUndefined();
    expect(
      mapSandboxPath(`${WD}/..\\..\\x`, WD, root, "win32"),
    ).toBeUndefined();
  });
});

describe("sandboxGoneMessage", () => {
  it("names the saved changes and the next step", () => {
    expect(sandboxGoneMessage("acme")).toBe(
      "The sandbox expired or was lost. Changes up to the last checkpoint are saved: exit, run acme sandbox pull to review them, then start a new session.",
    );
  });
});
