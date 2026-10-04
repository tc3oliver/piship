import { describe, expect, it } from "vitest";
import { windowsNpmCommandLine } from "./windows-npm.js";

describe("windowsNpmCommandLine", () => {
  it("quotes every argument, keeping characters cmd.exe treats literally in quotes", () => {
    expect(
      windowsNpmCommandLine([
        "install",
        "pkg@^1.2 <2 || >=3",
        "--registry=https://registry.example/a&b",
      ]),
    ).toBe(
      '"npm "install" "pkg@^1.2 <2 || >=3" "--registry=https://registry.example/a&b""',
    );
  });

  it("doubles trailing backslashes so node still sees the closing quote", () => {
    expect(windowsNpmCommandLine(["x", "C:\\dir\\"])).toBe(
      '"npm "x" "C:\\dir\\\\""',
    );
  });

  it.each([
    ['https://r.example/" & calc & "'],
    ["https://r.example/%COMSPEC%"],
    ["https://r.example/!PATH!"],
    ["https://r.example/\r\ncalc"],
  ])("refuses %j, which cmd.exe would interpret inside quotes", (value) => {
    expect(() =>
      windowsNpmCommandLine(["audit", `--registry=${value}`]),
    ).toThrow(/cmd\.exe interprets inside quotes/);
  });
});
