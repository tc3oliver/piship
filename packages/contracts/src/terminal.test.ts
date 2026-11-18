import { describe, expect, it } from "vitest";
import { asciiOnly, printable, statusMarks } from "./terminal.js";

describe("asciiOnly", () => {
  it("falls back to ASCII on a Windows console that names no Unicode terminal", () => {
    expect(asciiOnly({}, "win32")).toBe(true);
    expect(asciiOnly({ PISHIP_ASCII: "" }, "win32")).toBe(true);
  });

  it.each([
    { WT_SESSION: "guid" },
    { TERM_PROGRAM: "vscode" },
    { TERM: "xterm-256color" },
    { ConEmuPID: "1234" },
  ])("keeps Unicode in a known Unicode terminal on Windows: %j", (env) => {
    expect(asciiOnly(env, "win32", true)).toBe(false);
  });

  it("falls back to ASCII on Windows when output is redirected, even in a Unicode terminal", () => {
    expect(asciiOnly({ WT_SESSION: "guid" }, "win32", false)).toBe(true);
    expect(asciiOnly({ TERM: "xterm" }, "win32", false)).toBe(true);
    expect(asciiOnly({}, "linux", false)).toBe(false);
    expect(asciiOnly({ PISHIP_ASCII: "0" }, "win32", false)).toBe(false);
  });

  it("keeps Unicode elsewhere", () => {
    expect(asciiOnly({}, "linux")).toBe(false);
    expect(asciiOnly({}, "darwin")).toBe(false);
  });

  it("lets PISHIP_ASCII decide either way", () => {
    expect(asciiOnly({ PISHIP_ASCII: "1" }, "linux")).toBe(true);
    expect(asciiOnly({ PISHIP_ASCII: "0" }, "win32")).toBe(false);
    expect(asciiOnly({ PISHIP_ASCII: "0", WT_SESSION: "x" }, "win32")).toBe(
      false,
    );
  });
});

describe("statusMarks", () => {
  it("is one character wide in both sets and ASCII in the fallback", () => {
    const unicode = statusMarks({}, "linux");
    const ascii = statusMarks({}, "win32");
    expect(unicode).toEqual({ ok: "✓", warn: "!", fail: "✗", info: "-" });
    expect(ascii).toEqual({ ok: "+", warn: "!", fail: "x", info: "-" });
    for (const mark of [...Object.values(unicode), ...Object.values(ascii)])
      expect(mark).toHaveLength(1);
    expect(Object.values(ascii).join("")).toMatch(/^[\x20-\x7e]+$/);
  });
});

describe("printable", () => {
  it("replaces terminal and bidi controls, keeps newline and tab", () => {
    expect(printable("a\u001b]52;c;eA==\u0007b")).toBe("a?]52;c;eA==?b");
    expect(printable("x‮y⁦z\u009b")).toBe("x?y?z?");
    expect(printable("line\n\tnext")).toBe("line\n\tnext");
  });
});
