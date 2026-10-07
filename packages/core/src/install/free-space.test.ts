import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { assertFreeSpace, extractionNeed, freeBytes } from "./free-space.js";

describe("free-space preflight", () => {
  it("refuses an install that cannot fit, naming the directory and PISHIP_INSTALL_HOME", () => {
    let thrown: unknown;
    try {
      assertFreeSpace("/data/piship", 500 * 1048576, 100 * 1048576);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({
      code: "CONFIG_UNAVAILABLE",
      component: "install",
    });
    const error = thrown as Error & { userAction?: string };
    expect(error.message).toContain("/data/piship");
    expect(error.message).toContain("500 MiB");
    expect(error.message).toContain("100 MiB");
    expect(error.userAction).toContain("PISHIP_INSTALL_HOME");
  });

  it("passes when there is room or when free space is unknown", () => {
    expect(() => assertFreeSpace("/x", 100, 100)).not.toThrow();
    expect(() => assertFreeSpace("/x", 100, undefined)).not.toThrow();
    expect(() => assertFreeSpace("/does/not/exist/x", 1)).not.toThrow();
    expect(freeBytes("/does/not/exist/x")).toBeUndefined();
    expect(freeBytes(tmpdir())).toBeGreaterThan(0);
  });

  it("needs at least the archive's own size again", () => {
    expect(extractionNeed(10)).toBe(20);
  });
});
