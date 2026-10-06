import { describe, expect, it } from "vitest";
import { defaultStoreMode, storeMode } from "./policy.js";

describe("the store default by platform", () => {
  it("hard-links on Windows and is off everywhere else", () => {
    expect(defaultStoreMode("win32")).toBe("hardlink");
    for (const platform of ["darwin", "linux", "freebsd", "android"] as const)
      expect(defaultStoreMode(platform)).toBe("off");
  });

  it("follows the host platform when none is given", () => {
    expect(defaultStoreMode()).toBe(defaultStoreMode(process.platform));
    expect(storeMode({})).toBe(defaultStoreMode(process.platform));
  });

  it("uses the default for an unset or blank PISHIP_STORE", () => {
    expect(storeMode({}, "win32")).toBe("hardlink");
    expect(storeMode({ PISHIP_STORE: "" }, "win32")).toBe("hardlink");
    expect(storeMode({ PISHIP_STORE: "  " }, "win32")).toBe("hardlink");
    expect(storeMode({}, "darwin")).toBe("off");
    expect(storeMode({}, "linux")).toBe("off");
  });

  it("lets an explicit value win on every platform, off included", () => {
    for (const platform of ["win32", "darwin", "linux"] as const) {
      for (const mode of ["off", "copy", "clone", "hardlink"] as const)
        expect(storeMode({ PISHIP_STORE: mode }, platform)).toBe(mode);
      expect(storeMode({ PISHIP_STORE: " OFF " }, platform)).toBe("off");
    }
  });

  it("refuses an unknown value on every platform", () => {
    for (const platform of ["win32", "darwin"] as const)
      expect(() => storeMode({ PISHIP_STORE: "link" }, platform)).toThrow(
        /PISHIP_STORE=link is not one of/,
      );
  });
});
