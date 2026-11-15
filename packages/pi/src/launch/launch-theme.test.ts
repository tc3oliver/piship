import { describe, expect, it } from "vitest";
import { launchTheme } from "./runtime.js";

const base = {
  distributionTheme: "mypi",
  loaded: ["mypi"],
  command: "mypi",
};

describe("launchTheme", () => {
  it("uses an available theme as it is", () => {
    for (const theme of ["dark", "light", "mypi", undefined])
      expect(launchTheme({ ...base, theme, preferred: true })).toEqual({
        theme,
      });
  });

  it("falls back from a preference that is not available, and says how to fix it", () => {
    const chosen = launchTheme({ ...base, theme: "nosuch", preferred: true });
    expect(chosen.theme).toBe("mypi");
    expect(chosen.notice).toBe(
      "Notice: theme nosuch (your preference) is not available, so mypi is used. Choose one of dark, light, mypi with mypi config set theme <name>, or run mypi config unset theme.",
    );
    // With no usable distribution theme, Pi's default.
    expect(
      launchTheme({
        ...base,
        theme: "nosuch",
        preferred: true,
        distributionTheme: undefined,
      }).theme,
    ).toBeUndefined();
  });

  it("still fails a launch whose distribution theme is not available", () => {
    expect(() =>
      launchTheme({ ...base, theme: "gone", preferred: false, loaded: [] }),
    ).toThrow("Declared theme is unavailable: gone");
  });
});
