import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { assertDisjointRoots } from "./state-paths.js";

const KEYS = ["PISHIP_STATE_HOME", "PISHIP_INSTALL_HOME", "PISHIP_BIN_HOME"];
let temp: string;
let saved: Record<string, string | undefined>;

function roots(state: string, install: string, bin: string): void {
  process.env.PISHIP_STATE_HOME = state;
  process.env.PISHIP_INSTALL_HOME = install;
  process.env.PISHIP_BIN_HOME = bin;
}

describe("PiShip state, install, and bin homes", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-roots-"));
    saved = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  });
  afterEach(() => {
    for (const [key, value] of Object.entries(saved))
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    rmSync(temp, { recursive: true, force: true });
  });

  it("accepts separate sibling roots, whether or not they exist yet", () => {
    roots(join(temp, "state"), join(temp, "install"), join(temp, "bin"));
    expect(() => assertDisjointRoots()).not.toThrow();
    for (const name of ["state", "install", "bin"]) mkdirSync(join(temp, name));
    expect(() => assertDisjointRoots()).not.toThrow();
    // A shared prefix is not nesting.
    roots(join(temp, "piship"), join(temp, "piship-install"), join(temp, "b"));
    expect(() => assertDisjointRoots()).not.toThrow();
  });

  it("refuses a state home inside the install home's apps directory", () => {
    roots(
      join(temp, "piship", "apps"),
      join(temp, "piship"),
      join(temp, "bin"),
    );
    expect(() => assertDisjointRoots()).toThrow(
      /PISHIP_STATE_HOME .* and PISHIP_INSTALL_HOME .* overlap/,
    );
  });

  it("refuses a bin home inside one distribution's state", () => {
    roots(
      join(temp, "state"),
      join(temp, "install"),
      join(temp, "state", "mypi", "bin"),
    );
    expect(() => assertDisjointRoots()).toThrow(
      /PISHIP_STATE_HOME .* and PISHIP_BIN_HOME .* overlap/,
    );
  });

  it("refuses an install home inside the state home, and equal roots", () => {
    roots(
      join(temp, "state"),
      join(temp, "state", "install"),
      join(temp, "bin"),
    );
    expect(() => assertDisjointRoots()).toThrow(/overlap/);
    roots(join(temp, "state"), join(temp, "install"), join(temp, "install"));
    expect(() => assertDisjointRoots()).toThrow(
      /PISHIP_INSTALL_HOME .* and PISHIP_BIN_HOME .* overlap/,
    );
  });

  it("refuses roots that are the same directory through a symlink", () => {
    mkdirSync(join(temp, "real", "apps"), { recursive: true });
    // A junction on Windows, which needs no privilege.
    symlinkSync(join(temp, "real"), join(temp, "alias"), "junction");
    roots(join(temp, "alias", "apps"), join(temp, "real"), join(temp, "bin"));
    expect(() => assertDisjointRoots()).toThrow(/overlap/);
    // Also when the aliased part does not exist yet.
    roots(
      join(temp, "alias", "state"),
      join(temp, "real", "state", "x"),
      join(temp, "bin"),
    );
    expect(() => assertDisjointRoots()).toThrow(/overlap/);
  });

  it.runIf(process.platform === "darwin" || process.platform === "win32")(
    "refuses roots that differ only in case where the filesystem ignores case",
    () => {
      mkdirSync(join(temp, "Piship"));
      roots(
        join(temp, "piship", "apps"),
        join(temp, "PISHIP"),
        join(temp, "bin"),
      );
      expect(() => assertDisjointRoots()).toThrow(/overlap/);
    },
  );
});
