import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { launchPiDistribution, PINNED_PI_VERSION } from "./index.js";

const KEYS = [
  "PISHIP_STATE_HOME",
  "PISHIP_INSTALL_HOME",
  "PISHIP_BIN_HOME",
] as const;
let temp: string;
let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  temp = mkdtempSync(join(tmpdir(), "piship-launch-overlap-"));
  process.env.PISHIP_INSTALL_HOME = join(temp, "install");
  process.env.PISHIP_BIN_HOME = join(temp, "bin");
  process.env.PISHIP_STATE_HOME = join(temp, "state");
});
afterEach(() => {
  for (const key of KEYS)
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  vi.restoreAllMocks();
  rmSync(temp, { recursive: true, force: true });
});

const metadata = {
  app: {
    id: "acmecode",
    command: "acmecode",
    name: "AcmeCode",
    version: "1.0.0",
  },
  runtime: {
    package: "@earendil-works/pi-coding-agent",
    version: PINNED_PI_VERSION,
    pishipVersion: "0.7.0",
  },
  deployment: { mode: "managed" },
} as unknown as DistributionLock;

const launch = (args: string[]) =>
  launchPiDistribution({ distributionDir: temp, metadata, args });

describe("launch with overlapping PiShip roots (#49)", () => {
  it("starts when the state, install, and bin homes are separate", async () => {
    // The control: the same launch succeeds and creates its state directory.
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    await launch(["--version"]);
    expect(existsSync(join(temp, "state", "acmecode"))).toBe(true);
  });

  it("refuses before creating any state when the state home is inside the install home", async () => {
    process.env.PISHIP_STATE_HOME = join(temp, "install", "apps");
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const error = await launch(["--version"]).then(
      () => undefined,
      (failure: unknown) => failure,
    );
    expect(error).toBeInstanceOf(PiShipError);
    expect((error as PiShipError).code).toBe("CONFIG_INVALID");
    expect((error as PiShipError).message).toMatch(
      /PISHIP_STATE_HOME .* and PISHIP_INSTALL_HOME .* overlap/,
    );
    expect(log).not.toHaveBeenCalled();
    expect(existsSync(join(temp, "install", "apps", "acmecode"))).toBe(false);
  });
});
