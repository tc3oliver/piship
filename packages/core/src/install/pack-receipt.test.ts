import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  appDirectory,
  commandPathFor,
  type InstallReceipt,
  readInstallReceipt,
  receiptPath,
  writeReceipt,
} from "./receipt.js";

const KEYS = ["PISHIP_INSTALL_HOME", "PISHIP_BIN_HOME", "PISHIP_STATE_HOME"];
let saved: Record<string, string | undefined>;
let root: string;
beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  root = mkdtempSync(join(tmpdir(), "piship-pack-receipt-"));
  process.env.PISHIP_INSTALL_HOME = join(root, "install");
  process.env.PISHIP_BIN_HOME = join(root, "bin");
  process.env.PISHIP_STATE_HOME = join(root, "state");
  mkdirSync(join(root, "install", "receipts"), { recursive: true });
});
afterEach(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  rmSync(root, { recursive: true, force: true });
});

const app = {
  id: "acmepi",
  name: "AcmePi",
  command: "acmepi",
  version: "1.0.0",
} as InstallReceipt["app"];

function receipt(active: string, previous?: string): InstallReceipt {
  const entry = (version: string, release?: object) => ({
    version,
    payload: join(appDirectory("acmepi"), version),
    installedAt: "2026-10-29T00:00:00.000Z",
    ...(release ? { release } : {}),
  });
  return {
    schema: "piship-install/v1",
    app,
    payload: join(appDirectory("acmepi"), active),
    commandPath: commandPathFor("acmepi"),
    launcher: join(appDirectory("acmepi"), "launch.mjs"),
    active,
    ...(previous ? { previous } : {}),
    releases: [
      // The retained per-target release, as every earlier PiShip wrote it.
      entry("1.0.0", {
        target: "linux-x64",
        channel: "stable",
        pi: "1.1.0",
        piship: "0.13.0",
        lockSha256: "a".repeat(64),
        archiveSha256: "b".repeat(64),
      }),
      // The composed release: a pack and a runtime, no archive digest.
      entry("1.1.0", {
        target: "linux-x64",
        channel: "stable",
        pi: "1.1.0",
        piship: "0.13.0",
        lockSha256: "c".repeat(64),
        pack: { sha256: "d".repeat(64), version: "1.1.0" },
        runtime: { archiveSha256: "e".repeat(64), pishipVersion: "0.13.0" },
      }),
    ],
  } as InstallReceipt;
}

describe("receipts of composed releases", () => {
  it("reads a receipt with pack and runtime fields, and keeps them across a rollback commit", () => {
    writeReceipt(receipt("1.1.0", "1.0.0"));
    const before = readInstallReceipt("acmepi");
    expect(before.releases[1]?.release?.pack?.version).toBe("1.1.0");
    // What `rollbackDistribution` commits: the receipt read back, with the
    // retained release active.
    writeReceipt({
      ...before,
      active: "1.0.0",
      previous: "1.1.0",
      payload: join(appDirectory("acmepi"), "1.0.0"),
    });
    const after = readInstallReceipt("acmepi");
    expect(after.active).toBe("1.0.0");
    expect(after.releases[0]?.release?.archiveSha256).toBe("b".repeat(64));
    expect(after.releases[1]?.release?.runtime?.archiveSha256).toBe(
      "e".repeat(64),
    );
  });

  it("is plain JSON an earlier reader takes as it is: only known fields are checked", () => {
    writeReceipt(receipt("1.0.0", undefined));
    const raw = JSON.parse(readFileSync(receiptPath("acmepi"), "utf8"));
    for (const release of raw.releases) {
      expect(typeof release.version).toBe("string");
      expect(typeof release.payload).toBe("string");
    }
    expect(raw.releases[1].release.archiveSha256).toBeUndefined();
  });
});
