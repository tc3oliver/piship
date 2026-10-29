import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { MetricsSnapshot } from "@piship/audit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { lifecycleDoctor, verificationStates } from "./branded/doctor.js";
import { hash } from "./digest.js";
import {
  appDirectory,
  commandPathFor,
  type InstallReceipt,
  writeReceipt,
} from "./install/receipt.js";

const KEYS = ["PISHIP_INSTALL_HOME", "PISHIP_BIN_HOME", "PISHIP_STATE_HOME"];
let saved: Record<string, string | undefined>;
let root: string;
beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  root = mkdtempSync(join(tmpdir(), "piship-verification-"));
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
const release = {
  target: "linux-x64",
  channel: "stable",
  pi: "1.1.0",
  piship: "0.13.0",
  lockSha256: "c".repeat(64),
};

/** An installed 1.0.0 whose receipt carries `extra` on its release. */
const company = {
  identity: { mode: "oidc" },
  credential: { provider: "http-broker" },
  inference: { provider: "openai-compatible" },
};
const personal = {
  identity: { mode: "none" },
  credential: { provider: "pi-native" },
  inference: { provider: "pi-native" },
};

function installed(
  extra?: object,
  access: object | null = company,
  inventory?: Record<string, string>,
): BrandedContext {
  const payload = join(appDirectory("acmepi"), "1.0.0");
  mkdirSync(join(payload, "metadata"), { recursive: true });
  if (inventory)
    writeFileSync(
      join(payload, "metadata", "inventory.json"),
      JSON.stringify(inventory),
    );
  writeReceipt({
    schema: "piship-install/v1",
    app,
    payload,
    commandPath: commandPathFor("acmepi"),
    launcher: join(appDirectory("acmepi"), "launch.mjs"),
    active: "1.0.0",
    releases: [
      {
        version: "1.0.0",
        payload,
        installedAt: "2026-10-29T00:00:00.000Z",
        ...(extra ? { release: { ...release, ...extra } } : {}),
      },
    ],
  } as InstallReceipt);
  return {
    distributionDir: payload,
    metadata: {
      app,
      manifest: { schema: "piship/v1" },
      ...(access ? { access } : {}),
    },
  } as unknown as BrandedContext;
}

const none = {} as MetricsSnapshot;

describe("doctor verification states", () => {
  // The runtime part of a composed payload's inventory, and what a pack pins.
  const runtimeFiles = { "runtime/pi.mjs": "1".repeat(64) };
  const composedInventory = {
    ...runtimeFiles,
    "piship.yaml": "2".repeat(64),
    "resources/AGENTS.md": "3".repeat(64),
  };
  const pinned = hash(`${JSON.stringify(runtimeFiles, null, 2)}\n`);
  const composed = (inventorySha256: string | undefined) => ({
    via: "file",
    pack: { sha256: "d".repeat(64), version: "1.0.0" },
    runtime: {
      archiveSha256: "e".repeat(64),
      pishipVersion: "0.13.0",
      ...(inventorySha256 ? { inventorySha256 } : {}),
    },
  });

  it("reports a composed install by its pack and runtime, never as one artifact", () => {
    const states = verificationStates(
      installed(composed(pinned), company, composedInventory),
      none,
    );
    expect(states.runtime).toMatchObject({ state: "verified" });
    expect(states.runtime.detail).toContain("pack pins");
    expect(states.runtime.detail).not.toContain("artifact");
    expect(states.config.detail).toContain("company pack 1.0.0");
    expect(states.config.detail).toContain("channel signature was not checked");
  });

  it("fails a composed runtime that is not the pinned one, and does not guess without a pin", () => {
    const swapped = { ...composedInventory, "runtime/pi.mjs": "9".repeat(64) };
    expect(
      verificationStates(installed(composed(pinned), company, swapped), none)
        .runtime.state,
    ).toBe("failed");
    expect(
      verificationStates(
        installed(composed(undefined), company, composedInventory),
        none,
      ).runtime.state,
    ).toBe("local");
  });

  it("says a channel entry was signed only when the receipt says so", () => {
    expect(
      verificationStates(
        installed(
          { ...composed(pinned), via: "channel" },
          company,
          composedInventory,
        ),
        none,
      ).config.detail,
    ).toContain("signed channel entry");
  });

  it("names a composed install by its pack in the Release group", () => {
    const lines: string[][] = [];
    const line = (label: string, value: string) => lines.push([label, value]);
    lifecycleDoctor(
      installed(composed(pinned), company, composedInventory),
      "Release",
      line,
      line,
    );
    expect(lines).toEqual([
      [
        "release",
        expect.stringContaining("company pack 1.0.0 on runtime PiShip 0.13.0"),
      ],
    ]);
    expect(lines[0]?.[1]).not.toContain("artifact");
  });

  it("reports a per-target release from the one release", () => {
    const states = verificationStates(
      installed({ archiveSha256: "b".repeat(64) }),
      none,
    );
    expect(states.runtime.detail).toContain("linux-x64 release");
    expect(states.config.state).toBe("verified");
  });

  it("calls a payload install and a build directory local", () => {
    expect(verificationStates(installed(), none).runtime.state).toBe("local");
    expect(verificationStates(installed(), none).config.state).toBe("local");
    const build = {
      distributionDir: join(root, "elsewhere"),
      metadata: { app, manifest: { schema: "piship/v1" }, access: company },
    } as unknown as BrandedContext;
    expect(verificationStates(build, none).runtime.state).toBe("local");
  });

  it("keeps integration untested until this machine has evidence", () => {
    const ctx = installed();
    expect(verificationStates(ctx, none).integration).toMatchObject({
      state: "not-tested",
      detail: expect.stringContaining("acmepi login"),
    });
    const evidence = {
      gateway: { lastReachableAt: "2026-10-29T01:00:00.000Z" },
    } as MetricsSnapshot;
    expect(verificationStates(ctx, evidence).integration.state).toBe(
      "verified",
    );
    // A personal distribution on Pi's own providers has nothing to log in to.
    expect(
      verificationStates(installed(undefined, personal), none).integration
        .state,
    ).toBe("not-applicable");
    expect(
      verificationStates(installed(undefined, null), none).integration.state,
    ).toBe("not-applicable");
  });
});
