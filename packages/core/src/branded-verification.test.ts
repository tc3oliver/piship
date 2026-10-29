import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { MetricsSnapshot } from "@piship/audit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { verificationStates } from "./branded/doctor.js";
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
function installed(extra?: object, access = true): BrandedContext {
  const payload = join(appDirectory("acmepi"), "1.0.0");
  mkdirSync(payload, { recursive: true });
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
      ...(access ? { access: {} } : {}),
    },
  } as unknown as BrandedContext;
}

const none = {} as MetricsSnapshot;

describe("doctor verification states", () => {
  it("reports a composed install by its pack and runtime, never as one artifact", () => {
    const states = verificationStates(
      installed({
        pack: { sha256: "d".repeat(64), version: "1.0.0" },
        runtime: { archiveSha256: "e".repeat(64), pishipVersion: "0.13.0" },
      }),
      none,
    );
    expect(states.runtime).toMatchObject({ state: "verified" });
    expect(states.runtime.detail).toContain("runtime archive");
    expect(states.runtime.detail).not.toContain("artifact");
    expect(states.config.detail).toContain("company pack 1.0.0");
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
      metadata: { app, manifest: { schema: "piship/v1" }, access: {} },
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
    expect(
      verificationStates(installed(undefined, false), none).integration.state,
    ).toBe("not-applicable");
  });
});
