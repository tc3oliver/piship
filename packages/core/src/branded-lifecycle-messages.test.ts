// What the branded update and rollback commands tell the person they did:
// a channel switch, a rollback, the version rolled back from, and the
// channels a source does publish.
import { spawn } from "node:child_process";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import {
  appsDir,
  HOST_EVIDENCED,
  ID,
  KEY,
  installed,
  rejection,
  stateDir,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import type { BrandedContext } from "./branded/context.js";
import {
  requireInstalled,
  runRollback,
  runUpdate,
} from "./branded/lifecycle.js";
import { signChannel, verifyPayload } from "./index.js";
import { shellArg } from "./invocation.js";
import { lifecycleStatus, readInstallReceipt } from "./install/index.js";

useLifecycleHomes();

const scratch: string[] = [];
afterEach(() => {
  for (const dir of scratch.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

function context(lines: string[] = []): BrandedContext {
  const receipt = readInstallReceipt(ID);
  return {
    metadata: verifyPayload(receipt.payload) as BrandedContext["metadata"],
    distributionDir: receipt.payload,
    stateDir: stateDir(),
    mode: "personal",
    out: (line) => lines.push(line),
    err: () => {},
  };
}

async function run(
  command: typeof runUpdate | typeof runRollback,
  args: readonly string[] = [],
): Promise<string> {
  const lines: string[] = [];
  await command(context(lines), args);
  return lines.join("\n");
}

/** Another process that holds a runtime lease on `version`, as a session does. */
async function session(version: string): Promise<() => Promise<void>> {
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `import { holdRuntimeLease } from '@piship/core'; holdRuntimeLease(${JSON.stringify(ID)}, ${JSON.stringify(version)}); process.stdout.write('ready'); setInterval(() => {}, 1000);`,
    ],
    { cwd: process.cwd(), env: process.env, stdio: ["ignore", "pipe", "pipe"] },
  );
  await new Promise<void>((resolve, reject) => {
    child.stdout?.once("data", () => resolve());
    child.once("error", reject);
  });
  return async () => {
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
  };
}

const sign = (directory: string, channel: string, archive: string) =>
  signChannel({
    directory,
    channel,
    archives: [archive],
    privateKeyPem: KEY.privateKeyPem,
    keyId: KEY.id,
  });

describe("branded update --help", () => {
  it("prints the usage and succeeds", async () => {
    const lines: string[] = [];
    const ctx = {
      metadata: { app: { command: "acmepi" } },
      out: (line: string) => lines.push(line),
    } as unknown as BrandedContext;
    await runUpdate(ctx, ["--help"]);
    expect(lines).toEqual([
      "Usage: acmepi update [--channel <name>] [--from <dir|url>] [--check] [--accept-review]",
    ]);
  });
});

describe("branded lifecycle command outside an install", () => {
  it("names the payload's own install, not a piship command", () => {
    const dir = mkdtempSync(join(tmpdir(), "piship-not-installed-"));
    scratch.push(dir);
    const ctx = {
      metadata: { app: { id: "notinstalledpi", name: "Not Installed" } },
      distributionDir: dir,
    } as unknown as BrandedContext;
    let error: PiShipError | undefined;
    try {
      requireInstalled(ctx, "acmepi update");
    } catch (caught) {
      error = caught as PiShipError;
    }
    expect(error?.code).toBe("CONFIG_INVALID");
    expect(error?.message).toContain(
      `Install it first: node ${shellArg(join(dir, "piship.mjs"))} install ${shellArg(dir)}`,
    );
    expect(error?.message).not.toContain("piship install");
  });
});

describe.runIf(HOST_EVIDENCED)("branded update and rollback messages", () => {
  it("says when an update switches the channel it follows, and a check does not", async () => {
    const { b, channelDir } = await installed();
    await sign(channelDir, "candidate", b.archive);
    const checked = await run(runUpdate, ["--check", "--channel", "candidate"]);
    expect(checked).toContain("1.1.0 is available on the candidate channel");
    expect(checked).toContain(
      "run acmepi update --channel candidate to install it.",
    );
    expect(checked).not.toContain("Now following");
    const updated = await run(runUpdate, ["--channel", "candidate"]);
    expect(updated).toContain("Updated AcmePi 1.0.0 -> 1.1.0 (candidate");
    expect(updated).toContain(
      "Now following candidate (was stable). To return, run acmepi rollback (back to 1.0.0) and then acmepi update --channel stable, or run acmepi update --channel stable once stable offers 1.1.0 or newer.",
    );
    expect(await run(runUpdate)).not.toContain("Now following");
  });

  it("explains how to return to a channel that is behind the active release", async () => {
    const { a, b } = await installed();
    // A fresh source whose stable channel offers only 1.0.0.
    const channelDir = mkdtempSync(join(tmpdir(), "piship-behind-"));
    scratch.push(channelDir);
    process.env.ACMEPI_UPDATE_SOURCE = channelDir;
    await sign(channelDir, "stable", a.archive);
    await sign(channelDir, "candidate", b.archive);
    await run(runUpdate, ["--channel", "candidate"]);
    const refused = (await rejection(
      run(runUpdate, ["--channel", "stable"]),
    )) as PiShipError;
    expect(refused.code).toBe("UPDATE_FAILED");
    expect(refused.message).toContain("downgrades are refused");
    expect(refused.userAction).toBe(
      "Nothing was changed; 1.1.0 stays active. To follow stable now, run acmepi rollback (back to 1.0.0), then acmepi update --channel stable",
    );
    // The refused switch is not recorded.
    expect(readInstallReceipt(ID).channel).toBe("candidate");
    expect(await run(runRollback)).toContain(
      "1.0.0 is a stable release, but this installation still follows candidate, so acmepi update would offer candidate's newest release again. Run acmepi update --channel stable to follow stable.",
    );
    expect(await run(runUpdate, ["--channel", "stable"])).toContain(
      "AcmePi 1.0.0 is up to date on the stable channel.",
    );
    expect(readInstallReceipt(ID).channel).toBe("stable");
  });

  it("names the version a check offers as the one rolled back from", async () => {
    await installed();
    await run(runUpdate);
    const rolledBack = await run(runRollback);
    // No sign-in or credential: nothing is said about one.
    expect(rolledBack).toBe(
      "Rolled back AcmePi 1.1.0 -> 1.0.0. Sessions and settings were preserved.",
    );
    expect(await run(runUpdate, ["--check"])).toContain(
      "AcmePi 1.1.0 (you rolled back from this version) is available on the stable channel",
    );
  });

  it("says which running sessions keep the release they started with", async () => {
    await installed();
    const stop = await session("1.0.0");
    try {
      expect(await run(runUpdate)).toContain(
        "Updated AcmePi 1.0.0 -> 1.1.0 (stable, signed by test-release). 1.0.0 is kept for acmepi rollback; sessions and settings were preserved.\n1 running AcmePi session(s) still use 1.0.0; restart them to use 1.1.0.",
      );
      // No session runs 1.1.0: the rollback says nothing about one.
      expect(await run(runRollback)).not.toContain("running");
    } finally {
      await stop();
    }
  });

  it("does not call a release a running session holds left over", async () => {
    await installed();
    cpSync(join(appsDir(), "1.0.0"), join(appsDir(), "0.9.0"), {
      recursive: true,
    });
    const status = () =>
      lifecycleStatus(ID, verifyPayload(join(appsDir(), "1.0.0")));
    const stop = await session("0.9.0");
    try {
      expect(status().leftovers).toEqual([]);
      expect(status().runtimeLeases).toEqual({
        live: 1,
        stale: 0,
        held: ["0.9.0"],
      });
    } finally {
      await stop();
    }
    expect(status().leftovers).toEqual(["0.9.0"]);
  });

  it("names the channels a source publishes when it lacks the selected one", async () => {
    const { b } = await installed();
    const source = mkdtempSync(join(tmpdir(), "piship-candidate-only-"));
    scratch.push(source);
    await sign(source, "candidate", b.archive);
    const error = await rejection(
      run(runUpdate, ["--check", "--from", source]),
    );
    expect(error).toBeInstanceOf(PiShipError);
    expect((error as PiShipError).message).toBe(
      "Update source has no stable.json; it publishes candidate.json",
    );
    expect((error as PiShipError).userAction).toContain(
      "Run acmepi update --channel candidate",
    );
  });
});
