// What the branded update and rollback commands tell the person they did:
// a channel switch, a rollback, the version rolled back from, and the
// channels a source does publish.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  KEY,
  installed,
  rejection,
  stateDir,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import type { BrandedContext } from "./branded/context.js";
import { runRollback, runUpdate } from "./branded/lifecycle.js";
import { signChannel, verifyPayload } from "./index.js";
import { readInstallReceipt } from "./install/index.js";

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
      "Now following candidate (was stable); run acmepi update --channel stable to return.",
    );
    expect(await run(runUpdate)).not.toContain("Now following");
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
