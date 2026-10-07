// What a launch checks of the installed payload. By default one small file,
// piship.lock (which carries the policy), against the digest recorded when
// the release was installed, however many files the payload holds; with
// runtime.verifyAtLaunch the whole payload, inventory included.
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ID,
  installed,
  receiptFile,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import { hash } from "./digest.js";
import { runtimeStateDirectory } from "./state-paths.js";
import { installDistribution, readInstallReceipt } from "./install/index.js";
import { payloadInventory, verifyLaunchPayload } from "./payload.js";

vi.mock("node:crypto", async (original) => {
  const actual = await original<typeof import("node:crypto")>();
  return { ...actual, createHash: vi.fn(actual.createHash) };
});

useLifecycleHomes();
afterEach(() => vi.mocked(createHash).mockClear());

const lockPath = (payload: string) => join(payload, "piship.lock");
/** The lock with its policy relaxed: what an edit by someone with write access would do. */
function editLock(payload: string): void {
  const lock = JSON.parse(readFileSync(lockPath(payload), "utf8"));
  lock.governance = { ...(lock.governance ?? {}), relaxed: true };
  lock.runtime = { ...lock.runtime, edited: true };
  writeFileSync(lockPath(payload), `${JSON.stringify(lock, null, 2)}\n`);
}

describe("files a power loss leaves missing or empty", () => {
  const damaged = (path: string) =>
    expect.objectContaining({
      code: "INTEGRITY_FAILED",
      message: expect.stringContaining(path),
      userAction: expect.stringMatching(
        /piship repair acmepi <release archive>/,
      ),
    });

  it("is reported with the repair command when a file every launch reads is missing or empty", async () => {
    await installed();
    const { payload } = readInstallReceipt(ID);
    const lock = readFileSync(lockPath(payload));
    writeFileSync(lockPath(payload), "");
    expect(() => verifyLaunchPayload(payload)).toThrow(
      damaged("piship.lock (empty)"),
    );
    rmSync(lockPath(payload));
    expect(() => verifyLaunchPayload(payload)).toThrow(
      damaged("missing: piship.lock"),
    );
    writeFileSync(lockPath(payload), lock);
    const target = join(payload, "metadata", "target.json");
    writeFileSync(target, "");
    expect(() => verifyLaunchPayload(payload)).toThrow(
      damaged("metadata/target.json (empty)"),
    );
  });

  it("is found by a stat of the inventory's files, which hashes nothing, and only once per boot", async () => {
    await installed();
    const { payload } = readInstallReceipt(ID);
    const state = runtimeStateDirectory({ value: ID });
    mkdirSync(join(state, "cache"), { recursive: true });
    const victim = join(payload, "package-lock.json");
    const original = readFileSync(victim);
    writeFileSync(victim, "");
    vi.mocked(createHash).mockClear();
    expect(() => verifyLaunchPayload(payload)).toThrow(
      damaged("package-lock.json (empty)"),
    );
    expect(vi.mocked(createHash)).toHaveBeenCalledTimes(1);
    rmSync(victim);
    expect(() => verifyLaunchPayload(payload)).toThrow(
      damaged("missing: package-lock.json"),
    );
    // Intact: accepted, and recorded for this boot, so a later damage waits
    // for the next boot's check (the lock digest is still checked each time).
    writeFileSync(victim, original);
    expect(verifyLaunchPayload(payload).app.id).toBe(ID);
    expect(existsSync(join(state, "cache", "payload-files.json"))).toBe(true);
    writeFileSync(victim, "");
    expect(() => verifyLaunchPayload(payload)).not.toThrow();
  });

  it("is not checked for a build directory", async () => {
    const { a } = await installed();
    const build = join(a.directory, "payload");
    writeFileSync(join(build, "package-lock.json"), "");
    expect(() => verifyLaunchPayload(build)).not.toThrow();
  });
});

describe("an installed release's lock", () => {
  it("is launched when it is the one that was installed", async () => {
    await installed();
    const { payload } = readInstallReceipt(ID);
    expect(verifyLaunchPayload(payload).app.id).toBe(ID);
  });

  it("is refused once it is edited, with a way to repair it", async () => {
    await installed();
    const { payload } = readInstallReceipt(ID);
    const original = readFileSync(lockPath(payload));
    editLock(payload);
    expect(() => verifyLaunchPayload(payload)).toThrow(
      expect.objectContaining({
        code: "INTEGRITY_FAILED",
        message: expect.stringMatching(/is not the one that was installed/),
      }),
    );
    // The same bytes again are accepted.
    writeFileSync(lockPath(payload), original);
    expect(verifyLaunchPayload(payload).app.id).toBe(ID);
  });

  it("costs one hash at launch, however many files the payload holds", async () => {
    await installed();
    const { payload } = readInstallReceipt(ID);
    for (let index = 0; index < 150; index += 1) {
      mkdirSync(join(payload, "node_modules", "many"), { recursive: true });
      writeFileSync(join(payload, "node_modules", "many", `f${index}.js`), "x");
    }
    vi.mocked(createHash).mockClear();
    verifyLaunchPayload(payload);
    expect(vi.mocked(createHash)).toHaveBeenCalledTimes(1);
  });

  it("is bound for a payload directory too, by the digest the install recorded", async () => {
    const { a } = await installed();
    // Reinstall from the payload directory of the release, not its archive.
    const { uninstallDistribution } = await import("./install/index.js");
    uninstallDistribution(ID);
    const receipt = await installDistribution(
      join(a.directory, "payload"),
      true,
    );
    const entry = readInstallReceipt(ID).releases[0];
    expect(entry?.release).toBeUndefined();
    expect(entry?.lockSha256).toBe(
      hash(readFileSync(lockPath(receipt.payload))),
    );
    expect(verifyLaunchPayload(receipt.payload).app.id).toBe(ID);
    editLock(receipt.payload);
    expect(() => verifyLaunchPayload(receipt.payload)).toThrow(
      /is not the one that was installed/,
    );
  });

  it("is not compared when the install recorded no digest (an installation from before it was)", async () => {
    await installed();
    const receipt = JSON.parse(readFileSync(receiptFile(), "utf8"));
    for (const release of receipt.releases) {
      delete release.release;
      delete release.lockSha256;
    }
    writeFileSync(receiptFile(), JSON.stringify(receipt));
    const { payload } = readInstallReceipt(ID);
    editLock(payload);
    expect(() => verifyLaunchPayload(payload)).not.toThrow();
  });

  it("is not compared for a payload outside the install home's apps (a build directory)", async () => {
    const { a } = await installed();
    const build = join(a.directory, "payload");
    editLock(build);
    expect(() => verifyLaunchPayload(build)).not.toThrow();
  });
});

/** A resource file the lock lists, by its path under the payload's resources directory. */
function firstResource(payload: string): string {
  const lock = JSON.parse(readFileSync(lockPath(payload), "utf8"));
  return lock.resources[0].path as string;
}

describe("runtime.verifyAtLaunch", () => {
  /** Declare it as a distribution that asks for it would: in its lock, bound by the receipt and the inventory. */
  async function declared(value: boolean) {
    await installed();
    const receipt = JSON.parse(readFileSync(receiptFile(), "utf8"));
    const { payload } = readInstallReceipt(ID);
    const lock = JSON.parse(readFileSync(lockPath(payload), "utf8"));
    writeFileSync(
      lockPath(payload),
      `${JSON.stringify({ ...lock, verifyAtLaunch: value }, null, 2)}\n`,
    );
    writeFileSync(
      join(payload, "metadata", "inventory.json"),
      `${JSON.stringify(payloadInventory(payload), null, 2)}\n`,
    );
    for (const release of receipt.releases)
      if (release.payload === payload)
        release.release.lockSha256 = hash(readFileSync(lockPath(payload)));
    writeFileSync(receiptFile(), JSON.stringify(receipt));
    return payload;
  }

  it("detects an edited resource when true, and does not look when false", async () => {
    const asked = await declared(true);
    expect(verifyLaunchPayload(asked).app.id).toBe(ID);
    const resource = firstResource(asked);
    writeFileSync(join(asked, "resources", resource), "# Edited\n");
    expect(() => verifyLaunchPayload(asked)).toThrow(
      new RegExp(`integrity mismatch.*modified: resources/${resource}`),
    );
  }, 60_000);

  it("is not asked for when false: the same edit is not looked for", async () => {
    const declinedPayload = await declared(false);
    writeFileSync(
      join(declinedPayload, "resources", "AGENTS.md"),
      "# Edited\n",
    );
    expect(() => verifyLaunchPayload(declinedPayload)).not.toThrow();
  }, 60_000);

  it("verifies the inventory too: an added file is found", async () => {
    const asked = await declared(true);
    writeFileSync(join(asked, "bin", "extra.js"), "added\n");
    expect(() => verifyLaunchPayload(asked)).toThrow(
      /unexpected \(not in the inventory\): bin\/extra\.js/,
    );
  }, 60_000);
});
