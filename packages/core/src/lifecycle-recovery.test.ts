// What lifecycle commands say and leave behind when a step fails halfway:
// a retained release that no longer verifies, an active release an
// interrupted repair removed, a commit that fails after the sign-in was
// cleared, a --replace whose new payload is bad, and a purge that cannot
// remove the state.
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  installed,
  rejection,
  stateDir,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import type { BrandedContext } from "./branded/context.js";
import { lifecycleDoctor } from "./branded/doctor.js";
import { verifyPayload } from "./index.js";
import {
  installDistribution,
  readInstallReceipt,
  uninstallAndPurgeDistribution,
} from "./install/index.js";
import type { MigrationReport } from "./migration.js";
import { rollbackDistribution, updateDistribution } from "./update/index.js";
import { commitAfterClear } from "./update/state.js";

useLifecycleHomes();

const scratch: string[] = [];
afterEach(() => {
  for (const dir of scratch.splice(0)) {
    try {
      chmodSync(dir, 0o700);
    } catch {}
    rmSync(dir, { recursive: true, force: true });
  }
});

function doctorLines(): string[] {
  const receipt = readInstallReceipt(ID);
  const ctx: BrandedContext = {
    metadata: verifyPayload(receipt.payload) as BrandedContext["metadata"],
    distributionDir: receipt.payload,
    stateDir: stateDir(),
    mode: "personal",
    out: () => {},
    err: () => {},
  };
  const lines: string[] = [];
  lifecycleDoctor(
    ctx,
    "Update",
    (label, value) => lines.push(`ok ${label} ${value}`),
    (label, value) => lines.push(`! ${label} ${value}`),
  );
  return lines.filter((line) => / rollback /.test(line));
}

describe.runIf(HOST_EVIDENCED)("a retained release that is gone", () => {
  it("doctor warns with a next step instead of reporting it retained", async () => {
    const { opts } = await installed();
    await updateDistribution(ID, opts);
    expect(doctorLines()).toEqual(["ok rollback 1.0.0 retained"]);
    rmSync(join(readInstallReceipt(ID).releases[1]?.payload as string), {
      recursive: true,
      force: true,
    });
    const [line] = doctorLines();
    expect(line).toMatch(/^! rollback 1\.0\.0 is recorded as retained but/);
    expect(line).toContain(`piship.mjs repair ${ID}`);
  });

  it("doctor says a release retained by a rollback is newer and returned to by update", async () => {
    const { opts } = await installed();
    await updateDistribution(ID, opts);
    await rollbackDistribution(ID, opts);
    const command = readInstallReceipt(ID).app.command;
    expect(doctorLines()).toEqual([
      `ok rollback 1.1.0 retained, newer than the active 1.0.0; use ${command} update to return to it`,
    ]);
  });

  it("the launcher names the repair for an active release an interrupted repair removed", async () => {
    await installed();
    const receipt = readInstallReceipt(ID);
    rmSync(receipt.payload, { recursive: true, force: true });
    const result = spawnSync(
      process.execPath,
      [receipt.launcher as string, "version"],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("release 1.0.0 is missing");
    expect(result.stderr).toContain(`piship.mjs repair ${ID}`);
    expect(result.stderr).not.toContain("receipt is missing or damaged");
  });
});

describe("a commit that fails after the credentials were cleared", () => {
  const cleared = {
    items: [{ action: "clear-and-reacquire" }],
  } as unknown as MigrationReport;
  const untouched = { items: [] } as unknown as MigrationReport;

  it("says the sign-in is gone, keeping the error's code", () => {
    let thrown: unknown;
    try {
      commitAfterClear(
        () => {
          throw new PiShipError("UPDATE_FAILED", "disk full");
        },
        cleared,
        "acme",
      );
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(PiShipError);
    expect((thrown as PiShipError).code).toBe("UPDATE_FAILED");
    expect((thrown as Error).message).toMatch(
      /disk full.*already cleared.*acme login/,
    );
  });

  it("leaves the error alone when nothing was cleared", () => {
    const failure = new Error("disk full");
    expect(() =>
      commitAfterClear(
        () => {
          throw failure;
        },
        untouched,
        "acme",
      ),
    ).toThrow(failure);
  });
});

describe.runIf(HOST_EVIDENCED)("install --replace with a bad payload", () => {
  it("says the previous install was removed", async () => {
    await installed();
    const source = mkdtempSync(join(tmpdir(), "piship-replace-src-"));
    scratch.push(source);
    cpSync(readInstallReceipt(ID).payload, source, { recursive: true });
    writeFileSync(join(source, "resources", "AGENTS.md"), "# tampered\n");
    const error = await rejection(
      installDistribution(source, true, { replace: true }),
    );
    expect(error.message).toContain("--replace had already removed");
    expect(existsSync(join(stateDir(), "sessions", "s1.jsonl"))).toBe(true);
  });
});

describe.runIf(HOST_EVIDENCED && process.platform !== "win32")(
  "a purge whose state cannot be removed",
  () => {
    it("leaves the install in place so the command can run again", async () => {
      await installed();
      const receipt = readInstallReceipt(ID);
      const parent = process.env.PISHIP_STATE_HOME as string;
      scratch.push(parent);
      chmodSync(parent, 0o500);
      try {
        await rejection(
          uninstallAndPurgeDistribution(ID, { withoutLogout: true }),
        );
      } finally {
        chmodSync(parent, 0o700);
      }
      expect(readInstallReceipt(ID)).toEqual(receipt);
      expect(existsSync(receipt.payload)).toBe(true);
    });
  },
);
