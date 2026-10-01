// PiShip-owned temporary directories after a hard termination, from the point
// of view of the operations that create them: the OS-temp scratch of
// verification and launch checks, install and update staging, and what the
// doctor says about a directory that resists removal. The marker and
// liveness rules themselves are tested in @piship/contracts; here a real
// process is killed in the middle of an operation and the next operation
// finds a clean machine. Every scenario runs in a private OS temp directory.
import { spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readTemporaryOwner, type TemporaryKind } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  appsDir,
  deadPid,
  installed,
  livePid,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import { plantTemporary } from "../../../tests/helpers/temporaries.js";
import { lifecycleDoctor } from "./branded/index.js";
import {
  abandonedTemporaryCount,
  readInstallReceipt,
  reclaimInstallTemporaries,
  reclaimLaunchTemporaries,
  reclaimOsTemporaries,
  rollbackDistribution,
  sweepOutputStaging,
  updateDistribution,
  verifyPayload,
  verifyRelease,
} from "./index.js";
import { checkPayload } from "./update/state.js";

const posix = process.platform !== "win32";
const notRoot = posix && process.getuid?.() !== 0;
const TEMP_VARIABLES = ["TMPDIR", "TEMP", "TMP"] as const;

useLifecycleHomes();

let osTemp: string;
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  osTemp = mkdtempSync(join(tmpdir(), "piship-stale-os-temp-"));
  for (const name of TEMP_VARIABLES) {
    saved[name] = process.env[name];
    process.env[name] = osTemp;
  }
});
afterEach(() => {
  for (const name of TEMP_VARIABLES)
    if (saved[name] === undefined) delete process.env[name];
    else process.env[name] = saved[name];
  rmSync(osTemp, { recursive: true, force: true });
});

const installHome = () => process.env.PISHIP_INSTALL_HOME as string;

const plant = (
  parent: string,
  name: string,
  kind: TemporaryKind,
  pid: number,
) => plantTemporary(parent, name, kind, pid);

/** The OS temp directories of PiShip operations (the fixtures' own are not). */
const leftovers = () =>
  readdirSync(osTemp).filter((name) =>
    /^piship-(?:verify|launch-check|sandbox|release-test)-/.test(name),
  );

describe("where each start reclaims", () => {
  it("removes the OS temp directories of dead owners, by kind, and keeps the rest", () => {
    const dead = deadPid();
    const alive = livePid();
    const stale = [
      plant(osTemp, "piship-sandbox-aaaaaa", "sandbox", dead),
      plant(osTemp, "piship-verify-bbbbbb", "verify", dead),
      plant(osTemp, "piship-launch-check-cccccc", "launch-check", dead),
      plant(osTemp, "piship-release-test-dddddd", "release-test", dead),
      plant(osTemp, ".piship-probe-eeeeee", "probe", dead),
    ];
    const kept = [
      plant(osTemp, "piship-sandbox-ffffff", "sandbox", alive),
      plant(osTemp, "piship-verify-gggggg", "verify", alive),
      // Another location's kind, and the install kind, are not OS temp's.
      plant(osTemp, ".staging-hhhhhh", "staging", dead),
      plant(osTemp, ".piship-acme-iiiiii", "build", dead),
    ];
    const users = ["piship-verify-notes", "piship-sandbox-abc123"].map(
      (name) => {
        mkdirSync(join(osTemp, name));
        writeFileSync(join(osTemp, name, "keep.txt"), "user data");
        return join(osTemp, name, "keep.txt");
      },
    );
    const result = reclaimOsTemporaries();
    expect(result.failed).toEqual([]);
    expect([...result.removed].sort()).toEqual(stale.sort());
    for (const path of kept) expect(existsSync(path)).toBe(true);
    for (const path of users)
      expect(readFileSync(path, "utf8")).toBe("user data");
  });

  it("removes install staging of dead owners under the install home and apps/<id>", () => {
    const dead = deadPid();
    const alive = livePid();
    const apps = join(installHome(), "apps", ID);
    mkdirSync(join(apps, "1.0.0"), { recursive: true });
    writeFileSync(join(apps, "launch.mjs"), "launcher");
    const stale = [
      plant(installHome(), ".staging-aaaaaa", "staging", dead),
      plant(apps, ".staging-bbbbbb", "staging", dead),
    ];
    const live = [
      plant(installHome(), ".staging-cccccc", "staging", alive),
      plant(apps, ".staging-dddddd", "staging", alive),
    ];
    const unmarked = join(apps, ".staging-killed");
    mkdirSync(unmarked);
    // Without an id only the install home itself is swept.
    expect(reclaimInstallTemporaries().removed).toEqual([stale[0]]);
    expect(existsSync(stale[1] as string)).toBe(true);
    expect(reclaimInstallTemporaries(ID).removed).toEqual([stale[1]]);
    for (const path of live) expect(existsSync(path)).toBe(true);
    expect(existsSync(unmarked)).toBe(true);
    expect(readFileSync(join(apps, "launch.mjs"), "utf8")).toBe("launcher");
  });

  it("reports build and release staging beside an output, and removes it only when asked, each by its own kind", () => {
    const dead = deadPid();
    const output = join(osTemp, "dist");
    const build = plant(output, ".piship-acmepi-aaaaaa", "build", dead);
    const releases = join(output, "releases");
    const release = plant(
      releases,
      ".piship-release-acmepi-bbbbbb",
      "release",
      dead,
    );
    const told: { directory: string; count: number; attempted: boolean }[] = [];
    const abandonedStaging = (found: (typeof told)[number]) => told.push(found);
    // Not asked: a count, and nothing removed.
    sweepOutputStaging(output, "build", { abandonedStaging });
    sweepOutputStaging(releases, "release", { abandonedStaging });
    expect(told).toEqual([
      { directory: output, count: 1, attempted: false },
      { directory: releases, count: 1, attempted: false },
    ]);
    expect(existsSync(build)).toBe(true);
    expect(existsSync(release)).toBe(true);
    // Asked: each kind only in its own root.
    told.length = 0;
    sweepOutputStaging(output, "build", {
      reclaimStaging: true,
      abandonedStaging,
    });
    expect(told).toEqual([]);
    expect(existsSync(build)).toBe(false);
    expect(existsSync(release)).toBe(true);
    sweepOutputStaging(releases, "release", { reclaimStaging: true });
    expect(readdirSync(output)).toEqual(["releases"]);
    expect(readdirSync(releases)).toEqual([]);
  });

  it("never sweeps an output directory by itself", () => {
    // The launcher's sweeps, the ones every start runs, leave it alone.
    const output = join(osTemp, "dist");
    const build = plant(output, ".piship-acmepi-aaaaaa", "build", deadPid());
    reclaimOsTemporaries();
    reclaimInstallTemporaries(ID);
    expect(existsSync(build)).toBe(true);
  });

  it("bounds a launch's sweep and says what it left for a later start (#158)", () => {
    const dead = deadPid();
    const stale = [
      plant(osTemp, "piship-verify-aaaaaa", "verify", dead),
      plant(osTemp, "piship-sandbox-bbbbbb", "sandbox", dead),
      plant(installHome(), ".staging-cccccc", "staging", dead),
    ];
    // A budget that is spent before the first removal.
    let clock = 0;
    const notice = reclaimLaunchTemporaries(ID, {
      budgetMs: 0,
      monotonic: () => clock++,
    });
    expect(notice).toMatch(/left 3 abandoned temporary directories/);
    expect(notice).toMatch(/later start/);
    for (const path of stale) expect(existsSync(path)).toBe(true);
    expect(abandonedTemporaryCount(ID)).toBe(3);
    // The next launch with time to spare finishes the work, quietly.
    expect(reclaimLaunchTemporaries(ID)).toBeUndefined();
    for (const path of stale) expect(existsSync(path)).toBe(false);
    expect(abandonedTemporaryCount(ID)).toBe(0);
  });

  it("counts, without removing, what a start could not remove", () => {
    const stale = plant(osTemp, "piship-verify-aaaaaa", "verify", deadPid());
    plant(osTemp, "piship-verify-bbbbbb", "verify", livePid());
    plant(installHome(), ".staging-cccccc", "staging", deadPid());
    expect(abandonedTemporaryCount(ID)).toBe(2);
    expect(existsSync(stale)).toBe(true);
    reclaimOsTemporaries();
    reclaimInstallTemporaries(ID);
    expect(abandonedTemporaryCount(ID)).toBe(0);
  });
});

describe("a launch check killed in the middle", () => {
  const stateModule = pathToFileURL(
    fileURLToPath(new URL("../dist/update/state.js", import.meta.url)),
  ).href;
  /** Runs the launch check, whose runner reports it started and never returns. */
  const script = `
    const { checkPayload } = await import(process.env.STATE);
    const { writeSync } = await import("node:fs");
    const lock = { app: { command: "acmepi", version: "1.0.0" }, runtime: { version: "0.87.1" } };
    checkPayload(
      "/unused",
      lock,
      () => {
        writeSync(1, "started\\n");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 600000);
        return { status: 0, stdout: "", stderr: "" };
      },
      {},
      "UPDATE_FAILED",
    );
  `;

  async function killMidCheck(): Promise<void> {
    const child = spawn(
      process.execPath,
      ["--input-type=module", "-e", script],
      {
        env: { ...process.env, STATE: stateModule },
        stdio: ["ignore", "pipe", "inherit"],
      },
    );
    const exited = new Promise((resolve) => child.on("exit", resolve));
    await new Promise<void>((resolve, reject) => {
      child.stdout.on("data", () => resolve());
      child.on("error", reject);
      child.on("exit", () => reject(new Error("exited before it started")));
    });
    child.kill("SIGKILL");
    await exited;
  }

  const lock = {
    app: { command: "acmepi", version: "1.0.0" },
    runtime: { version: "0.87.1" },
  } as Parameters<typeof checkPayload>[1];
  const passing = () => ({ status: 0, stdout: "Pi 0.87.1", stderr: "" });

  it("leaves its throwaway state until the next launch check removes it", async () => {
    await killMidCheck();
    expect(leftovers()).toHaveLength(1);
    const [name] = leftovers();
    expect(readTemporaryOwner(join(osTemp, name as string))?.owner.kind).toBe(
      "launch-check",
    );
    checkPayload("/unused", lock, passing, {}, "UPDATE_FAILED");
    expect(leftovers()).toEqual([]);
  }, 30_000);

  it("does not accumulate across repeated interrupted launch checks", async () => {
    const counts: number[] = [];
    for (let run = 0; run < 3; run += 1) {
      await killMidCheck();
      counts.push(leftovers().length);
      // The next operation, which is also interrupted, starts by reclaiming.
    }
    // Each killed check found the one before it removed by its own start.
    expect(counts).toEqual([1, 1, 1]);
    checkPayload("/unused", lock, passing, {}, "UPDATE_FAILED");
    expect(leftovers()).toEqual([]);
  }, 30_000);

  it("keeps the state of a launch check that is still running", async () => {
    const child = spawn(
      process.execPath,
      ["--input-type=module", "-e", script],
      {
        env: { ...process.env, STATE: stateModule },
        stdio: ["ignore", "pipe", "inherit"],
      },
    );
    try {
      await new Promise<void>((resolve, reject) => {
        child.stdout.on("data", () => resolve());
        child.on("error", reject);
      });
      checkPayload("/unused", lock, passing, {}, "UPDATE_FAILED");
      // Its own directory is gone, the concurrent process's is not.
      expect(leftovers()).toHaveLength(1);
      expect(
        readTemporaryOwner(join(osTemp, leftovers()[0] as string))?.owner.pid,
      ).toBe(child.pid);
    } finally {
      const exited = new Promise((resolve) => child.on("exit", resolve));
      child.kill("SIGKILL");
      await exited;
    }
  }, 30_000);
});

describe.runIf(HOST_EVIDENCED)("lifecycle operations", () => {
  it("an install starts by removing install staging a killed install left", async () => {
    const stale = plant(installHome(), ".staging-aaaaaa", "staging", deadPid());
    const live = plant(installHome(), ".staging-bbbbbb", "staging", livePid());
    await installed();
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(live)).toBe(true);
    // Installing left no staging directory of its own.
    expect(readdirSync(installHome()).filter((n) => n.startsWith("."))).toEqual(
      [".staging-bbbbbb"],
    );
  });

  it("verifying an archive removes stale extractions and leaves none of its own", async () => {
    const { a } = await installed();
    const stale = plant(osTemp, "piship-verify-aaaaaa", "verify", deadPid());
    const live = plant(osTemp, "piship-verify-bbbbbb", "verify", livePid());
    const verified = await verifyRelease(a.archive);
    expect(existsSync(stale)).toBe(false);
    // Its extraction is a directory of this process while it is in use.
    expect(leftovers().sort()).toContain("piship-verify-bbbbbb");
    expect(leftovers()).toHaveLength(2);
    verified.cleanup();
    expect(leftovers()).toEqual(["piship-verify-bbbbbb"]);
    expect(existsSync(live)).toBe(true);
  });

  it("an update removes what killed operations left and its own staging", async () => {
    const { opts } = await installed();
    const dead = deadPid();
    const stale = [
      plant(osTemp, "piship-launch-check-aaaaaa", "launch-check", dead),
      plant(osTemp, "piship-verify-bbbbbb", "verify", dead),
      plant(installHome(), ".staging-cccccc", "staging", dead),
      plant(appsDir(), ".staging-dddddd", "staging", dead),
    ];
    const live = plant(
      osTemp,
      "piship-launch-check-eeeeee",
      "launch-check",
      livePid(),
    );
    const result = await updateDistribution(ID, opts);
    expect(result.status).toBe("updated");
    for (const path of stale) expect(existsSync(path)).toBe(false);
    expect(existsSync(live)).toBe(true);
    expect(readdirSync(appsDir()).sort()).toEqual([
      "1.0.0",
      "1.1.0",
      "launch.mjs",
    ]);
    expect(leftovers()).toEqual(["piship-launch-check-eeeeee"]);
  });

  it("a rollback removes what killed launch checks left", async () => {
    const { opts } = await installed();
    await updateDistribution(ID, opts);
    const stale = plant(
      osTemp,
      "piship-launch-check-aaaaaa",
      "launch-check",
      deadPid(),
    );
    await rollbackDistribution(ID, opts);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(existsSync(stale)).toBe(false);
  });

  it.runIf(notRoot)(
    "the doctor says how many abandoned directories resist removal, without paths",
    async () => {
      await installed();
      const payload = readInstallReceipt(ID).payload;
      const ctx = {
        metadata: verifyPayload(payload),
        distributionDir: payload,
        stateDir: join(process.env.PISHIP_STATE_HOME as string, ID),
        mode: "personal" as const,
        out: () => {},
        err: () => {},
      };
      const lines = () => {
        const seen: string[] = [];
        const line = (label: string, value: string) =>
          seen.push(`${label}: ${value}`);
        lifecycleDoctor(ctx, "Update", line, line);
        return seen;
      };
      expect(lines().filter((line) => line.startsWith("temporaries"))).toEqual(
        [],
      );
      const stuck = plant(osTemp, "piship-verify-aaaaaa", "verify", deadPid());
      const locked = join(stuck, "x");
      chmodSync(locked, 0o500);
      try {
        // What a launch does first; the locked directory resists it.
        expect(reclaimOsTemporaries().failed).toEqual([stuck]);
        const report = lines().filter((line) => line.startsWith("temporaries"));
        expect(report).toEqual([
          "temporaries: 1 abandoned PiShip temporary directory could not be removed; check the permissions of the OS temp directory and the install home",
        ]);
        expect(report.join("\n")).not.toContain(osTemp);
      } finally {
        chmodSync(locked, 0o700);
      }
      expect(reclaimOsTemporaries().removed).toEqual([stuck]);
      expect(lines().filter((line) => line.startsWith("temporaries"))).toEqual(
        [],
      );
    },
  );
});
