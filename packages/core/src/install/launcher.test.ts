// The installed launcher (`apps/<id>/launch.mjs`): the build it is stamped
// with, what its timing report prints, and its replacement when an earlier
// PiShip left a different one on disk.
import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  appsDir,
  fakeRun,
  ID,
  installed,
  useLifecycleHomes,
} from "../../../../tests/helpers/lifecycle-faults.js";
import { launcherBuildOf } from "../launcher-source.js";
import { rollbackDistribution, updateDistribution } from "../update/index.js";
import {
  inspectInstalledLauncher,
  installedLauncherPath,
  launcherSource,
  refreshInstalledLauncher,
} from "./launcher.js";
import { readInstallReceipt } from "./receipt.js";

useLifecycleHomes();

describe("the launcher's build stamp", () => {
  it("names the build in a comment and in the timing report, with no placeholder left", () => {
    const source = launcherSource(ID);
    const build = launcherBuildOf(source);
    expect(build).toMatch(/^[0-9a-f]{12}$/);
    expect(source).not.toContain("@@LAUNCHER_BUILD@@");
    expect(source).toContain(`timing.notes.installed_launcher = "${build}"`);
    expect(launcherSource(ID)).toBe(source);
    expect(launcherBuildOf(launcherSource("otherpi"))).not.toBe(build);
  });

  it("keeps its module location out of the source the bundler rewrites", () => {
    // A bundled runtime refreshes the launcher too. The bundler rewrites
    // every literal occurrence of the module-URL property in the modules it
    // bundles, which would change the launcher's text into one that looks for
    // its receipts in the wrong directory.
    const literal = ["import", "meta", "url"].join(".");
    const own = readFileSync(new URL("./launcher.ts", import.meta.url), "utf8");
    expect(own).not.toContain(literal);
    expect(launcherSource(ID)).toContain(`fileURLToPath(${literal})`);
  });
});

describe("an installed launcher", () => {
  it("prints which launcher ran, and the identity spawns, with PISHIP_DEBUG_TIMING=1", async () => {
    await installed();
    const receipt = readInstallReceipt(ID);
    // The fake payload loads no @piship/contracts, so nothing reports; the
    // marks are in the shared store for whichever module does.
    const build = launcherBuildOf(launcherSource(ID));
    const probe = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `process.on("exit", () => { const s = globalThis[Symbol.for("piship.startup-timing")]; process.stdout.write(JSON.stringify(s)); });
await import(${JSON.stringify(receipt.launcher)});`,
      ],
      { encoding: "utf8", env: { ...process.env, PISHIP_DEBUG_TIMING: "1" } },
    );
    expect(probe.status, probe.stderr).toBe(0);
    const store = JSON.parse(probe.stdout.split("\n").at(-1) as string) as {
      marks: { name: string; ms: number }[];
      notes: Record<string, string>;
      counters: Record<string, number>;
    };
    expect(store.notes.installed_launcher).toBe(build);
    expect(store.marks.map((mark) => mark.name)).toEqual([
      "launcher_start",
      "gate_acquired",
      "receipt_resolved",
      "core_loaded",
      "lease_held",
      "launcher_handoff",
    ]);
    // Reading no process identity: nothing was contended.
    expect(store.counters.identity_spawns ?? 0).toBe(0);
  });

  it("records nothing and prints nothing when timing is off", async () => {
    await installed();
    const receipt = readInstallReceipt(ID);
    const probe = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `process.on("exit", () => process.stdout.write(String(globalThis[Symbol.for("piship.startup-timing")])));
await import(${JSON.stringify(receipt.launcher)});`,
      ],
      {
        encoding: "utf8",
        env: { ...process.env, PISHIP_DEBUG_TIMING: "" },
      },
    );
    expect(probe.status, probe.stderr).toBe(0);
    expect(probe.stdout.split("\n").at(-1)).toBe("undefined");
    expect(probe.stderr).not.toContain("PISHIP_TIMING");
  });
});

describe("replacing a launcher an earlier PiShip installed", () => {
  it("replaces an outdated launcher once, and only for the active release", async () => {
    await installed();
    const path = installedLauncherPath(ID);
    const payload = readInstallReceipt(ID).payload;
    const current = readFileSync(path, "utf8");
    expect(inspectInstalledLauncher(ID)).toMatchObject({ current: true });
    // What a launcher installed before builds were stamped looked like.
    const earlier = current
      .replace(/^\/\/ launcher-build: .*\n/m, "")
      .replace(/^const timing = .*\nconst mark = .*\n/m, "");
    expect(earlier).not.toBe(current);
    writeFileSync(path, earlier);
    expect(inspectInstalledLauncher(ID)).toMatchObject({
      current: false,
      build: undefined,
    });
    // A build directory, or a release that is not the active one, does not
    // rewrite what the active release runs.
    expect(refreshInstalledLauncher(ID, appsDir())).toBe(false);
    expect(readFileSync(path, "utf8")).toBe(earlier);
    expect(refreshInstalledLauncher(ID, payload)).toBe(true);
    expect(readFileSync(path, "utf8")).toBe(current);
    expect(refreshInstalledLauncher(ID, payload)).toBe(false);
  });

  it("leaves a launcher that is not PiShip's own alone", async () => {
    await installed();
    const path = installedLauncherPath(ID);
    writeFileSync(path, "// my own launcher\n");
    expect(inspectInstalledLauncher(ID)).toBeUndefined();
    expect(refreshInstalledLauncher(ID, readInstallReceipt(ID).payload)).toBe(
      false,
    );
    expect(readFileSync(path, "utf8")).toBe("// my own launcher\n");
    // And nothing installed is not an error.
    expect(refreshInstalledLauncher("missingpi", appsDir())).toBe(false);
  });

  it("leaves no temporary file beside the launcher", async () => {
    await installed();
    const path = installedLauncherPath(ID);
    writeFileSync(path, readFileSync(path, "utf8").replace(/build: .*/, ""));
    expect(refreshInstalledLauncher(ID, readInstallReceipt(ID).payload)).toBe(
      true,
    );
    expect(
      readdirSync(appsDir()).filter((name) => name.endsWith(".tmp")),
    ).toEqual([]);
  });

  // What a launcher installed before builds were stamped looked like.
  const earlierLauncher = (current: string) =>
    current
      .replace(/^\/\/ launcher-build: .*\n/m, "")
      .replace(/^const timing = .*\nconst mark = .*\n/m, "");

  it("replaces a stale launcher when an update activates a release, and when a rollback does", async () => {
    const { opts } = await installed();
    const path = installedLauncherPath(ID);
    const current = readFileSync(path, "utf8");
    writeFileSync(path, earlierLauncher(current));
    await updateDistribution(ID, opts);
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
    expect(readFileSync(path, "utf8")).toBe(current);

    writeFileSync(path, earlierLauncher(current));
    await rollbackDistribution(ID, { runCheck: fakeRun });
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(readFileSync(path, "utf8")).toBe(current);
  }, 60_000);

  it("does not fail an update whose launcher cannot be replaced", async () => {
    const { opts } = await installed();
    const path = installedLauncherPath(ID);
    // A directory where the temporary file would go makes the write fail.
    writeFileSync(path, earlierLauncher(readFileSync(path, "utf8")));
    mkdirSync(`${path}.${process.pid}.tmp`);
    await expect(updateDistribution(ID, opts)).resolves.toMatchObject({
      status: "updated",
    });
    expect(inspectInstalledLauncher(ID)).toMatchObject({ current: false });
  }, 60_000);
});
