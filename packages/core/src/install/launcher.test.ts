// The installed launcher (`apps/<id>/launch.mjs`): the build it is stamped
// with, what its timing report prints, and its replacement when an earlier
// PiShip left a different one on disk.
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  appsDir,
  fakeRun,
  ID,
  installed,
  stateDir,
  useLifecycleHomes,
} from "../../../../tests/helpers/lifecycle-faults.js";
import { launcherBuildOf } from "../launcher-source.js";
import { rollbackDistribution, updateDistribution } from "../update/index.js";
import {
  commandShimSource,
  inspectInstalledLauncher,
  installedLauncherPath,
  launcherSource,
  ownsCommandShim,
  refreshInstalledLauncher,
  writeShim,
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
      "lease_held",
      "gate_released",
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

describe("the V8 compile cache of a bundled payload", () => {
  // The cache is a directory the launcher creates before it asks Node to use
  // it, so the directory shows whether it was asked.
  async function launchWith(options: {
    bundled: boolean;
    lock?: "missing" | Record<string, unknown>;
  }): Promise<boolean> {
    await installed();
    const receipt = readInstallReceipt(ID);
    const lockPath = join(receipt.payload, "piship.lock");
    if (options.bundled)
      writeFileSync(join(receipt.payload, "metadata", "bundle.json"), "{}\n");
    if (options.lock === "missing") rmSync(lockPath);
    else if (options.lock)
      writeFileSync(
        lockPath,
        `${JSON.stringify({ ...JSON.parse(readFileSync(lockPath, "utf8")), ...options.lock }, null, 2)}\n`,
      );
    expect(existsSync(stateDir())).toBe(true);
    const result = spawnSync(process.execPath, [receipt.launcher as string], {
      encoding: "utf8",
      env: { ...process.env, NODE_DISABLE_COMPILE_CACHE: "" },
    });
    expect(result.status, result.stderr).toBe(0);
    return existsSync(join(stateDir(), "cache", "compile"));
  }

  it("is kept for a bundled payload whose lock does not ask for launch verification", async () => {
    expect(await launchWith({ bundled: true })).toBe(true);
  });

  it("is kept when the lock declares verifyAtLaunch false", async () => {
    expect(
      await launchWith({ bundled: true, lock: { verifyAtLaunch: false } }),
    ).toBe(true);
  });

  it("is off when the lock asks for launch verification, since a cache in state is not verified", async () => {
    expect(
      await launchWith({ bundled: true, lock: { verifyAtLaunch: true } }),
    ).toBe(false);
  });

  it("is off when the lock cannot be read (the payload is damaged)", async () => {
    expect(await launchWith({ bundled: true, lock: "missing" })).toBe(false);
  });

  it("is off for a payload that is not bundled", async () => {
    expect(await launchWith({ bundled: false })).toBe(false);
  });

  it("is not created before the state directory exists", async () => {
    await installed();
    const receipt = readInstallReceipt(ID);
    writeFileSync(join(receipt.payload, "metadata", "bundle.json"), "{}\n");
    rmSync(stateDir(), { recursive: true, force: true });
    const result = spawnSync(process.execPath, [receipt.launcher as string], {
      encoding: "utf8",
    });
    expect(result.status, result.stderr).toBe(0);
    expect(existsSync(stateDir())).toBe(false);
  });
});

describe("the command shim", () => {
  const launcher = "C:\\Users\\me\\install\\apps\\acmepi\\launch.mjs";
  const posixLauncher = "/home/me/it's/apps/acmepi/launch.mjs";
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0))
      rmSync(root, { recursive: true, force: true });
  });
  const file = (content: string) => {
    const root = mkdtempSync(join(tmpdir(), "piship-shim-"));
    roots.push(root);
    const path = join(root, "acmepi");
    writeFileSync(path, content);
    return path;
  };

  it("runs node on the Windows PATH without spawning `where` first", () => {
    const text = commandShimSource(launcher, "win32");
    expect(text).toBe(
      `@echo off\r\nnode "${launcher}" %*\r\nif %errorlevel% equ 9009 (echo Node.js 22.19.0 or newer is required. Install Node separately. 1>&2 & exit /b 1)\r\n`,
    );
    // No process is started to find node, and none is pinned: a path written
    // at install time outlives the node the user switches to.
    expect(text).not.toMatch(/where|\.exe|if exist/);
    expect(text.split("\r\n").filter(Boolean)).toHaveLength(3);
  });

  it("keeps the POSIX shim as it was", () => {
    expect(commandShimSource(posixLauncher, "linux")).toBe(
      `#!/bin/sh\ncommand -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }\nexec node '/home/me/it'"'"'s/apps/acmepi/launch.mjs' "$@"\n`,
    );
    expect(commandShimSource(posixLauncher, "darwin")).toBe(
      commandShimSource(posixLauncher, "linux"),
    );
  });

  it("is owned when its text is exactly one PiShip wrote, the earlier Windows text included", () => {
    const legacy = `@echo off\r\nwhere node >nul 2>nul || (echo Node.js 22.19.0 or newer is required. Install Node separately. 1>&2 & exit /b 1)\r\nnode "${launcher}" %*\r\n`;
    expect(
      ownsCommandShim(
        file(commandShimSource(launcher, "win32")),
        launcher,
        "win32",
      ),
    ).toBe(true);
    expect(ownsCommandShim(file(legacy), launcher, "win32")).toBe(true);
    // Only on Windows, and only for this launcher.
    expect(ownsCommandShim(file(legacy), launcher, "linux")).toBe(false);
    expect(
      ownsCommandShim(
        file(commandShimSource(launcher, "win32")),
        `${launcher}x`,
        "win32",
      ),
    ).toBe(false);
    expect(
      ownsCommandShim(
        file(`${commandShimSource(launcher, "win32")}rem edited\r\n`),
        launcher,
        "win32",
      ),
    ).toBe(false);
    expect(
      ownsCommandShim(join(tmpdir(), "no-such-shim"), launcher, "win32"),
    ).toBe(false);
  });

  it("is written once, executable off Windows", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-shim-"));
    roots.push(root);
    const path = join(root, "acmepi");
    writeShim(path, posixLauncher, "linux");
    expect(readFileSync(path, "utf8")).toBe(
      commandShimSource(posixLauncher, "linux"),
    );
    expect(statSync(path).mode & 0o111).toBe(0o111);
    expect(() => writeShim(path, posixLauncher, "linux")).toThrow(/EEXIST/);
  });
});
