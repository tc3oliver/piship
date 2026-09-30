// Temporary directories a hard termination left. A real `piship build` is
// killed with SIGKILL while it stages its payload, and the next builds do not
// pile its leftovers up; the branded launcher removes what dead PiShip
// processes left in the OS temp directory and the install home, and leaves a
// live process's directories and every directory that is not PiShip's.
import { spawn, spawnSync } from "node:child_process";
import {
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
import { fileURLToPath } from "node:url";
import {
  TEMPORARY_OWNER_FILE,
  readTemporaryOwner,
  type TemporaryKind,
} from "@piship/contracts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { branded, launcher } from "../helpers/distribution.js";
import { deadPid, livePid, stopLiveProcesses } from "../helpers/processes.js";
import { plantTemporary } from "../helpers/temporaries.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const posix = process.platform !== "win32";

let temp: string;
let manifest: string;
let env: NodeJS.ProcessEnv;
beforeAll(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-stale-e2e-"));
  manifest = join(temp, "stale-agent", "piship.yaml");
  env = {
    ...process.env,
    PISHIP_STATE_HOME: join(temp, "state"),
    PISHIP_INSTALL_HOME: join(temp, "install"),
    PISHIP_BIN_HOME: join(temp, "bin"),
    HOME: join(temp, "home"),
    USERPROFILE: join(temp, "home"),
    // The launcher reclaims in this directory, never the machine's own.
    TMPDIR: join(temp, "os-temp"),
    TEMP: join(temp, "os-temp"),
    TMP: join(temp, "os-temp"),
  };
  delete env.PISHIP_BUILD_INPUT;
  mkdirSync(join(temp, "os-temp"));
  const run = (...args: string[]) =>
    spawnSync(process.execPath, [bin, ...args], {
      cwd: temp,
      env,
      encoding: "utf8",
    });
  expect(run("init", join(temp, "stale-agent")).status).toBe(0);
  const locked = run("lock", manifest);
  expect(locked.status, locked.stderr).toBe(0);
});
afterAll(() => {
  stopLiveProcesses();
  rmSync(temp, { recursive: true, force: true });
});

const dist = () => join(temp, "dist");
const stagings = () =>
  existsSync(dist())
    ? readdirSync(dist()).filter((name) => name.startsWith(".piship-"))
    : [];

/** `piship build`, which stages under `dist/.piship-stale-agent-*`. */
function startBuild(flags: string[]) {
  return spawn(process.execPath, [bin, "build", manifest, ...flags], {
    cwd: temp,
    env,
    // Its own process group, so the kill takes npm with it.
    detached: posix,
    stdio: ["ignore", "ignore", "pipe"],
  });
}

/**
 * Wait until this build has staged (a directory that was not there before it
 * started has a readable marker: the file exists a moment before it has its
 * record), then kill it. Leftovers of the builds before it do not count: they
 * are there from the start. Returns what the build said on stderr.
 */
async function killBuildMidStaging(flags: string[] = []): Promise<string> {
  const before = new Set(stagings());
  const child = startBuild(flags);
  let said = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    said += chunk.toString("utf8");
  });
  const exited = new Promise((resolve) => child.on("close", resolve));
  const deadline = Date.now() + 90_000;
  for (;;) {
    const name = stagings().find(
      (item) =>
        !before.has(item) &&
        // Not the name a sweep gives a directory it is removing.
        !item.startsWith(".piship-reclaim-") &&
        readTemporaryOwner(join(dist(), item)) !== undefined,
    );
    if (name) break;
    if (Date.now() > deadline) throw new Error("the build never staged");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  process.kill(-(child.pid as number), "SIGKILL");
  await exited;
  return said;
}

let built: string | undefined;
/** The finished build the launcher scenario runs. */
function build(): string {
  if (built) return built;
  const result = spawnSync(process.execPath, [bin, "build", manifest], {
    cwd: temp,
    env,
    encoding: "utf8",
  });
  expect(result.status, result.stderr).toBe(0);
  built = join(dist(), "stale-agent");
  return built;
}

describe.runIf(posix)("piship build killed with SIGKILL", () => {
  it("leaves its staging, which a later build reports and removes only when asked to", async () => {
    await killBuildMidStaging();
    expect(stagings()).toHaveLength(1);
    const [left] = stagings();
    const owner = readTemporaryOwner(join(dist(), left as string))?.owner;
    expect(owner).toMatchObject({ kind: "build" });
    // Not asked: dist/ is in the project, which a sandboxed agent may write,
    // so the next build says what it found and removes nothing.
    const said = await killBuildMidStaging();
    expect(said).toMatch(/1 abandoned staging directory of killed runs in /);
    expect(said).toContain("--reclaim-staging");
    expect(said).not.toContain(left as string);
    expect(stagings()).toHaveLength(2);
    expect(existsSync(join(dist(), left as string, TEMPORARY_OWNER_FILE))).toBe(
      true,
    );
    // Asked: what is abandoned goes, and leftovers do not grow however often.
    const counts: number[] = [];
    for (let run = 0; run < 3; run += 1) {
      await killBuildMidStaging(["--reclaim-staging"]);
      counts.push(stagings().length);
    }
    expect(counts).toEqual([1, 1, 1]);
    const result = spawnSync(
      process.execPath,
      [bin, "build", manifest, "--reclaim-staging"],
      { cwd: temp, env, encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    built = join(dist(), "stale-agent");
    expect(stagings()).toEqual([]);
    expect(readdirSync(dist())).toEqual(["stale-agent"]);
    // The payload is not marked: the marker lives beside it, not in it.
    expect(existsSync(join(built, TEMPORARY_OWNER_FILE))).toBe(false);
  }, 240_000);
});

describe("the branded launcher", () => {
  const osTemp = () => join(temp, "os-temp");
  const installHome = () => join(temp, "install");

  const plant = (
    parent: string,
    name: string,
    kind: TemporaryKind,
    pid: number,
  ) => plantTemporary(parent, name, kind, pid);

  it("removes what dead PiShip processes left and nothing else", async () => {
    const payload = build();
    const dead = deadPid();
    const alive = livePid();
    mkdirSync(join(installHome(), "apps", "stale-agent"), { recursive: true });
    const stale = [
      plant(osTemp(), "piship-sandbox-aaaaaa", "sandbox", dead),
      plant(osTemp(), "piship-verify-bbbbbb", "verify", dead),
      plant(osTemp(), "piship-launch-check-cccccc", "launch-check", dead),
      plant(osTemp(), "piship-release-test-dddddd", "release-test", dead),
      plant(installHome(), ".staging-eeeeee", "staging", dead),
      plant(
        join(installHome(), "apps", "stale-agent"),
        ".staging-ffffff",
        "staging",
        dead,
      ),
    ];
    const kept = [
      plant(osTemp(), "piship-sandbox-gggggg", "sandbox", alive),
      plant(installHome(), ".staging-hhhhhh", "staging", alive),
    ];
    // Not PiShip's: shares a prefix, or has the exact shape without a marker.
    const users = ["piship-sandbox-notes", "piship-verify-abc123"].map(
      (name) => {
        const path = join(osTemp(), name);
        mkdirSync(path);
        writeFileSync(join(path, "keep.txt"), "user data");
        return path;
      },
    );
    const version = await branded(
      launcher(payload, "stale-agent"),
      ["--version"],
      {
        cwd: temp,
        env,
      },
    );
    expect(version.status, version.stderr).toBe(0);
    for (const path of stale) expect(existsSync(path)).toBe(false);
    for (const path of kept)
      expect(readFileSync(join(path, "x", "output.txt"), "utf8")).toBe(
        "private tool output",
      );
    for (const path of users)
      expect(readFileSync(join(path, "keep.txt"), "utf8")).toBe("user data");
  }, 120_000);
});
