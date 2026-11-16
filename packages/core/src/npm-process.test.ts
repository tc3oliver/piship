import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  fakeNpmDirectory,
  withFakeNpm,
} from "../../../tests/helpers/fake-npm.js";
import {
  NPM_TIMED_OUT,
  npmTimeoutMinutes,
  supervisedNpm,
} from "./npm-process.js";
import { runCommand } from "./pi-packages/command.js";

const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
};

async function until(check: () => boolean, ms = 10_000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return true;
    await new Promise((done) => setTimeout(done, 100));
  }
  return check();
}

let directory = "";
const leftovers: number[] = [];
const hangingEnv = () => {
  directory = mkdtempSync(join(tmpdir(), "piship-npm-timeout-"));
  return withFakeNpm({
    ...process.env,
    PISHIP_REQUIRE_REGISTRY: "",
    PISHIP_FAKE_NPM_HANG: join(directory, "grandchild.pid"),
  });
};
const grandchild = async () => {
  const file = join(directory, "grandchild.pid");
  expect(
    await until(() => existsSync(file) && readFileSync(file, "utf8") !== ""),
  ).toBe(true);
  const pid = Number(readFileSync(file, "utf8"));
  leftovers.push(pid);
  return pid;
};
const fakeCli = () =>
  join(fakeNpmDirectory(), "node_modules", "npm", "bin", "npm-cli.js");

afterEach(() => {
  delete process.env.PISHIP_NPM_TIMEOUT_MINUTES;
  for (const pid of leftovers.splice(0))
    try {
      process.kill(pid, "SIGKILL");
    } catch {}
  if (directory) rmSync(directory, { recursive: true, force: true });
});

describe("npm under its supervisor", () => {
  it("defaults to 10 minutes and takes a positive PISHIP_NPM_TIMEOUT_MINUTES", () => {
    expect(npmTimeoutMinutes({})).toBe(10);
    expect(npmTimeoutMinutes({ PISHIP_NPM_TIMEOUT_MINUTES: "30" })).toBe(30);
    expect(npmTimeoutMinutes({ PISHIP_NPM_TIMEOUT_MINUTES: "0" })).toBe(10);
    expect(npmTimeoutMinutes({ PISHIP_NPM_TIMEOUT_MINUTES: "x" })).toBe(10);
  });

  it("stops a hung npm ci and its children at the time limit, and says why", async () => {
    process.env.PISHIP_NPM_TIMEOUT_MINUTES = "0.05";
    const env = hangingEnv();
    const started = Date.now();
    const result = runCommand("npm", ["ci"], { cwd: directory, env });
    expect(result.status).toBe(NPM_TIMED_OUT);
    expect(Date.now() - started).toBeLessThan(30_000);
    expect(result.stderr).toContain("npm timed out after 0.05 minutes");
    expect(result.stderr).toContain("registry may be unreachable");
    expect(result.stderr).toContain("PISHIP_NPM_TIMEOUT_MINUTES");
    const pid = await grandchild();
    expect(await until(() => !alive(pid))).toBe(true);
  }, 60_000);

  it("stops npm's children when the PiShip process that ran it is killed", async () => {
    const env = hangingEnv();
    const { file, args } = supervisedNpm(process.execPath, [fakeCli(), "ci"]);
    // A stand-in for PiShip: it waits in spawnSync, as PiShip does, and names
    // itself as the parent the supervisor watches.
    const parent = spawn(
      process.execPath,
      [
        "-e",
        `const a = JSON.parse(process.env.SUPERVISED);
         const o = JSON.parse(a[2]); o.parent = process.pid; a[2] = JSON.stringify(o);
         require("node:child_process").spawnSync(process.env.NODE_FILE, a, { stdio: "ignore" });`,
      ],
      {
        env: { ...env, SUPERVISED: JSON.stringify(args), NODE_FILE: file },
        stdio: "ignore",
      },
    );
    const pid = await grandchild();
    expect(alive(pid)).toBe(true);
    parent.kill("SIGKILL");
    expect(await until(() => !alive(pid))).toBe(true);
  }, 60_000);

  it.skipIf(process.platform === "win32")(
    "stops npm's process group on SIGTERM and exits at once",
    async () => {
      const env = hangingEnv();
      const { file, args } = supervisedNpm(process.execPath, [fakeCli(), "ci"]);
      const supervisor = spawn(file, args, { env, stdio: "ignore" });
      const exited = new Promise<number | null>((done) =>
        supervisor.on("exit", (code) => done(code)),
      );
      const pid = await grandchild();
      supervisor.kill("SIGTERM");
      expect(await exited).toBe(130);
      expect(await until(() => !alive(pid))).toBe(true);
    },
    60_000,
  );
});
