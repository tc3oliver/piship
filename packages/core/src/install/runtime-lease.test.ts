import { spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { holdRuntimeLease, runtimeLeases } from "./runtime-lease.js";

const roots: string[] = [];
const saved = process.env.PISHIP_INSTALL_HOME;
afterEach(() => {
  if (saved === undefined) delete process.env.PISHIP_INSTALL_HOME;
  else process.env.PISHIP_INSTALL_HOME = saved;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function home(): string {
  const root = mkdtempSync(join(tmpdir(), "piship-runtime-lease-"));
  roots.push(root);
  process.env.PISHIP_INSTALL_HOME = root;
  return root;
}

it("recovers a runtime lease left by a crashed process", async () => {
  const root = home();
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      "import { holdRuntimeLease } from '@piship/core'; holdRuntimeLease('acme', '1.0.0'); process.stdout.write('ready'); setInterval(() => {}, 1000);",
    ],
    {
      cwd: process.cwd(),
      env: { ...process.env },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  await new Promise<void>((resolve, reject) => {
    child.stdout?.once("data", () => resolve());
    child.once("error", reject);
  });
  expect(runtimeLeases("acme").filter((item) => item.live)).toHaveLength(1);
  child.kill("SIGKILL");
  await new Promise<void>((resolve) => child.once("exit", () => resolve()));
  expect(runtimeLeases("acme", true).filter((item) => item.live)).toHaveLength(
    0,
  );
  expect(
    readdirSync(join(root, "apps", "acme", ".runtime-leases", "1.0.0")),
  ).toHaveLength(0);
});

it("does not mistake a reused PID for the original process instance", () => {
  const root = home();
  const directory = join(root, "apps", "acme", ".runtime-leases", "1.0.0");
  mkdirSync(directory, { recursive: true });
  const path = join(directory, "00000000-0000-0000-0000-000000000000.json");
  writeFileSync(
    path,
    JSON.stringify({
      schema: "piship-runtime-lease/v1",
      pid: process.pid,
      identity: "1",
      instance: "00000000-0000-0000-0000-000000000000",
      version: "1.0.0",
    }),
  );
  const now = new Date();
  utimesSync(path, now, now);
  expect(runtimeLeases("acme", true)[0]?.live).toBe(false);
  expect(existsSync(path)).toBe(false);
});

it("tracks simultaneous sessions on different payload versions", () => {
  home();
  const releaseOne = holdRuntimeLease("acme", "1.0.0");
  const releaseTwo = holdRuntimeLease("acme", "2.0.0");
  try {
    expect(
      runtimeLeases("acme")
        .filter((item) => item.live)
        .map((item) => item.version)
        .sort(),
    ).toEqual(["1.0.0", "2.0.0"]);
    releaseOne();
    expect(
      runtimeLeases("acme")
        .filter((item) => item.live)
        .map((item) => item.version),
    ).toEqual(["2.0.0"]);
  } finally {
    releaseOne();
    releaseTwo();
  }
});

it("keeps a lease live for a checker in another time zone", async () => {
  home();
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      "import { holdRuntimeLease } from '@piship/core'; holdRuntimeLease('acme', '1.0.0'); process.stdout.write('ready'); setInterval(() => {}, 1000);",
    ],
    {
      cwd: process.cwd(),
      env: { ...process.env, TZ: "Asia/Tokyo", LC_ALL: "fr_FR.UTF-8" },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const tz = process.env.TZ;
  try {
    await new Promise<void>((resolve, reject) => {
      child.stdout?.once("data", () => resolve());
      child.once("error", reject);
    });
    process.env.TZ = "America/Los_Angeles";
    expect(runtimeLeases("acme", true).map((item) => item.live)).toEqual([
      true,
    ]);
  } finally {
    if (tz === undefined) delete process.env.TZ;
    else process.env.TZ = tz;
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
  }
});

it.runIf(process.platform === "darwin")(
  "keeps a live process's lease written in the earlier ps text format",
  () => {
    const root = home();
    const directory = join(root, "apps", "acme", ".runtime-leases", "1.0.0");
    mkdirSync(directory, { recursive: true });
    const path = join(directory, "00000000-0000-0000-0000-000000000000.json");
    // The local-time `ps -o lstart=` text earlier releases recorded, in a
    // time zone that matches no reading of this process's start time.
    writeFileSync(
      path,
      JSON.stringify({
        schema: "piship-runtime-lease/v1",
        pid: process.pid,
        identity: "Thu Jan  1 00:00:00 1970",
        instance: "00000000-0000-0000-0000-000000000000",
        version: "1.0.0",
      }),
    );
    expect(runtimeLeases("acme", true)[0]?.live).toBe(true);
    expect(existsSync(path)).toBe(true);
  },
);
