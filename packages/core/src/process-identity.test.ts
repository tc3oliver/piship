import { spawn } from "node:child_process";
import { afterEach, expect, it } from "vitest";
import { processIdentity, processIdentityMatches } from "./process-identity.js";

const saved = { TZ: process.env.TZ, LC_ALL: process.env.LC_ALL };
const children: ReturnType<typeof spawn>[] = [];
afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const child of children.splice(0)) child.kill("SIGKILL");
});

function sleeper(): number {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  children.push(child);
  return child.pid as number;
}

it("reads one process's identity the same in every time zone and locale", () => {
  const pid = sleeper();
  const seen = new Set<string | undefined>();
  for (const [tz, locale] of [
    ["UTC", "C"],
    ["Asia/Tokyo", "C"],
    ["America/Los_Angeles", "fr_FR.UTF-8"],
    ["Asia/Kolkata", "de_DE.UTF-8"],
  ] as const) {
    process.env.TZ = tz;
    process.env.LC_ALL = locale;
    seen.add(processIdentity(pid));
  }
  expect(seen.size).toBe(1);
  expect([...seen][0]).toMatch(/\S/);
});

it("tells a matching, a different and an unknown start identity apart", () => {
  const pid = sleeper();
  const identity = processIdentity(pid) as string;
  expect(processIdentityMatches(identity, pid)).toBe(true);
  expect(processIdentityMatches("1", pid)).toBe(false);
  expect(processIdentityMatches(null, pid)).toBeUndefined();
});

it.runIf(process.platform === "darwin")(
  "reads macOS start time as UTC seconds and leaves the earlier text unknown",
  () => {
    const pid = sleeper();
    const identity = processIdentity(pid) as string;
    expect(identity).toMatch(/^\d+$/);
    expect(Math.abs(Number(identity) - Date.now() / 1000)).toBeLessThan(120);
    expect(
      processIdentityMatches("Thu Jan  1 00:00:00 1970", pid),
    ).toBeUndefined();
  },
);
