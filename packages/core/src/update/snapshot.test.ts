// Migration snapshot retention: only completed snapshots count, the newest
// three by creation sequence are kept whatever the wall clock did, and what
// interrupted snapshots left is reclaimed.
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { LifecyclePhase } from "../install/receipt.js";
import { STALE_TEMPORARY_MS } from "../install/temporaries.js";
import { snapshotState } from "./state.js";

let state: string;
beforeEach(() => {
  state = mkdtempSync(join(tmpdir(), "piship-snapshots-"));
  mkdirSync(join(state, "config"));
  writeFileSync(join(state, "config", "preferences.json"), '{"theme":"dark"}');
  writeFileSync(join(state, "config", "policy.json"), "{}");
});
afterEach(() => {
  rmSync(state, { recursive: true, force: true });
});

const root = () => join(state, "migration", "snapshots");
const at = (iso: string) => new Date(iso);
/** Snapshots on disk, by the `to` version each records. */
function retained(): string[] {
  return readdirSync(root())
    .sort()
    .map(
      (name) =>
        JSON.parse(readFileSync(join(root(), name, "snapshot.json"), "utf8"))
          .to as string,
    );
}
function snapshot(
  to: string,
  time: string,
  faults?: (phase: LifecyclePhase) => void,
) {
  return snapshotState(state, "0.9.0", to, at(time), faults);
}

describe("snapshotState", () => {
  it("publishes a complete snapshot with its sequence and time", () => {
    const path = snapshot("1.0.0", "2026-09-30T00:00:00.000Z") as string;
    expect(readdirSync(root())).toEqual(["00000001-0.9.0-to-1.0.0"]);
    expect(readdirSync(path).sort()).toEqual(["config", "snapshot.json"]);
    expect(
      JSON.parse(readFileSync(join(path, "snapshot.json"), "utf8")),
    ).toMatchObject({
      schema: "piship-snapshot/v1",
      sequence: 1,
      time: "2026-09-30T00:00:00.000Z",
      files: ["config/preferences.json", "config/policy.json"],
    });
  });

  it("keeps the newest three by sequence after the clock moves back", () => {
    snapshot("A", "2026-09-30T00:00:00.000Z");
    snapshot("B", "2026-09-30T01:00:00.000Z");
    snapshot("C", "2026-09-30T02:00:00.000Z");
    snapshot("D", "2026-09-29T23:00:00.000Z");
    expect(retained()).toEqual(["B", "C", "D"]);
    snapshot("E", "2026-09-29T23:30:00.000Z");
    expect(retained()).toEqual(["C", "D", "E"]);
  });

  it("keeps the newest three by sequence after a forward jump and a return to normal time", () => {
    snapshot("A", "2026-09-30T00:00:00.000Z");
    snapshot("B", "2031-01-01T00:00:00.000Z");
    snapshot("C", "2026-09-30T01:00:00.000Z");
    snapshot("D", "2026-09-30T02:00:00.000Z");
    expect(retained()).toEqual(["B", "C", "D"]);
    snapshot("E", "2026-09-30T03:00:00.000Z");
    expect(retained()).toEqual(["C", "D", "E"]);
  });

  it.each<LifecyclePhase>([
    "snapshot-directory",
    "snapshot-file",
    "snapshot-files",
    "snapshot-manifest",
    "snapshot-publish",
  ])("counts only completed snapshots after failures at %s", (phase) => {
    snapshot("A", "2026-09-30T00:00:00.000Z");
    for (const time of ["01", "02", "03"]) {
      expect(() =>
        snapshot("failed", `2026-09-30T${time}:00:00.000Z`, (step) => {
          if (step === phase) throw new Error(`failed at ${step}`);
        }),
      ).toThrow(`failed at ${phase}`);
      expect(retained()).toEqual(["A"]);
    }
    snapshot("B", "2026-09-30T04:00:00.000Z");
    snapshot("C", "2026-09-30T05:00:00.000Z");
    expect(retained()).toEqual(["A", "B", "C"]);
    snapshot("D", "2026-09-30T06:00:00.000Z");
    expect(retained()).toEqual(["B", "C", "D"]);
  });

  it("reclaims what killed snapshots left, but not a live one's staging", () => {
    snapshot("A", "2026-09-30T00:00:00.000Z");
    const dead = spawnSync(process.execPath, ["-e", ""]).pid as number;
    // A killed process's staging directory, one too old to be live, and an
    // incomplete snapshot directory an earlier PiShip left.
    const killed = join(root(), `.staging-p${dead}-abc123`);
    cpSync(join(root(), readdirSync(root())[0] as string), killed, {
      recursive: true,
    });
    const old = join(root(), `.staging-p${process.pid}-old123`);
    mkdirSync(old);
    const then = new Date(Date.now() - STALE_TEMPORARY_MS - 60_000);
    utimesSync(old, then, then);
    const live = join(root(), `.staging-p${process.pid}-live12`);
    mkdirSync(live);
    const incomplete = join(root(), "2026-09-30T00-00-00-000Z-0.9.0-to-1.0.0");
    mkdirSync(join(incomplete, "config"), { recursive: true });
    writeFileSync(join(incomplete, "config", "preferences.json"), "{}");
    const unrelated = join(root(), ".staging-notes");
    mkdirSync(unrelated);
    snapshot("B", "2026-09-30T01:00:00.000Z");
    expect(existsSync(killed)).toBe(false);
    expect(existsSync(old)).toBe(false);
    expect(existsSync(incomplete)).toBe(false);
    expect(existsSync(live)).toBe(true);
    expect(existsSync(unrelated)).toBe(true);
    rmSync(live, { recursive: true });
    rmSync(unrelated, { recursive: true });
    expect(retained()).toEqual(["A", "B"]);
  });

  it("orders snapshots written before sequences first, by their recorded time", () => {
    mkdirSync(root(), { recursive: true });
    for (const [name, time] of [
      ["2026-09-30T02-00-00-000Z-0.9.0-to-L2", "2026-09-30T02:00:00.000Z"],
      ["2026-09-30T01-00-00-000Z-0.9.0-to-L1", "2026-09-30T01:00:00.000Z"],
    ] as const) {
      mkdirSync(join(root(), name));
      writeFileSync(
        join(root(), name, "snapshot.json"),
        JSON.stringify({
          schema: "piship-snapshot/v1",
          to: name.slice(-2),
          time,
        }),
      );
    }
    snapshot("A", "2020-01-01T00:00:00.000Z");
    snapshot("B", "2020-01-01T00:00:00.000Z");
    expect(retained().sort()).toEqual(["A", "B", "L2"]);
  });
});
