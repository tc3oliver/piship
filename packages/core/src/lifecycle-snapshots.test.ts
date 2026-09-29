// Migration snapshots of an update that fails or is killed at each step of
// building one: the active release is unaffected, no incomplete snapshot is
// left or counted, and what a killed process left is reclaimed by the next
// update.
import { cpSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  deadPid,
  installed,
  launch,
  rejection,
  snapshotsDir,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import { type LifecyclePhase, readInstallReceipt } from "./install/index.js";
import { updateDistribution } from "./update/index.js";

vi.mock("node:fs", async (importOriginal) =>
  (await import("../../../tests/helpers/fs-faults.js")).faultyFs(
    await importOriginal(),
  ),
);

useLifecycleHomes();

const phases: LifecyclePhase[] = [
  "snapshot-directory",
  "snapshot-file",
  "snapshot-files",
  "snapshot-manifest",
  "snapshot-publish",
];

describe.runIf(HOST_EVIDENCED)("interrupted migration snapshots", () => {
  it.each(phases)(
    "leaves no snapshot data and the active release after a failure at %s",
    async (phase) => {
      const { opts } = await installed();
      await rejection(
        updateDistribution(ID, {
          ...opts,
          faults: (at) => {
            if (at === phase) throw new Error(`failed at ${at}`);
          },
        }),
      );
      expect(readInstallReceipt(ID).active).toBe("1.0.0");
      expect(launch()).toBe("payload 1.0.0");
      expect(readdirSync(snapshotsDir())).toEqual([]);
      const result = await updateDistribution(ID, opts);
      expect(readdirSync(snapshotsDir())).toEqual([
        (result.snapshot as string).split(/[/\\]/).at(-1),
      ]);
    },
  );

  it.each(phases)(
    "reclaims what a process killed at %s left, on the next update",
    async (phase) => {
      const { opts } = await installed();
      let left = "";
      await rejection(
        updateDistribution(ID, {
          ...opts,
          faults: (at) => {
            if (at !== phase) return;
            // What a killed process leaves: its staging directory as it
            // was, under a process ID that no longer exists.
            const staging = readdirSync(snapshotsDir()).find((name) =>
              name.startsWith(".staging-"),
            ) as string;
            left = join(snapshotsDir(), `.staging-p${deadPid()}-killed`);
            cpSync(join(snapshotsDir(), staging), left, { recursive: true });
            throw new Error("killed");
          },
        }),
      );
      expect(existsSync(left)).toBe(true);
      expect(readInstallReceipt(ID).active).toBe("1.0.0");
      const result = await updateDistribution(ID, opts);
      expect(result.status).toBe("updated");
      expect(existsSync(left)).toBe(false);
      expect(readdirSync(snapshotsDir())).toHaveLength(1);
      expect(readdirSync(result.snapshot as string).sort()).toEqual([
        "config",
        "snapshot.json",
      ]);
    },
  );
});
