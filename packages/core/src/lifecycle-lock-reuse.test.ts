// Update against a lifecycle lock left by a crashed holder whose process ID
// another live process now has, and against a live holder.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  age,
  appsDir,
  installed,
  livePid,
  rejection,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import { readInstallReceipt } from "./install/index.js";
import { LIFECYCLE_LOCK_STALE_MS } from "./install/lifecycle-lock.js";
import { updateDistribution } from "./update/index.js";

vi.mock("node:fs", async (importOriginal) =>
  (await import("../../../tests/helpers/fs-faults.js")).faultyFs(
    await importOriginal(),
  ),
);

useLifecycleHomes();

describe.runIf(HOST_EVIDENCED)(
  "a lifecycle lock after process ID reuse",
  () => {
    it("recovers the lock of a crashed holder whose ID another live process now has", async () => {
      const { opts } = await installed();
      const lock = join(appsDir(), ".lifecycle.lock");
      writeFileSync(
        lock,
        JSON.stringify({
          schema: "piship-lifecycle-lock/v1",
          pid: livePid(),
          instance: "crashed-holder-a",
          acquiredAt: new Date(Date.now() - 3_600_000).toISOString(),
        }),
      );
      age(lock, LIFECYCLE_LOCK_STALE_MS + 60_000);
      await expect(updateDistribution(ID, opts)).resolves.toMatchObject({
        status: "updated",
      });
      expect(existsSync(lock)).toBe(false);
    });

    it("still waits for a live holder that keeps its lease", async () => {
      const { opts } = await installed();
      const lock = join(appsDir(), ".lifecycle.lock");
      const holder = livePid();
      writeFileSync(
        lock,
        JSON.stringify({
          schema: "piship-lifecycle-lock/v1",
          pid: holder,
          instance: "live-holder-b",
          acquiredAt: new Date().toISOString(),
        }),
      );
      const error = await rejection(updateDistribution(ID, opts));
      expect(error).toMatchObject({ code: "UPDATE_FAILED", retryable: true });
      expect(error.message).toContain(`(process ${holder})`);
      expect(readInstallReceipt(ID).active).toBe("1.0.0");
      expect(JSON.parse(readFileSync(lock, "utf8")).instance).toBe(
        "live-holder-b",
      );
    });
  },
);
