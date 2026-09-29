// Update and rollback against a lifecycle lock left by a crashed holder whose
// process ID another live process now has, against a live holder, against a
// wall clock that jumps while a holder works, and against a lock taken over
// before the receipt is written.
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  age,
  appsDir,
  fakeRun,
  installed,
  launch,
  livePid,
  rejection,
  temporaries,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import { readInstallReceipt, uninstallDistribution } from "./install/index.js";
import { LIFECYCLE_LOCK_REUSE_MS } from "./install/lifecycle-lock.js";
import { rollbackDistribution, updateDistribution } from "./update/index.js";

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
      age(lock, LIFECYCLE_LOCK_REUSE_MS + 60_000);
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

    it("never lets an uninstall take an update's lock when the wall clock jumps forward during its launch check", async () => {
      const { opts } = await installed();
      let refusal: unknown;
      const result = await updateDistribution(ID, {
        ...opts,
        faults: (at) => {
          // The launch check just ran synchronously, so no heartbeat did.
          if (at !== "verified") return;
          const clock = vi
            .spyOn(Date, "now")
            .mockReturnValue(Date.now() + 60 * 60_000);
          try {
            uninstallDistribution(ID);
          } catch (error) {
            refusal = error;
          } finally {
            clock.mockRestore();
          }
        },
      });
      expect(refusal).toMatchObject({ code: "UPDATE_FAILED", retryable: true });
      expect((refusal as Error).message).toMatch(/Another update, rollback/);
      expect(result).toMatchObject({ status: "updated", to: "1.1.0" });
      expect(launch()).toBe("payload 1.1.0");
    });

    const losses: [string, (lock: string) => void][] = [
      [
        "another operation took the lock over",
        (lock) =>
          writeFileSync(
            lock,
            JSON.stringify({
              schema: "piship-lifecycle-lock/v1",
              pid: livePid(),
              instance: "took-over",
              acquiredAt: new Date().toISOString(),
            }),
          ),
      ],
      ["the lock was removed", (lock) => rmSync(lock)],
    ];

    it.each(losses)(
      "aborts an update whose lock was lost before the receipt (%s) and leaves the release unchanged",
      async (_name, lose) => {
        const { opts } = await installed();
        const lock = join(appsDir(), ".lifecycle.lock");
        const error = await rejection(
          updateDistribution(ID, {
            ...opts,
            faults: (at) => {
              if (at === "installed") lose(lock);
            },
          }),
        );
        expect(error).toMatchObject({ code: "UPDATE_FAILED", retryable: true });
        expect(error.message).toMatch(/taken over .*nothing was committed/);
        expect(readInstallReceipt(ID).active).toBe("1.0.0");
        expect(launch()).toBe("payload 1.0.0");
        expect(temporaries()).toEqual([]);
        // Whoever holds the lock now owns the installation: neither its lock
        // nor the release directory it may be activating is touched.
        if (existsSync(lock))
          expect(JSON.parse(readFileSync(lock, "utf8")).instance).toBe(
            "took-over",
          );
        expect(existsSync(join(appsDir(), "1.1.0"))).toBe(true);
        // Retryable: once the other operation is gone, the same update works.
        rmSync(lock, { force: true });
        await expect(updateDistribution(ID, opts)).resolves.toMatchObject({
          status: "updated",
          to: "1.1.0",
        });
        expect(launch()).toBe("payload 1.1.0");
      },
    );

    it.each(losses)(
      "aborts a rollback whose lock was lost before the receipt (%s) and leaves the release unchanged",
      async (_name, lose) => {
        const { opts } = await installed();
        await updateDistribution(ID, opts);
        const lock = join(appsDir(), ".lifecycle.lock");
        const error = await rejection(
          rollbackDistribution(ID, {
            runCheck: fakeRun,
            faults: (at) => {
              if (at === "verified") lose(lock);
            },
          }),
        );
        expect(error).toMatchObject({
          code: "ROLLBACK_FAILED",
          retryable: true,
        });
        expect(error.message).toMatch(/taken over .*nothing was committed/);
        expect(readInstallReceipt(ID).active).toBe("1.1.0");
        expect(launch()).toBe("payload 1.1.0");
        expect(temporaries()).toEqual([]);
        if (existsSync(lock))
          expect(JSON.parse(readFileSync(lock, "utf8")).instance).toBe(
            "took-over",
          );
        rmSync(lock, { force: true });
        await expect(
          rollbackDistribution(ID, { runCheck: fakeRun }),
        ).resolves.toMatchObject({ from: "1.1.0", to: "1.0.0" });
        expect(launch()).toBe("payload 1.0.0");
      },
    );
  },
);
