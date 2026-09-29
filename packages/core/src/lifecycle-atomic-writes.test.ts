// The receipt commit of update and rollback under injected I/O faults: a
// short write is completed, and every failure before the rename keeps the
// previous receipt byte for byte, the previous release active, and no
// temporary behind. node:fs is wrapped so faults can be armed per path.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
  clearFaults,
  type FsFault,
  fired,
  injectFault,
} from "../../../tests/helpers/fs-faults.js";
import {
  HOST_EVIDENCED,
  ID,
  MARKER,
  RECEIPT,
  deadPid,
  fakeRun,
  installed,
  launch,
  receiptFile,
  rejection,
  stateDir,
  temporaries,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import { readInstallReceipt } from "./install/index.js";
import { readStateMarker } from "./migration.js";
import { rollbackDistribution, updateDistribution } from "./update/index.js";

vi.mock("node:fs", async (importOriginal) =>
  (await import("../../../tests/helpers/fs-faults.js")).faultyFs(
    await importOriginal(),
  ),
);

useLifecycleHomes();

const failures: [string, FsFault][] = [
  ["a write that makes no progress", { op: "write", stall: true }],
  ["ENOSPC while writing", { op: "write", code: "ENOSPC" }],
  ["a failed fsync", { op: "fsync", code: "EIO" }],
  ["a failed rename", { op: "rename", code: "EACCES" }],
];

describe.runIf(HOST_EVIDENCED)(
  "atomic lifecycle writes under I/O faults",
  () => {
    it("completes a receipt commit and a marker write through short writes", async () => {
      const { opts } = await installed();
      injectFault(RECEIPT, { op: "write", short: true }, 4);
      injectFault(MARKER, { op: "write", short: true }, 4);
      const result = await updateDistribution(ID, opts);
      expect(result).toMatchObject({
        status: "updated",
        to: "1.1.0",
        notices: [],
      });
      expect(fired.some((item) => RECEIPT.test(item))).toBe(true);
      expect(fired.some((item) => MARKER.test(item))).toBe(true);
      expect(readInstallReceipt(ID).active).toBe("1.1.0");
      expect(readStateMarker(stateDir())?.version).toBe("1.1.0");
      expect(launch()).toBe("payload 1.1.0");
      expect(temporaries()).toEqual([]);
    });

    it.each(failures)(
      "keeps the previous receipt and release after %s at the update commit",
      async (_name, fault) => {
        const { opts } = await installed();
        const before = readFileSync(receiptFile());
        injectFault(RECEIPT, fault);
        await rejection(updateDistribution(ID, opts));
        expect(fired.length).toBeGreaterThan(0);
        expect(readFileSync(receiptFile())).toEqual(before);
        expect(readInstallReceipt(ID).active).toBe("1.0.0");
        expect(launch()).toBe("payload 1.0.0");
        expect(temporaries()).toEqual([]);
        clearFaults();
        await expect(updateDistribution(ID, opts)).resolves.toMatchObject({
          status: "updated",
          to: "1.1.0",
        });
        expect(launch()).toBe("payload 1.1.0");
      },
    );

    it.each(failures)(
      "keeps the previous receipt and release after %s at the rollback commit",
      async (_name, fault) => {
        const { opts } = await installed();
        await updateDistribution(ID, opts);
        const before = readFileSync(receiptFile());
        injectFault(RECEIPT, fault);
        await rejection(rollbackDistribution(ID, { runCheck: fakeRun }));
        expect(readFileSync(receiptFile())).toEqual(before);
        expect(launch()).toBe("payload 1.1.0");
        expect(temporaries()).toEqual([]);
        clearFaults();
        await expect(
          rollbackDistribution(ID, { runCheck: fakeRun }),
        ).resolves.toMatchObject({ to: "1.0.0" });
        expect(launch()).toBe("payload 1.0.0");
      },
    );

    it("ignores a receipt temporary a killed writer left, and reclaims it", async () => {
      const { opts } = await installed();
      const before = readFileSync(receiptFile(), "utf8");
      const leftover = `${receiptFile()}.p${deadPid()}-0123456789ab.tmp`;
      // A killed commit: the new receipt was written but never renamed.
      writeFileSync(leftover, before.replace(/1\.0\.0/g, "1.1.0"));
      expect(readInstallReceipt(ID).active).toBe("1.0.0");
      expect(launch()).toBe("payload 1.0.0");
      await updateDistribution(ID, opts);
      expect(existsSync(leftover)).toBe(false);
      expect(temporaries()).toEqual([]);
    });
  },
);
