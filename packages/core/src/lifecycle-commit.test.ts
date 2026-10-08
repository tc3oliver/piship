// The receipt is the commit point of update and rollback: a state marker
// that cannot be written after it (a full, read-only, or failing state
// filesystem) never turns an activation into a reported failure, and the
// next lifecycle operation repairs the marker. node:fs is wrapped so faults
// can be armed per path.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditEvent } from "@piship/contracts";
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
  fakeRun,
  installed,
  launch,
  markerFile,
  rejection,
  stateDir,
  temporaries,
  useLifecycleHomes,
  write,
} from "../../../tests/helpers/lifecycle-faults.js";
import type { BrandedContext } from "./branded/context.js";
import { runRollback, runUpdate } from "./branded/lifecycle.js";
import { resolveLock, verifyPayload } from "./index.js";
import { readInstallReceipt } from "./install/index.js";
import { readStateMarker } from "./migration.js";
import { rollbackDistribution, updateDistribution } from "./update/index.js";

vi.mock("node:fs", async (importOriginal) =>
  (await import("../../../tests/helpers/fs-faults.js")).faultyFs(
    await importOriginal(),
  ),
);

useLifecycleHomes();

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);

describe.runIf(HOST_EVIDENCED)(
  "a state marker that cannot be written after the commit",
  () => {
    const faults: [string, FsFault][] = [
      ["ENOSPC", { op: "write", code: "ENOSPC" }],
      ["a read-only state directory (EACCES)", { op: "open", code: "EACCES" }],
      ["a generic write failure (EIO)", { op: "rename", code: "EIO" }],
    ];

    it.each(faults)(
      "reports the update as activated after %s, and the next operation repairs the marker",
      async (_name, fault) => {
        const { opts } = await installed();
        // The marker 1.0.0 wrote when it last activated.
        write(
          markerFile(),
          `${JSON.stringify({ schema: "piship-state/v1", distribution: ID, version: "1.0.0", pi: "1.1.0", piship: "0.1.0" })}\n`,
        );
        injectFault(MARKER, fault);
        const result = await updateDistribution(ID, opts);
        expect(fired.length).toBeGreaterThan(0);
        expect(result).toMatchObject({ status: "updated", to: "1.1.0" });
        expect(result.notices).toEqual([
          expect.stringMatching(
            /^1\.1\.0 is active, but its state marker could not be written \(.+\); the next update or rollback repairs it$/,
          ),
        ]);
        expect(readInstallReceipt(ID).active).toBe(result.to);
        expect(launch()).toBe("payload 1.1.0");
        expect(readStateMarker(stateDir())?.version).toBe("1.0.0");
        expect(temporaries()).toEqual([]);
        clearFaults();
        // Recovery at the start of the next lifecycle operation.
        await expect(updateDistribution(ID, opts)).resolves.toMatchObject({
          status: "up-to-date",
          notices: [],
        });
        expect(readStateMarker(stateDir())?.version).toBe("1.1.0");
      },
    );

    it.each(faults)(
      "reports the rollback as activated after %s, and the next operation repairs the marker",
      async (_name, fault) => {
        const { opts } = await installed();
        await updateDistribution(ID, opts);
        const before = readFileSync(markerFile());
        injectFault(MARKER, fault);
        const result = await rollbackDistribution(ID, { runCheck: fakeRun });
        expect(result).toMatchObject({ from: "1.1.0", to: "1.0.0" });
        expect(result.notices).toEqual([
          expect.stringMatching(/^1\.0\.0 is active, but its state marker/),
        ]);
        expect(readInstallReceipt(ID).active).toBe(result.to);
        expect(launch()).toBe("payload 1.0.0");
        // The previous marker is kept whole.
        expect(readFileSync(markerFile())).toEqual(before);
        expect(temporaries()).toEqual([]);
        clearFaults();
        // The next operation repairs the marker before anything else, even
        // one that then refuses (the retained 1.1.0 is newer than 1.0.0).
        const next = await rejection(
          rollbackDistribution(ID, { runCheck: fakeRun }),
        );
        expect(next.message).toMatch(/use update instead/);
        expect(readStateMarker(stateDir())?.version).toBe("1.0.0");
        expect(readInstallReceipt(ID).active).toBe("1.0.0");
      },
    );

    it.each<[string, FsFault]>([
      ["a write that makes no progress", { op: "write", stall: true }],
      ["a failed fsync", { op: "fsync", code: "EIO" }],
    ])(
      "keeps the previous state marker whole after %s",
      async (_name, fault) => {
        const { opts } = await installed();
        await updateDistribution(ID, opts);
        const before = readFileSync(markerFile());
        injectFault(MARKER, fault);
        await rollbackDistribution(ID, { runCheck: fakeRun });
        expect(readFileSync(markerFile())).toEqual(before);
        expect(temporaries()).toEqual([]);
        clearFaults();
        await updateDistribution(ID, opts);
        expect(readStateMarker(stateDir())?.version).toBe("1.1.0");
      },
    );

    it("keeps the recovery of a process killed right after the commit", async () => {
      const { opts } = await installed();
      await rejection(
        updateDistribution(ID, {
          ...opts,
          faults: (at) => {
            if (at === "committed") throw new Error("killed");
          },
        }),
      );
      expect(readInstallReceipt(ID).active).toBe("1.1.0");
      expect(readStateMarker(stateDir())).toBeNull();
      await updateDistribution(ID, opts);
      expect(readStateMarker(stateDir())?.version).toBe("1.1.0");
    });

    /** The branded command of the installed active release, governed with a local audit file. */
    function brandedContext() {
      const receipt = readInstallReceipt(ID);
      const demo = resolveLock(DEMO);
      const governance = demo.governance as NonNullable<typeof demo.governance>;
      const out: string[] = [];
      const err: string[] = [];
      const ctx: BrandedContext = {
        metadata: {
          ...verifyPayload(receipt.payload),
          governance: {
            ...governance,
            manifest: {
              ...governance.manifest,
              audit: {
                ...governance.manifest.audit,
                enabled: true,
                sinks: [{ id: "local", type: "file", required: false }],
              },
            },
          },
        } as BrandedContext["metadata"],
        distributionDir: receipt.payload,
        stateDir: stateDir(),
        mode: "personal",
        out: (message) => out.push(message),
        err: (message) => err.push(message),
      };
      return { ctx, out, err };
    }
    function lifecycleMetrics(): Record<string, number> {
      return JSON.parse(
        readFileSync(join(stateDir(), "logs", "metrics.json"), "utf8"),
      ).lifecycle;
    }
    function auditEvents(): AuditEvent[] {
      return readFileSync(join(stateDir(), "logs", "audit.jsonl"), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as AuditEvent);
    }

    it("records a committed update and rollback as activated in audit and metrics", async () => {
      await installed();
      const update = brandedContext();
      injectFault(MARKER, { op: "write", code: "ENOSPC" });
      await runUpdate(update.ctx, []);
      expect(update.out.at(-1)).toMatch(/^Updated AcmePi 1\.0\.0 -> 1\.1\.0 /);
      expect(update.err).toEqual([
        expect.stringMatching(
          /^Notice: 1\.1\.0 is active, but its state marker/,
        ),
      ]);
      expect(launch()).toBe("payload 1.1.0");
      const rollback = brandedContext();
      await runRollback(rollback.ctx);
      expect(rollback.out.at(-1)).toMatch(
        /^Rolled back AcmePi 1\.1\.0 -> 1\.0\.0\./,
      );
      expect(launch()).toBe("payload 1.0.0");
      expect(lifecycleMetrics()).toEqual({ "update:ok": 1, "rollback:ok": 1 });
      expect(
        auditEvents().map((event) => [event.event, event.decision]),
      ).toEqual([
        ["runtime.update", "allowed"],
        ["runtime.rollback", "allowed"],
      ]);
    });
  },
);
