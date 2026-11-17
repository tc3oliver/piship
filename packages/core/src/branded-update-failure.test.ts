// doctor names the last failed update or check, which the receipt does not
// record, until a later check succeeds.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  installed,
  rejection,
  stateDir,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import type { BrandedContext } from "./branded/context.js";
import { lifecycleDoctor } from "./branded/doctor.js";
import { runUpdate } from "./branded/lifecycle.js";
import { verifyPayload } from "./index.js";
import { readInstallReceipt } from "./install/index.js";

useLifecycleHomes();

const scratch: string[] = [];
afterEach(() => {
  for (const dir of scratch.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

function context(): BrandedContext {
  const receipt = readInstallReceipt(ID);
  return {
    metadata: verifyPayload(receipt.payload) as BrandedContext["metadata"],
    distributionDir: receipt.payload,
    stateDir: stateDir(),
    mode: "personal",
    out: () => {},
    err: () => {},
  };
}

function lastCheck(): string[] {
  const lines: string[] = [];
  lifecycleDoctor(
    context(),
    "Update",
    (label, value) => lines.push(`ok ${label} ${value}`),
    (label, value) => lines.push(`! ${label} ${value}`),
  );
  return lines.filter((line) => line.includes(" last check "));
}

describe.runIf(HOST_EVIDENCED)("doctor last check", () => {
  it("shows a failed attempt next to the last successful check until one succeeds", async () => {
    await installed();
    await runUpdate(context(), ["--check"]);
    expect(lastCheck()).toEqual([
      expect.stringMatching(/^ok last check available 1\.1\.0 \(/),
    ]);
    const empty = mkdtempSync(join(tmpdir(), "piship-empty-source-"));
    scratch.push(empty);
    const error = await rejection(runUpdate(context(), ["--from", empty]));
    expect(error.code).toBe("UPDATE_FAILED");
    const failed = lastCheck();
    expect(failed).toHaveLength(2);
    expect(failed[0]).toMatch(/^ok last check available 1\.1\.0 \(/);
    expect(failed[1]).toMatch(
      /^! last check update failed at \S+: Update source has no stable\.json$/,
    );
    // The receipt is unchanged by the failure; a later check clears the warning.
    await new Promise((resolve) => setTimeout(resolve, 5));
    await runUpdate(context(), ["--check"]);
    expect(lastCheck()).toEqual([
      expect.stringMatching(/^ok last check available 1\.1\.0 \(/),
    ]);
  });

  it("does not record a failed one-off --check --from", async () => {
    await installed();
    const empty = mkdtempSync(join(tmpdir(), "piship-empty-source-"));
    scratch.push(empty);
    const error = await rejection(
      runUpdate(context(), ["--check", "--from", empty]),
    );
    expect(error.code).toBe("UPDATE_FAILED");
    expect(lastCheck()).toEqual([]);
  });
});
