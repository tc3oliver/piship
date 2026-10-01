// The installed launcher's registration gate and launching marker: what they
// record about the launcher, and how a launcher judges a gate someone else
// left (a process ID now another process's, another host's, an earlier
// PiShip's).
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync,
  watch,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { processHostToken } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  age,
  appsDir,
  deadPid,
  installed,
  livePid,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import { readInstallReceipt, uninstallDistribution } from "./install/index.js";
import { LIFECYCLE_LOCK_REUSE_MS } from "./install/lifecycle-lock.js";
import { processIdentity, recordedProcessGone } from "./process-identity.js";

useLifecycleHomes();

/**
 * The end of the gate's path: the launcher names it by its real path, which
 * on macOS (/private/var) and Windows (a long user name for a short one)
 * differs from the configured one.
 */
const GATE_TAIL = join("receipts", `.${ID}.launch.lock`);

function gatePath(): string {
  return join(
    process.env.PISHIP_INSTALL_HOME as string,
    "receipts",
    `.${ID}.launch.lock`,
  );
}

function gate(fields: Record<string, unknown>): void {
  writeFileSync(
    gatePath(),
    `${JSON.stringify({
      schema: "piship-lifecycle-lock/v1",
      instance: "left-behind",
      identity: null,
      host: processHostToken(),
      started: null,
      ...fields,
    })}\n`,
  );
}

function runLauncher() {
  return spawnSync(process.execPath, [join(appsDir(), "launch.mjs")], {
    encoding: "utf8",
  });
}

function refusal(action: () => unknown): Error {
  try {
    action();
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected a refusal");
}

const waitForFile = (path: string): Promise<void> =>
  new Promise((resolvePromise) => {
    const watcher = watch(dirname(path), () => {
      if (existsSync(path)) {
        watcher.close();
        resolvePromise();
      }
    });
    if (existsSync(path)) {
      watcher.close();
      resolvePromise();
    }
  });

describe.runIf(HOST_EVIDENCED)("the launch gate", () => {
  it("records the launcher's process as a runtime lease does, in the gate and in its launching marker", async () => {
    await installed();
    const payload = readInstallReceipt(ID).payload;
    const ready = join(dirname(payload), "ready");
    const release = join(dirname(payload), "release");
    // A core that holds the launcher right after it took the gate and wrote
    // its launching marker.
    writeFileSync(
      join(payload, "node_modules", "@piship", "core", "dist", "index.js"),
      `import { writeFileSync, watch, existsSync } from "node:fs";
import { dirname } from "node:path";
writeFileSync(${JSON.stringify(ready)}, "ready");
await new Promise((resolve) => {
  const watcher = watch(dirname(${JSON.stringify(release)}), () => {
    if (existsSync(${JSON.stringify(release)})) { watcher.close(); resolve(); }
  });
  if (existsSync(${JSON.stringify(release)})) { watcher.close(); resolve(); }
});
export { holdRuntimeLease } from ${JSON.stringify(pathToFileURL(resolve("packages/core/dist/index.js")).href)};
`,
    );
    const child = spawn(
      process.execPath,
      [readInstallReceipt(ID).launcher as string],
      { stdio: "ignore" },
    );
    try {
      await waitForFile(ready);
      const launching = join(appsDir(), ".runtime-leases", ".launching");
      const records = [
        JSON.parse(readFileSync(gatePath(), "utf8")),
        ...readdirSync(launching).map((name) =>
          JSON.parse(readFileSync(join(launching, name), "utf8")),
        ),
      ];
      expect(records).toHaveLength(2);
      for (const record of records) {
        expect(record).toMatchObject({
          pid: child.pid,
          host: processHostToken(),
          started: expect.any(Number),
        });
        // Linux records the start identity itself, exactly as core reads it.
        if (process.platform === "linux")
          expect(record.identity).toBe(processIdentity(child.pid as number));
        else expect(record.identity).toBeNull();
        // Core judges the launcher's own record as its running process.
        expect(recordedProcessGone(record)).toBe(false);
      }
      writeFileSync(release, "continue");
      const code = await new Promise<number | null>((resolvePromise) =>
        child.once("exit", resolvePromise),
      );
      expect(code).toBe(0);
      expect(existsSync(gatePath())).toBe(false);
    } finally {
      child.kill();
    }
  }, 60_000);

  it("reclaims at once a gate whose process ID now belongs to a process with another start identity", async () => {
    await installed();
    gate({ pid: livePid(), identity: "1" });
    const launched = runLauncher();
    expect(launched.status, launched.stderr).toBe(0);
    expect(launched.stdout).toContain("payload 1.0.0");
    expect(existsSync(gatePath())).toBe(false);
  }, 60_000);

  // Linux records the start identity; elsewhere the launcher records its
  // start time, which another process with the same ID does not share.
  it.runIf(process.platform !== "linux")(
    "reclaims at once a gate whose recorded start time is not the start of the process with its ID",
    async () => {
      await installed();
      gate({ pid: livePid(), started: Date.now() - 3_600_000 });
      const launched = runLauncher();
      expect(launched.status, launched.stderr).toBe(0);
      expect(existsSync(gatePath())).toBe(false);
    },
    60_000,
  );

  it("waits for a gate whose holder is running, and reclaims one of an earlier PiShip whose process is gone", async () => {
    await installed();
    const holder = livePid();
    gate({ pid: holder, identity: processIdentity(holder) ?? null });
    expect(runLauncher().status).toBe(1);
    expect(existsSync(gatePath())).toBe(true);
    // Records of an earlier PiShip: a process ID and an instance, or a
    // bare process ID.
    writeFileSync(
      gatePath(),
      JSON.stringify({
        schema: "piship-lifecycle-lock/v1",
        pid: deadPid(),
        instance: "earlier",
      }),
    );
    expect(runLauncher().status).toBe(0);
    writeFileSync(gatePath(), String(deadPid()));
    expect(runLauncher().status).toBe(0);
    expect(existsSync(gatePath())).toBe(false);
  }, 60_000);

  it("never reclaims another host's gate by this host's processes before its lease runs out", async () => {
    await installed();
    const gone = deadPid();
    gate({ pid: gone, identity: "1", host: "0123456789ab" });
    const refused = runLauncher();
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain(`process ${gone} on another host`);
    expect(existsSync(gatePath())).toBe(true);
    age(gatePath(), LIFECYCLE_LOCK_REUSE_MS + 60_000);
    const launched = runLauncher();
    expect(launched.status, launched.stderr).toBe(0);
    expect(existsSync(gatePath())).toBe(false);
  }, 60_000);

  it("names the gate and its holder when it stops waiting, in the launcher and in core", async () => {
    await installed();
    const holder = livePid();
    gate({ pid: holder, identity: processIdentity(holder) ?? null });
    const launched = runLauncher();
    expect(launched.status).toBe(1);
    expect(launched.stderr).toContain(GATE_TAIL);
    expect(launched.stderr).toContain(`held by process ${holder}.`);
    const error = refusal(() => uninstallDistribution(ID));
    expect(error.message).toContain(gatePath());
    expect(error.message).toContain(`held by process ${holder}`);
  }, 60_000);

  it("reports an error other than a held gate as it is, never as contention", async () => {
    await installed();
    // The receipts directory replaced by a file: the gate cannot be created
    // (ENOTDIR, or ENOENT on Windows), and retrying cannot help.
    const receipts = dirname(gatePath());
    renameSync(receipts, `${receipts}.moved`);
    writeFileSync(receipts, "not a directory");
    const launched = runLauncher();
    expect(launched.status).toBe(1);
    expect(launched.stderr).toContain(
      `Could not register a launch of ${ID}: E`,
    );
    expect(launched.stderr).toContain(`.${ID}.launch.lock`);
    expect(launched.stderr).not.toMatch(/registering|retry/i);
  }, 60_000);

  // Permissions do not stop file creation on Windows, and root ignores them.
  it.runIf(process.platform !== "win32" && process.getuid?.() !== 0)(
    "reports a read-only receipts directory as the permission error it is",
    async () => {
      await installed();
      const receipts = dirname(gatePath());
      chmodSync(receipts, 0o555);
      try {
        const launched = runLauncher();
        expect(launched.status).toBe(1);
        expect(launched.stderr).toContain("EACCES");
        expect(launched.stderr).toContain(GATE_TAIL);
        expect(launched.stderr).not.toMatch(/registering|retry/i);
        const error = refusal(() => uninstallDistribution(ID));
        expect(error.message).toContain("EACCES");
        expect(error.message).not.toMatch(/registering|retry/i);
      } finally {
        chmodSync(receipts, 0o755);
      }
    },
    60_000,
  );
});
