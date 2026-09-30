import { existsSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { activateSandbox } from "./activate.js";
import type { SandboxAdapter } from "./adapter.js";
import type { SandboxExecIO, SandboxExecRequest } from "./backend.js";
import { NativeBackend } from "./native.js";
import type { SandboxPolicy, SandboxProfile } from "./profile.js";
import { selectAdapter } from "./select.js";

const posix = process.platform !== "win32";
const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));

// Runs the command as it is: these tests are about the lifetime of the
// process, not what the OS sandbox denies it.
const identity: SandboxAdapter = {
  id: "macos-seatbelt",
  available: async () => ({ available: true }),
  wrap: (_profile, command) => ({ ...command }),
};

let root: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-native-")));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const profile = (): SandboxProfile => ({
  workspace: root,
  homeDir: root,
  tmpDir: root,
  readDeny: [],
  writeAllow: [root],
  readOnly: [],
  writeProtect: { files: [], directories: [] },
  network: "allow",
  environmentAllow: [],
  warnings: [],
});

const io = (signal: AbortSignal): SandboxExecIO => ({
  signal,
  onStdout: () => {},
  onStderr: () => {},
});

const request = (command: string): SandboxExecRequest => ({
  command,
  cwd: root,
  workspacePath: ".",
  env: { PATH: process.env.PATH ?? "/usr/bin:/bin", DIR: root },
});

/** Ignores SIGTERM, so only the kill after the grace period stops it. */
const STUBBORN =
  'trap "" TERM; while :; do mkdir -p "$DIR/late" && echo x >> "$DIR/late/mark"; sleep 0.05; done';

async function untilExists(path: string, ms = 3000): Promise<void> {
  for (let waited = 0; waited < ms && !existsSync(path); waited += 25)
    await sleep(25);
  expect(existsSync(path)).toBe(true);
}

describe.skipIf(!posix)("the native backend's dispose", () => {
  it("returns only once a command that ignores SIGTERM has been killed", async () => {
    const instance = await new NativeBackend(
      identity,
      process.platform,
    ).prepare({ profile: profile() });
    const running = instance.exec(
      request(STUBBORN),
      io(new AbortController().signal),
    );
    await untilExists(join(root, "late", "mark"));
    const started = Date.now();
    await instance.dispose();
    // The command was stopped after its grace period, and is gone now.
    expect(Date.now() - started).toBeGreaterThanOrEqual(700);
    expect(await running).toMatchObject({ signal: "SIGKILL" });
    // Whatever removes the directory next cannot be undone by the command.
    rmSync(join(root, "late"), { recursive: true, force: true });
    await sleep(400);
    expect(existsSync(join(root, "late"))).toBe(false);
  });

  it("stops a command started in the same tick, and refuses one afterwards", async () => {
    const instance = await new NativeBackend(
      identity,
      process.platform,
    ).prepare({ profile: profile() });
    let ended = false;
    const running = instance
      .exec(request("sleep 30"), io(new AbortController().signal))
      .finally(() => {
        ended = true;
      });
    await instance.dispose();
    // A dispose that does not wait for a command started in the same tick
    // (one that returns after aborting) comes back while it is still dying.
    expect(ended).toBe(true);
    expect(await running).toMatchObject({ signal: "SIGTERM" });
    await expect(
      instance.exec(request("true"), io(new AbortController().signal)),
    ).rejects.toThrow("disposed");
    // A second dispose has nothing left to wait for.
    await instance.dispose();
  });

  it("returns at once when nothing is running", async () => {
    const instance = await new NativeBackend(
      identity,
      process.platform,
    ).prepare({ profile: profile() });
    const result = await instance.exec(
      request("exit 3"),
      io(new AbortController().signal),
    );
    expect(result.exitCode).toBe(3);
    const started = Date.now();
    await instance.dispose();
    expect(Date.now() - started).toBeLessThan(500);
  });

  it("still stops a running command through the caller's signal", async () => {
    const instance = await new NativeBackend(
      identity,
      process.platform,
    ).prepare({ profile: profile() });
    const controller = new AbortController();
    const running = instance.exec(request("sleep 30"), io(controller.signal));
    await sleep(100);
    controller.abort();
    expect(await running).toMatchObject({ signal: "SIGTERM" });
    await instance.dispose();
  });
});

const native = selectAdapter();
const nativeReady = (await native.available()).available;
const requireSandbox = process.env.PISHIP_REQUIRE_SANDBOX === "1";

describe.skipIf(!posix || (!nativeReady && !requireSandbox))(
  "ending a session that has a command in its grace period",
  () => {
    it("leaves the session temp directory removed, not recreated by the command", async () => {
      const policy: SandboxPolicy = {
        required: true,
        filesystem: {
          read: { deny: [] },
          write: { allow: ["workspace", "tmp"] },
        },
        network: { mode: "deny" },
        environment: { allow: ["PATH"] },
      };
      const sandbox = await activateSandbox(policy, {
        workspace: root,
        homeDir: join(root, "home"),
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
      });
      const tmp = sandbox.profile.tmpDir;
      // The command recreates the session temp directory whenever it is gone.
      const running = sandbox
        .exec(
          `trap "" TERM; while :; do mkdir -p "$TMPDIR/late" && echo x >> "$TMPDIR/late/mark"; sleep 0.05; done`,
          root,
          { onData: () => {} },
        )
        .catch(() => undefined);
      await untilExists(join(tmp, "late", "mark"), 5000);
      await sandbox.dispose();
      await running;
      await sleep(400);
      expect(existsSync(tmp)).toBe(false);
    });
  },
);
