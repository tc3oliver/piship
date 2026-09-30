// The session's temp directory: private while it exists, marked with its
// owner, gone after a normal end, and reclaimed at the next activation when
// the session was killed. Every scenario runs against a private OS temp
// directory (TMPDIR), so the machine's real one is neither read nor changed.
import { spawn } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  TEMPORARY_OWNER_FILE,
  createTemporaryDirectory,
  readTemporaryOwner,
  type TemporaryOwner,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deadPid } from "../../../tests/helpers/processes.js";
import { activateSandbox } from "./activate.js";
import type { SandboxPolicy } from "./profile.js";
import { fakeBackend, fakeWrappingBackend } from "./testing/fake-backend.js";

const posix = process.platform !== "win32";
const TEMP_VARIABLES = ["TMPDIR", "TEMP", "TMP"] as const;

const policy: SandboxPolicy = {
  required: true,
  filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: { allow: ["PATH"] },
};

let root: string;
let workspace: string;
const saved: Record<string, string | undefined> = {};
const children: ReturnType<typeof spawn>[] = [];
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-session-tmp-")));
  workspace = join(root, "workspace");
  mkdirSync(workspace);
  for (const name of TEMP_VARIABLES) {
    saved[name] = process.env[name];
    process.env[name] = join(root, "os-temp");
  }
  mkdirSync(join(root, "os-temp"));
});
afterEach(() => {
  for (const child of children.splice(0)) child.kill("SIGKILL");
  for (const name of TEMP_VARIABLES)
    if (saved[name] === undefined) delete process.env[name];
    else process.env[name] = saved[name];
  rmSync(root, { recursive: true, force: true });
});

const osTemp = () => join(root, "os-temp");
const sessions = () =>
  readdirSync(osTemp()).filter((name) => name.startsWith("piship-sandbox-"));

const activate = () =>
  activateSandbox(policy, {
    workspace,
    homeDir: join(root, "home"),
    backend: fakeBackend().backend,
    env: { PATH: "/usr/bin" },
    settleMs: 50,
  });

const sandboxModule = pathToFileURL(
  fileURLToPath(new URL("../dist/index.js", import.meta.url)),
).href;
/**
 * A process that activates a sandbox session, writes tool output into its
 * temp directory, prints that directory, and waits to be killed.
 */
const session = `
  const { activateSandbox, customBackend } = await import(process.env.SANDBOX);
  const { writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const backend = customBackend({
    id: "acme-sandbox",
    available: async () => ({ available: true }),
    capabilities: () => ({
      isolation: "remote",
      planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
      network: ["deny", "allow"],
      localProcesses: false,
    }),
    prepare: async () => ({
      exec: async (request, io) => {
        io.onStdout(Buffer.from("piship-sandbox-ready unset\\n"));
        if (request.command.includes("piship-network"))
          io.onStdout(Buffer.from("piship-network-blocked\\n"));
        return { exitCode: 0 };
      },
      dispose: async () => {},
    }),
  });
  const sandbox = await activateSandbox(
    {
      required: true,
      filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
      network: { mode: "deny" },
      environment: { allow: ["PATH"] },
    },
    {
      workspace: process.env.WORKSPACE,
      homeDir: process.env.HOME_DIR,
      backend,
      env: { PATH: "/usr/bin" },
      settleMs: 50,
    },
  );
  writeFileSync(join(sandbox.profile.tmpDir, "tool-output.txt"), "private tool output");
  process.stdout.write(JSON.stringify(sandbox.profile.tmpDir) + "\\n");
  setInterval(() => {}, 1000);
`;

/** Start a session in its own process and wait until its directory has output. */
async function startSession(): Promise<{
  tmp: string;
  kill: () => Promise<void>;
}> {
  const child = spawn(
    process.execPath,
    ["--input-type=module", "-e", session],
    {
      env: {
        ...process.env,
        SANDBOX: sandboxModule,
        WORKSPACE: workspace,
        HOME_DIR: join(root, "home"),
      },
      stdio: ["ignore", "pipe", "inherit"],
    },
  );
  children.push(child);
  const tmp = await new Promise<string>((resolve, reject) => {
    let text = "";
    child.stdout.on("data", (chunk: Buffer) => {
      text += chunk.toString("utf8");
      if (text.includes("\n")) resolve(JSON.parse(text) as string);
    });
    child.on("error", reject);
    child.on("exit", () => reject(new Error("the session exited early")));
  });
  return {
    tmp,
    kill: async () => {
      const exited = new Promise((resolve) => child.on("exit", resolve));
      child.kill("SIGKILL");
      await exited;
    },
  };
}

describe("session temp directory", () => {
  it("is private, marked with its owner, and holds the sandbox's TMPDIR beside the marker", async () => {
    const sandbox = await activate();
    try {
      expect(sessions()).toHaveLength(1);
      const dir = join(osTemp(), sessions()[0] as string);
      const owner = readTemporaryOwner(dir)?.owner;
      expect(owner).toMatchObject({ kind: "sandbox", pid: process.pid });
      // The marker is outside the directory contained commands write in.
      expect(realpathSync(sandbox.profile.tmpDir)).toBe(
        join(realpathSync(dir), "tmp"),
      );
      expect(readdirSync(dir).sort()).toEqual([TEMPORARY_OWNER_FILE, "tmp"]);
      if (posix) {
        expect(lstatSync(dir).mode & 0o777).toBe(0o700);
        expect(lstatSync(join(dir, "tmp")).mode & 0o777).toBe(0o700);
        expect(lstatSync(join(dir, TEMPORARY_OWNER_FILE)).mode & 0o777).toBe(
          0o600,
        );
      }
    } finally {
      await sandbox.dispose();
    }
    expect(sessions()).toEqual([]);
  });

  it("is gone with its content after the session ends", async () => {
    const sandbox = await activate();
    const dir = join(osTemp(), sessions()[0] as string);
    writeFileSync(join(sandbox.profile.tmpDir, "tool-output.txt"), "output");
    await sandbox.dispose();
    expect(existsSync(dir)).toBe(false);
  });

  it("does not create a directory for a sandbox that is not active", async () => {
    const off = await activateSandbox(
      { ...policy, required: false },
      {
        workspace,
        homeDir: join(root, "home"),
        backend: fakeBackend().backend,
        env: { PATH: "/usr/bin" },
      },
    );
    expect(sessions()).toEqual([]);
    await off.dispose();
  });
});

describe("an abandoned session", () => {
  it("is removed with its tool output by the next activation", async () => {
    const abandoned = await startSession();
    const dir = dirname(abandoned.tmp);
    expect(readFileSync(join(abandoned.tmp, "tool-output.txt"), "utf8")).toBe(
      "private tool output",
    );
    await abandoned.kill();
    // SIGKILL ran no exit hook: the directory and its output are still here.
    expect(existsSync(join(abandoned.tmp, "tool-output.txt"))).toBe(true);
    const sandbox = await activate();
    try {
      expect(existsSync(dir)).toBe(false);
      expect(sessions()).toHaveLength(1);
    } finally {
      await sandbox.dispose();
    }
    expect(sessions()).toEqual([]);
  });

  it("does not grow across repeated killed sessions", async () => {
    const counts: number[] = [];
    for (let run = 0; run < 3; run += 1) {
      await (await startSession()).kill();
      const sandbox = await activate();
      counts.push(sessions().length);
      await sandbox.dispose();
    }
    // Only the activating session's own directory was there each time.
    expect(counts).toEqual([1, 1, 1]);
    expect(sessions()).toEqual([]);
  });

  it("leaves a live concurrent session and unrelated directories alone", async () => {
    const running = await startSession();
    const killed = await startSession();
    await killed.kill();
    const mine = join(osTemp(), "piship-sandbox-notes");
    const unmarked = join(osTemp(), "piship-sandbox-abc123");
    for (const path of [mine, unmarked]) {
      mkdirSync(path);
      writeFileSync(join(path, "keep.txt"), "user data");
    }
    const sandbox = await activate();
    try {
      expect(existsSync(dirname(killed.tmp))).toBe(false);
      expect(readFileSync(join(running.tmp, "tool-output.txt"), "utf8")).toBe(
        "private tool output",
      );
      for (const path of [mine, unmarked])
        expect(readFileSync(join(path, "keep.txt"), "utf8")).toBe("user data");
    } finally {
      await sandbox.dispose();
    }
    await running.kill();
  });
});

describe.runIf(posix)("probe directories", () => {
  it("removes a killed probe's directory, and its own when the activation ends", async () => {
    const tmpDir = join(root, "session-tmp");
    mkdirSync(tmpDir);
    // What a probe killed mid-check left: a marked directory of a dead owner.
    const host = createTemporaryDirectory(tmpDir, "staging");
    const { owner } = readTemporaryOwner(host.path) as {
      owner: TemporaryOwner;
    };
    host.remove();
    const stale = join(tmpDir, ".piship-probe-abc123");
    mkdirSync(join(stale, "allowed"), { recursive: true });
    writeFileSync(join(stale, "allowed", "write-probe"), "probe");
    writeFileSync(
      join(stale, TEMPORARY_OWNER_FILE),
      JSON.stringify({
        ...owner,
        kind: "probe",
        name: ".piship-probe-abc123",
        pid: deadPid(),
        instance: "0123456789abcdef",
      }),
    );
    const unrelated = join(tmpDir, ".piship-probe-notes");
    mkdirSync(unrelated);
    // An uncontained "sandbox": the probe runs, finds nothing enforced, and
    // the required activation fails, after the probe cleaned up.
    await expect(
      activateSandbox(policy, {
        workspace,
        homeDir: join(root, "home"),
        tmpDir,
        backend: fakeWrappingBackend(
          {
            wrap: () => {
              throw new Error("never wrapped natively");
            },
          },
          false,
        ),
        env: { PATH: "/usr/bin" },
        settleMs: 50,
      }),
    ).rejects.toThrow(/sandbox/i);
    expect(existsSync(stale)).toBe(false);
    expect(readdirSync(tmpDir).sort()).toEqual([".piship-probe-notes"]);
  });
});
