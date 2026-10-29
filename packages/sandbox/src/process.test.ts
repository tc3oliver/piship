import { execFileSync, spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { activateSandbox } from "./activate.js";
import { parsePs, spawnManaged, trackDescendants } from "./process.js";

const node = process.execPath;
const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));
const PROCESS_TIMEOUT_TEST_MS = process.platform === "win32" ? 20_000 : 15_000;

// A child that starts a heartbeat-writing grandchild in its own process group.
const TREE = `
const { spawn } = require("node:child_process");
const [heartbeat, token] = process.argv.slice(1);
spawn(process.execPath, ["-e", "setInterval(() => require('node:fs').appendFileSync(process.argv[1], '.'), 50)", heartbeat, token], { stdio: "ignore" });
process.stdout.write("started\\n");
setInterval(() => {}, 1000);
`;

function running(token: string): boolean {
  if (process.platform === "linux") {
    for (const entry of readdirSync("/proc")) {
      if (!/^\d+$/.test(entry)) continue;
      try {
        if (readFileSync(`/proc/${entry}/cmdline`, "utf8").includes(token))
          return true;
      } catch {
        // exited while scanning
      }
    }
    return false;
  }
  if (process.platform === "darwin")
    return execFileSync("ps", ["-Ao", "command"], {
      encoding: "utf8",
    }).includes(token);
  return false;
}

async function heartbeatStopped(file: string): Promise<boolean> {
  await sleep(300);
  const size = (() => {
    try {
      return statSync(file).size;
    } catch {
      return 0;
    }
  })();
  await sleep(400);
  let after = 0;
  try {
    after = statSync(file).size;
  } catch {
    after = 0;
  }
  return after === size;
}

describe("spawnManaged", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "piship-process-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it(
    "kills the whole process tree on timeout",
    async () => {
      const heartbeat = join(dir, "hb");
      const token = `piship-tree-${Date.now()}`;
      let output = "";
      const child = spawnManaged({
        file: node,
        args: ["-e", TREE, heartbeat, token],
        cwd: dir,
        env: { PATH: process.env.PATH ?? "" },
        // The Windows helper and child can take over 5 s to start on a busy
        // runner. Keep the readiness assertion and the actual timeout/tree
        // reclaim checks; allow a separate startup budget on Windows.
        timeoutMs: process.platform === "win32" ? 10_000 : 5000,
        graceMs: 300,
        onStdout: (chunk) => {
          output += chunk.toString();
        },
      });
      const exit = await child.exited;
      expect(output).toContain("started");
      expect(exit.timedOut).toBe(true);
      expect(exit.cancelled).toBe(false);
      expect(await heartbeatStopped(heartbeat)).toBe(true);
      expect(running(token)).toBe(false);
    },
    PROCESS_TIMEOUT_TEST_MS,
  );

  it("cancels through an AbortSignal", async () => {
    const heartbeat = join(dir, "hb");
    const token = `piship-abort-${Date.now()}`;
    const controller = new AbortController();
    const child = spawnManaged({
      file: node,
      args: ["-e", TREE, heartbeat, token],
      cwd: dir,
      env: { PATH: process.env.PATH ?? "" },
      signal: controller.signal,
      graceMs: 300,
    });
    setTimeout(() => controller.abort(), 500);
    const exit = await child.exited;
    expect(exit.cancelled).toBe(true);
    expect(await heartbeatStopped(heartbeat)).toBe(true);
    expect(running(token)).toBe(false);
  });

  it("does not start when the signal is already aborted", async () => {
    const child = spawnManaged({
      file: node,
      args: ["-e", ""],
      cwd: dir,
      env: {},
      signal: AbortSignal.abort(),
    });
    expect(child.pid).toBeUndefined();
    expect((await child.exited).cancelled).toBe(true);
  });

  it("kills leftover group members when the leader exits", async () => {
    const heartbeat = join(dir, "hb");
    const token = `piship-orphan-${Date.now()}`;
    const leader = TREE.replace(
      "setInterval(() => {}, 1000);",
      "setTimeout(() => process.exit(0), 300);",
    );
    const exit = await spawnManaged({
      file: node,
      args: ["-e", leader, heartbeat, token],
      cwd: dir,
      env: { PATH: process.env.PATH ?? "" },
    }).exited;
    expect(exit.code).toBe(0);
    expect(await heartbeatStopped(heartbeat)).toBe(true);
    expect(running(token)).toBe(false);
  });

  it.skipIf(process.platform !== "win32")(
    "returns the governed child's exit code after draining its output",
    async () => {
      let stdout = "";
      let stderr = "";
      const result = await spawnManaged({
        file: node,
        args: [
          "-e",
          "process.stdout.write('out'); process.stderr.write('err'); process.exit(37)",
        ],
        cwd: dir,
        env: { PATH: process.env.PATH ?? "" },
        onStdout: (chunk) => {
          stdout += chunk.toString();
        },
        onStderr: (chunk) => {
          stderr += chunk.toString();
        },
      }).exited;
      expect(result).toMatchObject({
        code: 37,
        timedOut: false,
        cancelled: false,
      });
      expect(stdout).toBe("out");
      expect(stderr).toBe("err");
    },
  );

  it.skipIf(process.platform !== "win32")(
    "kills a live governed tree when PiShip exits",
    async () => {
      const heartbeat = join(dir, "shutdown-hb");
      const token = `piship-shutdown-${Date.now()}`;
      const modulePath = fileURLToPath(
        new URL("../dist/index.js", import.meta.url),
      );
      const source = `
      const { spawnManaged } = await import(process.argv[1]);
      const child = spawnManaged({ file: process.execPath, args: ["-e", ${JSON.stringify(TREE)}, process.argv[2], process.argv[3]], cwd: process.cwd(), env: { PATH: process.env.PATH ?? "" } });
      child.stdout.on("data", () => process.exit(0));
    `;
      execFileSync(
        node,
        [
          "--input-type=module",
          "-e",
          source,
          pathToFileURL(modulePath).href,
          heartbeat,
          token,
        ],
        {
          cwd: dir,
          timeout: 20_000,
        },
      );
      expect(await heartbeatStopped(heartbeat)).toBe(true);
    },
  );

  it.skipIf(process.platform !== "win32")(
    "reclaims a live governed tree when its owner exits unsuccessfully",
    async () => {
      const heartbeat = join(dir, "failed-exit-hb");
      const token = `piship-failed-exit-${Date.now()}`;
      const modulePath = fileURLToPath(
        new URL("../dist/index.js", import.meta.url),
      );
      const source = `
        const { existsSync, statSync } = await import("node:fs");
        const { spawnManaged } = await import(process.argv[1]);
        spawnManaged({
          file: process.execPath,
          args: ["-e", ${JSON.stringify(TREE)}, process.argv[2], process.argv[3]],
          cwd: process.cwd(),
          env: { PATH: process.env.PATH ?? "" },
        });
        const deadline = Date.now() + 10_000;
        setInterval(() => {
          if (existsSync(process.argv[2]) && statSync(process.argv[2]).size > 0)
            process.exit(42);
          if (Date.now() > deadline) process.exit(43);
        }, 50);
      `;
      const result = spawnSync(
        node,
        [
          "--input-type=module",
          "-e",
          source,
          pathToFileURL(modulePath).href,
          heartbeat,
          token,
        ],
        { cwd: dir, timeout: 20_000 },
      );
      expect(result.status).toBe(42);
      expect(statSync(heartbeat).size).toBeGreaterThan(0);
      expect(await heartbeatStopped(heartbeat)).toBe(true);
    },
    30_000,
  );

  it.skipIf(process.platform !== "win32")(
    "reclaims a live governed tree when its owner is forcibly killed",
    async () => {
      const heartbeat = join(dir, "hard-kill-hb");
      const token = `piship-hard-kill-${Date.now()}`;
      const modulePath = fileURLToPath(
        new URL("../dist/index.js", import.meta.url),
      );
      const source = `
        const { existsSync, statSync } = await import("node:fs");
        const { spawnManaged } = await import(process.argv[1]);
        spawnManaged({
          file: process.execPath,
          args: ["-e", ${JSON.stringify(TREE)}, process.argv[2], process.argv[3]],
          cwd: process.cwd(),
          env: { PATH: process.env.PATH ?? "" },
        });
        const timer = setInterval(() => {
          if (existsSync(process.argv[2]) && statSync(process.argv[2]).size > 0) {
            clearInterval(timer);
            console.log("ready");
          }
        }, 50);
        setTimeout(() => process.exit(43), 10_000);
      `;
      const owner = spawn(
        node,
        [
          "--input-type=module",
          "-e",
          source,
          pathToFileURL(modulePath).href,
          heartbeat,
          token,
        ],
        { cwd: dir, stdio: ["ignore", "pipe", "pipe"] },
      );
      try {
        let output = "";
        await new Promise<void>((resolve, reject) => {
          const deadline = setTimeout(
            () => reject(new Error("owner did not start")),
            15_000,
          );
          owner.stdout?.on("data", (chunk: Buffer) => {
            output += chunk.toString();
            if (output.includes("ready")) {
              clearTimeout(deadline);
              resolve();
            }
          });
          owner.once("exit", (code) => {
            clearTimeout(deadline);
            reject(new Error(`owner exited before readiness: ${code}`));
          });
        });
        expect(statSync(heartbeat).size).toBeGreaterThan(0);
        // /PID without /T kills only PiShip, not its supervisor or descendants.
        const killed = spawnSync(
          "taskkill",
          ["/F", "/PID", String(owner.pid)],
          {
            encoding: "utf8",
            timeout: 5000,
          },
        );
        expect(killed.status, killed.stderr).toBe(0);
        await new Promise<void>((resolve) =>
          owner.once("close", () => resolve()),
        );
        expect(await heartbeatStopped(heartbeat)).toBe(true);
      } finally {
        if (owner.exitCode === null && owner.pid)
          spawnSync("taskkill", ["/F", "/T", "/PID", String(owner.pid)], {
            stdio: "ignore",
            timeout: 5000,
          });
      }
    },
    30_000,
  );

  it("passes only the approved environment and strips credentials", async () => {
    let output = "";
    const exit = await spawnManaged({
      file: node,
      args: ["-e", "process.stdout.write(JSON.stringify(process.env))"],
      cwd: dir,
      env: {
        PATH: process.env.PATH ?? "",
        DOCS_MODE: "demo",
        ACME_API_TOKEN: "sk-should-never-arrive",
      },
      onStdout: (chunk) => {
        output += chunk.toString();
      },
    }).exited;
    expect(exit.code).toBe(0);
    const env = JSON.parse(output) as Record<string, string>;
    expect(env.DOCS_MODE).toBe("demo");
    expect(env.ACME_API_TOKEN).toBeUndefined();
    expect(output).not.toContain("sk-should-never-arrive");
    expect(env.HOME).toBeUndefined();
  });

  it("supports piped stdin and reports spawn failures without throwing", async () => {
    const child = spawnManaged({
      file: node,
      args: ["-e", "process.stdin.pipe(process.stdout)"],
      cwd: dir,
      env: { PATH: process.env.PATH ?? "" },
      stdin: "pipe",
    });
    let output = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.stdin?.end("ping");
    expect((await child.exited).code).toBe(0);
    expect(output).toBe("ping");
    // A request/response child must see each message while stdin stays open.
    const echo = spawnManaged({
      file: node,
      args: ["-e", "process.stdin.pipe(process.stdout)"],
      cwd: dir,
      env: { PATH: process.env.PATH ?? "" },
      stdin: "pipe",
    });
    const reply = new Promise<string>((resolveReply) =>
      echo.stdout?.once("data", (chunk: Buffer) =>
        resolveReply(chunk.toString()),
      ),
    );
    echo.stdin?.write("request\n");
    expect(await reply).toBe("request\n");
    echo.stdin?.end();
    expect((await echo.exited).code).toBe(0);
    const missing = await spawnManaged({
      file: join(dir, "does-not-exist"),
      cwd: dir,
      env: {},
    }).exited;
    expect(missing.code).toBeNull();
    expect(missing.error).toMatch(/ENOENT/);
  });
});

describe("trackDescendants", () => {
  // pid -> [ppid, pgid, start]; 10 is this process, 9 its parent, 100 the leader.
  let seq = 0;
  const table = (entries: Record<number, [number, number, string]>) => ({
    seq: ++seq,
    rows: parsePs(
      Object.entries(entries)
        .map(([pid, [ppid, pgid, start]]) => `${pid} ${ppid} ${pgid} ${start}`)
        .join("\n"),
    ),
  });
  type Known = Parameters<typeof trackDescendants>[3];
  const T = "Mon Oct 26 04:00:00 2026";

  it("records descendants that left the group, across a reparenting", () => {
    const known: Known = new Map();
    trackDescendants(
      table({
        9: [1, 9, T],
        10: [9, 9, T],
        100: [10, 100, T],
        101: [100, 100, T], // same group: the group kill reaches it
        102: [101, 102, T], // setsid
        103: [102, 102, T],
        200: [1, 200, T], // unrelated
      }),
      100,
      true,
      known,
      10,
    );
    expect([...known.keys()].sort()).toEqual([102, 103]);
    // The leader and 102 exited; 103 now belongs to launchd and is still found.
    trackDescendants(
      table({
        9: [1, 9, T],
        10: [9, 9, T],
        103: [1, 102, T],
        104: [103, 104, T],
      }),
      100,
      false,
      known,
      10,
    );
    expect([...known.keys()].sort()).toEqual([103, 104]);
  });

  it("follows a group member whose parent exited", () => {
    const known: Known = new Map();
    trackDescendants(
      table({
        10: [1, 10, T],
        100: [10, 100, T],
        101: [1, 100, T], // still in the leader's group, reparented
        102: [101, 102, T], // setsid
      }),
      100,
      true,
      known,
      10,
    );
    expect([...known.keys()]).toEqual([102]);
  });

  it("never lets an older snapshot read late drop a newer record", () => {
    const known: Known = new Map();
    const older = table({ 10: [1, 10, T], 100: [10, 100, T] });
    // A sync snapshot taken after it sees the escapee 105, born since.
    trackDescendants(
      table({ 10: [1, 10, T], 100: [10, 100, T], 105: [100, 105, T] }),
      100,
      true,
      known,
      10,
    );
    trackDescendants(older, 100, true, known, 10);
    expect([...known.keys()]).toEqual([105]);
    // The leader is gone and 105 belongs to launchd: still recorded.
    const exit = table({ 10: [1, 10, T], 105: [1, 105, T] });
    trackDescendants(exit, 100, false, known, 10);
    expect(known.get(105)?.seen).toBe(exit.seq);
    // Only a newer snapshot without it drops it.
    trackDescendants(table({ 10: [1, 10, T] }), 100, false, known, 10);
    expect(known.size).toBe(0);
  });

  it("drops a reused pid and never follows it", () => {
    const known: Known = new Map([[102, { start: T, seen: 0 }]]);
    trackDescendants(
      table({
        10: [1, 10, T],
        102: [1, 102, "Mon Oct 26 05:00:00 2026"], // same pid, another process
        300: [102, 300, T],
      }),
      100,
      false,
      known,
      10,
    );
    expect(known.size).toBe(0);
  });

  it("never records this process or its ancestors", () => {
    const known: Known = new Map();
    // A table claiming the launcher descends from, and shares a group with,
    // the leader (pid confusion).
    trackDescendants(
      table({
        100: [1, 100, T],
        9: [100, 100, T],
        10: [9, 9, T],
        11: [10, 11, T],
      }),
      100,
      true,
      known,
      10,
    );
    expect(known.has(9)).toBe(false);
    expect(known.has(10)).toBe(false);
    expect(known.has(11)).toBe(false);
  });
});

describe.skipIf(process.platform !== "darwin")(
  "macOS: descendants of a sandboxed command that left its group",
  () => {
    let dir: string;
    let sandbox: Awaited<ReturnType<typeof activateSandbox>>;
    const tokens: string[] = [];
    const env = { PATH: process.env.PATH ?? "" };
    // Node's `detached` calls setsid(): the grandchild leaves the leader's group.
    const ESCAPING = TREE.replace(
      '{ stdio: "ignore" }',
      '{ stdio: "ignore", detached: true }',
    );
    const EXITING = ESCAPING.replace(
      "setInterval(() => {}, 1000);",
      "setTimeout(() => process.exit(0), 2000);",
    );
    const appeared = async (check: () => boolean) => {
      for (let waited = 0; !check() && waited < 10_000; waited += 100)
        await sleep(100);
      return check();
    };
    const token = (name: string) => {
      const value = `piship-${name}-${Date.now()}`;
      tokens.push(value);
      return value;
    };
    beforeEach(async () => {
      dir = mkdtempSync(join(tmpdir(), "piship-reclaim-"));
      mkdirSync(join(dir, "home"));
      sandbox = await activateSandbox(
        {
          required: true,
          filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
          network: { mode: "deny" },
          environment: { allow: ["PATH"] },
        },
        { workspace: dir, homeDir: join(dir, "home"), env },
      );
    });
    afterEach(async () => {
      // Whatever a failed check left running.
      for (const value of tokens.splice(0))
        spawnSync("/usr/bin/pkill", ["-KILL", "-f", value]);
      await sandbox.dispose();
      rmSync(dir, { recursive: true, force: true });
    });

    it("kills it when the leader exits, and leaves a detached bystander alone", async () => {
      const heartbeat = join(dir, "hb");
      const escaped = token("setsid");
      const bystander = token("bystander");
      // Not this process's child: a helper starts it in a session of its own and exits.
      execFileSync(node, [
        "-e",
        "require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)', process.argv[1]], { detached: true, stdio: 'ignore' }).unref()",
        bystander,
      ]);
      const exit = await spawnManaged({
        file: node,
        args: ["-e", EXITING, heartbeat, escaped],
        cwd: dir,
        env,
        sandbox,
      }).exited;
      expect(exit.code).toBe(0);
      expect(existsSync(heartbeat)).toBe(true);
      expect(await heartbeatStopped(heartbeat)).toBe(true);
      expect(running(escaped)).toBe(false);
      expect(running(bystander)).toBe(true);
    });

    it("kills it on timeout", async () => {
      const heartbeat = join(dir, "hb");
      const escaped = token("setsid-timeout");
      const exit = await spawnManaged({
        file: node,
        args: ["-e", ESCAPING, heartbeat, escaped],
        cwd: dir,
        env,
        sandbox,
        timeoutMs: 5000,
        graceMs: 300,
      }).exited;
      expect(exit.timedOut).toBe(true);
      expect(existsSync(heartbeat)).toBe(true);
      expect(await heartbeatStopped(heartbeat)).toBe(true);
      expect(running(escaped)).toBe(false);
    });

    it("finds it below a group member whose parent exited", async () => {
      // ( (member) & ): the member stays in the group with launchd as parent,
      // then starts the escaping heartbeat.
      const heartbeat = join(dir, "hb");
      const escaped = token("orphan-member");
      const member = join(dir, "member.js");
      // Paths reach the scripts through argv, so no script text is built from them.
      writeFileSync(
        member,
        `setTimeout(() => require("node:child_process").spawn(process.execPath, ["-e", "setInterval(() => require('node:fs').appendFileSync(process.argv[1], '.'), 50)", process.argv[2], process.argv[3]], { detached: true, stdio: "ignore" }), 600); setInterval(() => {}, 1000);`,
      );
      const leader = `require("node:child_process").spawn(process.execPath, ["-e", "require('node:child_process').spawn(process.execPath, [process.argv[1], process.argv[2], process.argv[3]], { stdio: 'ignore' }); process.exit(0)", process.argv[1], process.argv[2], process.argv[3]], { stdio: "ignore" }); setInterval(() => {}, 1000);`;
      const exit = await spawnManaged({
        file: node,
        args: ["-e", leader, member, heartbeat, escaped],
        cwd: dir,
        env,
        sandbox,
        timeoutMs: 5000,
        graceMs: 300,
      }).exited;
      expect(exit.timedOut).toBe(true);
      expect(existsSync(heartbeat)).toBe(true);
      expect(await heartbeatStopped(heartbeat)).toBe(true);
      expect(running(escaped)).toBe(false);
    });

    it("leaves a detached child of an uncontained command alone", async () => {
      const heartbeat = join(dir, "hb");
      const detached = token("uncontained");
      const exit = await spawnManaged({
        file: node,
        args: ["-e", EXITING, heartbeat, detached],
        cwd: dir,
        env,
      }).exited;
      expect(exit.code).toBe(0);
      expect(await appeared(() => existsSync(heartbeat))).toBe(true);
      expect(await heartbeatStopped(heartbeat)).toBe(false);
      expect(running(detached)).toBe(true);
    });
  },
);
