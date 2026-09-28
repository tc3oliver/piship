import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnManaged } from "./process.js";

const node = process.execPath;
const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));

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

  it("kills the whole process tree on timeout", async () => {
    const heartbeat = join(dir, "hb");
    const token = `piship-tree-${Date.now()}`;
    let output = "";
    const child = spawnManaged({
      file: node,
      args: ["-e", TREE, heartbeat, token],
      cwd: dir,
      env: { PATH: process.env.PATH ?? "" },
      timeoutMs: 1000,
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
  });

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

  it.skipIf(process.platform === "win32")(
    "kills leftover group members when the leader exits",
    async () => {
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
    },
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
    const missing = await spawnManaged({
      file: join(dir, "does-not-exist"),
      cwd: dir,
      env: {},
    }).exited;
    expect(missing.code).toBeNull();
    expect(missing.error).toMatch(/ENOENT/);
  });
});
