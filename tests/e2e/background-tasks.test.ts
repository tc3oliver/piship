import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher } from "../helpers/distribution.js";

// Background tasks never outlive the PiShip process that started them: not
// when the session ends, and not when the process is sent SIGTERM. Each task
// starts a child of its own, so the whole process tree is checked. These
// cases use POSIX ps, pkill and signals; Windows has separate live Job Object
// and uncontained Bash tests.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const temporary: string[] = [];
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

type Services = Awaited<ReturnType<typeof startLocalServices>>;

/** The demo in Build mode with its shell `ask` relaxed to `allow`. */
async function distribution(options: { unsandboxed?: boolean } = {}) {
  const services: Services = await startLocalServices();
  closers.push(() => services.close());
  const temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-tasks-e2e-")));
  temporary.push(temp);
  const directory = join(temp, "distribution");
  cpSync(join(root, "examples", "demo-company"), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  const source = readFileSync(manifest, "utf8")
    .replace(
      "provider: system",
      "provider: file\n    acknowledgePlaintext: true",
    )
    .replace("127.0.0.1:8765", "127.0.0.1")
    .replace("defaultMode: plan", "defaultMode: build")
    .replace(
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: ask',
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: allow',
    );
  if (
    !source.includes("defaultMode: build") ||
    source.includes('"**"\n      effect: ask\n    - id: acme.tools')
  )
    throw new Error("demo manifest patch did not apply");
  const configured = options.unsandboxed
    ? source.replace(
        "sandbox:\n  required: true",
        "sandbox:\n  required: false",
      )
    : source;
  if (options.unsandboxed && configured === source)
    throw new Error("demo sandbox patch did not apply");
  writeFileSync(manifest, configured);
  const home = join(temp, "home");
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...services.env(),
    PISHIP_STATE_HOME: join(temp, "state"),
    PISHIP_NO_BROWSER: "1",
    HOME: home,
  };
  delete env.PISHIP_BUILD_INPUT;
  delete env.PISHIP_SANDBOX_ADAPTER;
  for (const step of ["lock", "build"]) {
    const done = spawnSync(process.execPath, [bin, step, manifest], {
      cwd: temp,
      env,
      encoding: "utf8",
    });
    expect(done.status, done.stderr).toBe(0);
  }
  const command = launcher(join(temp, "dist", "acmecode"), "acmecode");
  const project = join(temp, "project");
  mkdirSync(project, { recursive: true });
  const login = await branded(command, ["login"], {
    cwd: project,
    env,
    approve: (url) => services.approve(url),
  });
  expect(login.status, login.stderr).toBe(0);
  const audit = () =>
    readFileSync(join(temp, "state", "acmecode", "logs", "audit.jsonl"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { event: string; detail?: object });
  return { services, command, project, env, audit };
}

/**
 * A sleep no other process on the machine runs: its argument is unique. A
 * failing test still leaves none behind.
 */
function marker(): string {
  const seconds = `${5000 + Math.floor(Math.random() * 4000)}.${Math.floor(Math.random() * 900) + 100}`;
  closers.push(() => {
    spawnSync("pkill", ["-f", `^sleep ${seconds}$`]);
  });
  return seconds;
}

/** How many processes run `sleep <seconds>` now. */
function sleeping(seconds: string): number {
  const listed = spawnSync("ps", ["-eo", "command"], { encoding: "utf8" });
  return listed.stdout
    .split("\n")
    .filter((line) => line.trim() === `sleep ${seconds}`).length;
}

async function until(check: () => boolean, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return true;
    await new Promise((done) => setTimeout(done, 100));
  }
  return check();
}

describe.skipIf(process.platform === "win32")(
  "background tasks end with PiShip",
  () => {
    it("stops every task and the processes it started when the session ends", async () => {
      const { services, command, project, env } = await distribution();
      const seconds = marker();
      services.knobs.gatewayMode = "script";
      services.knobs.toolScript = [
        {
          name: "task_start",
          arguments: {
            command: `sleep ${seconds} & sleep ${seconds}; wait`,
          },
        },
      ];
      services.state.toolResults = [];
      const result = await branded(command, ["--smoke-model"], {
        cwd: project,
        env,
        timeoutMs: 120_000,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(services.state.toolResults[0]).toMatch(
        /Started\. Task \w+: running/,
      );
      expect(await until(() => sleeping(seconds) === 0, 5000)).toBe(true);
    }, 300000);

    it("stops every task when the PiShip process is sent SIGTERM", async () => {
      const { services, command, project, env, audit } = await distribution();
      const seconds = marker();
      const hold = marker();
      services.knobs.gatewayMode = "script";
      services.knobs.toolScript = [
        {
          name: "task_start",
          arguments: {
            command: `sleep ${seconds} & sleep ${seconds}; wait`,
          },
        },
        // Holds the session open while the test signals the process.
        { name: "bash", arguments: { command: `sleep ${hold}` } },
      ];
      services.state.toolResults = [];
      const child = spawn(command, ["--smoke-model"], {
        cwd: project,
        env,
        stdio: "ignore",
      });
      const exited = new Promise((done) => child.on("exit", done));
      closers.push(() => {
        child.kill("SIGKILL");
      });
      expect(
        await until(
          () => sleeping(seconds) === 2 && sleeping(hold) === 1,
          60_000,
        ),
      ).toBe(true);
      child.kill("SIGTERM");
      expect(await exited).toBe(143);
      expect(
        await until(
          () => sleeping(seconds) === 0 && sleeping(hold) === 0,
          5000,
        ),
      ).toBe(true);
      // The session ended first, so the stop was recorded.
      expect(
        audit().find((event) => event.event === "task.stop")?.detail,
      ).toMatchObject({ reason: "close" });
    }, 300000);
  },
);

/**
 * A native CLI integration check, not just a direct Job Object helper test.
 * /PID without /T kills the PiShip owner, leaving its supervisors to reclaim
 * detached descendants for both the foreground and background shell paths.
 */
describe.runIf(process.platform === "win32")(
  "Windows CLI hard-kill containment",
  () => {
    it.each(["bash", "task_start"] as const)(
      "reclaims a detached descendant after a forced owner kill (%s)",
      async (tool) => {
        const { services, command, project, env } = await distribution({
          unsandboxed: true,
        });
        // The .cmd shim starts this same Node entrypoint; killing cmd.exe
        // would not test what happens when the actual PiShip owner dies.
        const entry = command.replace(/\.cmd$/i, "");
        expect(existsSync(entry)).toBe(true);
        const heartbeat = join(project, "heartbeat");
        const stop = join(project, "stop");
        writeFileSync(
          join(project, "child.cjs"),
          [
            'const fs = require("node:fs");',
            'const path = require("node:path");',
            'const heartbeat = path.join(__dirname, "heartbeat");',
            'const stop = path.join(__dirname, "stop");',
            'setInterval(() => { if (fs.existsSync(stop)) process.exit(0); fs.appendFileSync(heartbeat, "."); }, 75);',
          ].join("\n"),
        );
        writeFileSync(
          join(project, "parent.cjs"),
          [
            'const { spawn } = require("node:child_process");',
            'const { existsSync } = require("node:fs");',
            'const path = require("node:path");',
            'const stop = path.join(__dirname, "stop");',
            'spawn(process.execPath, ["child.cjs"], { cwd: __dirname, detached: true, stdio: "ignore" }).unref();',
            'setInterval(() => { if (existsSync(stop)) process.exit(0); }, 100);',
          ].join("\n"),
        );
        services.knobs.gatewayMode = "script";
        services.knobs.toolScript = [
          { name: tool, arguments: { command: "node parent.cjs" } },
          ...(tool === "task_start"
            ? [
                {
                  name: "bash",
                  arguments: {
                    command: 'node -e "setInterval(() => {}, 1000)"',
                  },
                },
              ]
            : []),
        ];
        services.state.toolResults = [];
        const owner = spawn(process.execPath, [entry, "--smoke-model"], {
          cwd: project,
          env,
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        });
        let output = "";
        owner.stdout?.on("data", (chunk: Buffer) => {
          output += chunk.toString();
        });
        owner.stderr?.on("data", (chunk: Buffer) => {
          output += chunk.toString();
        });
        try {
          const ready = await until(
            () =>
              (existsSync(heartbeat) && statSync(heartbeat).size > 0) ||
              owner.exitCode !== null ||
              owner.signalCode !== null,
            90_000,
          );
          expect(ready, output).toBe(true);
          expect(existsSync(heartbeat), output).toBe(true);
          expect(statSync(heartbeat).size, output).toBeGreaterThan(0);
          // Deliberately omit /T: the Job Object, not taskkill, must
          // terminate the detached grandchild.
          const killed = spawnSync(
            "taskkill",
            ["/F", "/PID", String(owner.pid)],
            { encoding: "utf8", timeout: 5000 },
          );
          expect(killed.status, killed.stderr).toBe(0);
          await new Promise<void>((resolve, reject) => {
            if (owner.exitCode !== null || owner.signalCode !== null)
              return resolve();
            const timer = setTimeout(
              () =>
                reject(new Error("PiShip owner did not exit after taskkill")),
              10_000,
            );
            owner.once("close", () => {
              clearTimeout(timer);
              resolve();
            });
          });
          await new Promise((done) => setTimeout(done, 300));
          const afterKill = statSync(heartbeat).size;
          await new Promise((done) => setTimeout(done, 400));
          expect(statSync(heartbeat).size).toBe(afterKill);
        } finally {
          // If containment fails, release both fixture processes before
          // deleting the temporary project. Do not hide the failed assertion.
          writeFileSync(stop, "");
          if (owner.exitCode === null && owner.signalCode === null && owner.pid)
            spawnSync("taskkill", ["/F", "/T", "/PID", String(owner.pid)], {
              stdio: "ignore",
              timeout: 5000,
            });
          await new Promise((done) => setTimeout(done, 300));
        }
      },
      360_000,
    );
  },
);
