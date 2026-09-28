// Boundary tests against the real OS sandbox of this platform (bubblewrap on
// Linux, sandbox-exec on macOS). They are gated on the adapter platform, not
// silently skipped: with PISHIP_REQUIRE_SANDBOX=1 an unavailable adapter fails.
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ActiveSandbox, activateSandbox } from "./activate.js";
import { sanitizeStderr } from "./environment.js";
import { spawnManaged } from "./process.js";
import type { SandboxPolicy } from "./profile.js";
import { selectAdapter } from "./select.js";

const adapter = selectAdapter();
const native = adapter.id !== "unsupported";
const availability = native ? await adapter.available() : undefined;
const requireSandbox = process.env.PISHIP_REQUIRE_SANDBOX === "1";
const ready = availability?.available === true;

const node = process.execPath;
const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));
const SECRET = "boundary-secret-7f3a9c";

const TREE = `
const { spawn } = require("node:child_process");
const [heartbeat, token] = process.argv.slice(2);
spawn(process.execPath, ["-e", "setInterval(() => require('node:fs').appendFileSync(process.argv[1], '.'), 50)", heartbeat, token], { stdio: "ignore" });
setInterval(() => {}, 1000);
`;
const CONNECT = `
const net = require("node:net");
const [host, port] = process.argv.slice(2);
const socket = net.connect({ host, port: Number(port) });
const timer = setTimeout(() => { console.log("timeout"); process.exit(3); }, 3000);
socket.once("connect", () => { console.log("connected"); process.exit(0); });
socket.once("error", (e) => { console.log("refused " + e.code); process.exit(2); });
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
  return execFileSync("ps", ["-Ao", "command"], { encoding: "utf8" }).includes(
    token,
  );
}

function size(file: string): number {
  try {
    return statSync(file).size;
  } catch {
    return 0;
  }
}

async function heartbeatStopped(file: string): Promise<boolean> {
  await sleep(300);
  const before = size(file);
  await sleep(400);
  return size(file) === before;
}

function listen(): Promise<{
  server: Server;
  port: number;
  hits: () => number;
}> {
  let hits = 0;
  const server = createServer((socket) => {
    hits++;
    socket.destroy();
  });
  return new Promise((done) =>
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      done({
        server,
        port: typeof address === "object" && address ? address.port : 0,
        hits: () => hits,
      });
    }),
  );
}

describe.skipIf(!native)(`native sandbox adapter ${adapter.id}`, () => {
  it("is available on this host (mandatory with PISHIP_REQUIRE_SANDBOX=1)", () => {
    if (requireSandbox || ready)
      expect(availability).toEqual({ available: true });
    else
      console.warn(
        `sandbox boundary tests skipped: ${availability && !availability.available ? availability.reason : "unknown"}`,
      );
  });

  describe.skipIf(!ready && !requireSandbox)("boundary", () => {
    let root: string;
    let ws: string;
    let home: string;
    let outside: string;
    let sandbox: ActiveSandbox;
    let open: ActiveSandbox;

    const config: SandboxPolicy = {
      required: true,
      filesystem: {
        read: { deny: ["~/.ssh", "~/.netrc", "workspace/.secrets"] },
        write: { allow: ["workspace", "tmp"] },
      },
      network: { mode: "deny" },
      environment: { allow: ["PATH", "HOME", "LANG", "ACME_API_TOKEN"] },
    };

    const run = async (
      box: ActiveSandbox,
      command: string,
      timeout?: number,
    ) => {
      let output = "";
      const result = await box.exec(command, ws, {
        onData: (data) => {
          output += data.toString("utf8");
        },
        ...(timeout ? { timeout } : {}),
      });
      return { exitCode: result.exitCode, output };
    };

    beforeAll(async () => {
      const base = existsSync("/var/tmp") ? "/var/tmp" : tmpdir();
      root = realpathSync(mkdtempSync(join(base, "piship-boundary-")));
      ws = join(root, "ws");
      home = join(root, "home");
      outside = join(root, "outside");
      mkdirSync(join(home, ".ssh"), { recursive: true });
      mkdirSync(join(ws, ".secrets"), { recursive: true });
      mkdirSync(outside);
      writeFileSync(join(home, ".ssh", "id_ed25519"), SECRET);
      writeFileSync(join(home, ".netrc"), SECRET);
      writeFileSync(join(ws, ".secrets", "key"), SECRET);
      writeFileSync(join(ws, "tree.js"), TREE);
      writeFileSync(join(ws, "connect.js"), CONNECT);
      const env = {
        ...process.env,
        HOME: home,
        ACME_API_TOKEN: "sk-live-never-in-children",
        UNLISTED_VARIABLE: "unlisted",
      };
      sandbox = await activateSandbox(config, {
        workspace: ws,
        homeDir: home,
        env,
      });
      open = await activateSandbox(
        { ...config, network: { mode: "allow" } },
        { workspace: ws, homeDir: home, env },
      );
    });
    afterAll(() => {
      sandbox?.dispose();
      open?.dispose();
      if (root) rmSync(root, { recursive: true, force: true });
    });

    it("reports enforced containment with every plane after the live probe", () => {
      expect(sandbox.report).toMatchObject({
        level: "enforced",
        adapter: adapter.id,
        planes: [
          "filesystem-read-deny",
          "filesystem-write-allowlist",
          "network-deny",
          "environment-filter",
        ],
      });
      expect(open.report.planes).not.toContain("network-deny");
    });

    it("allows writes inside the workspace and the session temp directory", async () => {
      const result = await run(
        sandbox,
        `echo inside > "${ws}/written" && echo tmp > "$TMPDIR/written"`,
      );
      expect(result.exitCode).toBe(0);
      expect(readFileSync(join(ws, "written"), "utf8")).toBe("inside\n");
      expect(
        readFileSync(join(sandbox.profile.tmpDir, "written"), "utf8"),
      ).toBe("tmp\n");
    });

    it("denies writes outside the allowlist", async () => {
      for (const target of [
        join(outside, "escape"),
        join(home, "escape"),
        join(root, "escape"),
      ]) {
        const result = await run(sandbox, `echo x > "${target}"`);
        expect(result.exitCode).not.toBe(0);
        expect(existsSync(target)).toBe(false);
      }
    });

    it("hides denied directories and files, including a deny inside the workspace", async () => {
      const result = await run(
        sandbox,
        [
          `echo "listed=$(ls -a "${home}/.ssh" 2>/dev/null | grep -c id_)"`,
          `cat "${home}/.ssh/id_ed25519"`,
          `cat "${home}/.netrc"`,
          `cat "${ws}/.secrets/key"`,
          `echo overwrite > "${ws}/.secrets/key"`,
          `echo overwrite > "${home}/.netrc"`,
          "echo done",
        ].join("; "),
      );
      expect(result.output).toContain("done");
      expect(result.output).toContain("listed=0");
      expect(result.output).not.toContain(SECRET);
      expect(readFileSync(join(ws, ".secrets", "key"), "utf8")).toBe(SECRET);
      expect(readFileSync(join(home, ".netrc"), "utf8")).toBe(SECRET);
    });

    it.runIf(process.platform === "darwin")(
      "cannot start processes outside the sandbox through launchd, open, or osascript",
      async (ctx) => {
        const waitFor = async (file: string, ms: number) => {
          for (let waited = 0; waited < ms; waited += 250) {
            if (existsSync(file)) return true;
            await sleep(250);
          }
          return existsSync(file);
        };
        const label = (name: string) =>
          `dev.piship.boundary.${name}.${process.pid}`;
        const remove = (name: string) => {
          try {
            execFileSync("/bin/launchctl", ["remove", label(name)], {
              stdio: "ignore",
            });
          } catch {
            // not submitted
          }
        };
        // Control: outside the sandbox, a launchd job does run. Without this
        // the absence of the marker below would prove nothing.
        const control = join(outside, "control");
        execFileSync("/bin/launchctl", [
          "submit",
          "-l",
          label("control"),
          "--",
          "/usr/bin/touch",
          control,
        ]);
        const controlRan = await waitFor(control, 15_000);
        remove("control");
        if (!controlRan)
          ctx.skip("launchd did not run a submitted job on this host");

        const marker = join(outside, "launched");
        const script = join(ws, "escape.command");
        writeFileSync(script, `#!/bin/sh\ntouch "${marker}"\n`, {
          mode: 0o755,
        });
        const attempts: [string, string][] = [
          [
            "launchctl",
            `/bin/launchctl submit -l ${label("direct")} -- /usr/bin/touch "${marker}"`,
          ],
          [
            "copied launchctl",
            `cp /bin/launchctl ./lc; echo cp=$?; ./lc submit -l ${label("copy")} -- /usr/bin/touch "${marker}"`,
          ],
          ["open", `/usr/bin/open -g "${script}"`],
          ["open via copy", `cp /usr/bin/open ./op; echo cp=$?; ./op -g "${script}"`],
          [
            "osascript",
            `/usr/bin/osascript -e 'do shell script "/usr/bin/open -g ${script}"'`,
          ],
          [
            "osascript from node",
            `"${node}" -e 'require("node:child_process").execFileSync("/usr/bin/osascript", ["-e", "tell application \\"Terminal\\" to do script \\"touch ${marker}\\""])'`,
          ],
        ];
        try {
          for (const [name, command] of attempts) {
            const started = Date.now();
            // Denial must be a prompt refusal, not a hang.
            const result = await run(sandbox, command, 10).catch(
              (error: Error) => {
                throw new Error(`${name}: ${error.message}`);
              },
            );
            console.info(
              `seatbelt ${name}: exit ${result.exitCode} after ${Date.now() - started} ms: ${result.output.trim().slice(0, 200)}`,
            );
            expect(result.exitCode, name).not.toBe(0);
          }
          expect(await waitFor(marker, 15_000)).toBe(false);
        } finally {
          for (const name of ["direct", "copy"]) remove(name);
        }
        // Ordinary tools still run under the same profile.
        const tools = await run(
          sandbox,
          `/bin/sh -c 'echo sh-ok' && "${node}" -e 'console.log("node-ok")' && git --version`,
        );
        expect(tools.exitCode, tools.output).toBe(0);
        expect(tools.output).toContain("sh-ok");
        expect(tools.output).toContain("node-ok");
      },
      120_000,
    );

    it("denies external and host loopback network access", async () => {
      const listener = await listen();
      try {
        const external = await run(sandbox, `"${node}" connect.js 1.1.1.1 443`);
        expect(external.output).toMatch(/refused|timeout/);
        expect(external.output).not.toContain("connected");
        expect(external.exitCode).not.toBe(0);
        const loopback = await run(
          sandbox,
          `"${node}" connect.js 127.0.0.1 ${listener.port}`,
        );
        expect(loopback.output).toMatch(/refused|timeout/);
        expect(loopback.output).not.toContain("connected");
        expect(loopback.exitCode).not.toBe(0);
        expect(listener.hits()).toBe(0);
      } finally {
        listener.server.close();
      }
    });

    it("reaches a host loopback listener in network allow mode", async () => {
      const listener = await listen();
      try {
        const result = await run(
          open,
          `"${node}" connect.js 127.0.0.1 ${listener.port}`,
        );
        expect(result.output).toContain("connected");
        expect(result.exitCode).toBe(0);
      } finally {
        listener.server.close();
      }
    });

    it("passes only allowed, non-credential environment variables", async () => {
      const result = await run(sandbox, "env");
      expect(result.exitCode).toBe(0);
      expect(result.output).toContain("PATH=");
      expect(result.output).toContain(`HOME=${home}`);
      expect(result.output).not.toContain("ACME_API_TOKEN");
      expect(result.output).not.toContain("sk-live-never-in-children");
      expect(result.output).not.toContain("UNLISTED_VARIABLE");
    });

    it("kills the sandboxed process tree on timeout", async () => {
      const heartbeat = join(ws, "hb-timeout");
      const token = `piship-sbx-timeout-${Date.now()}`;
      await expect(
        run(sandbox, `"${node}" tree.js "${heartbeat}" ${token}`, 1),
      ).rejects.toThrow("timeout:1");
      expect(await heartbeatStopped(heartbeat)).toBe(true);
      expect(size(heartbeat)).toBeGreaterThan(0);
      expect(running(token)).toBe(false);
    });

    it("cancels the sandboxed process tree through an AbortSignal", async () => {
      const heartbeat = join(ws, "hb-abort");
      const token = `piship-sbx-abort-${Date.now()}`;
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 800);
      await expect(
        sandbox.exec(`"${node}" tree.js "${heartbeat}" ${token}`, ws, {
          onData: () => {},
          signal: controller.signal,
        }),
      ).rejects.toThrow("aborted");
      expect(await heartbeatStopped(heartbeat)).toBe(true);
      expect(running(token)).toBe(false);
    });

    it("reports signal exits as 128 + signal number", async () => {
      expect((await run(sandbox, "kill -TERM $$")).exitCode).toBe(143);
      expect((await run(sandbox, "exit 7")).exitCode).toBe(7);
    });

    it("redacts stderr of a sandboxed governed child", async () => {
      let stderr = "";
      const exit = await spawnManaged({
        file: "/bin/sh",
        args: [
          "-c",
          'echo "request failed: Authorization: Bearer abcdefgh12345678" >&2; echo "$DOCS_MODE"',
        ],
        cwd: ws,
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin", DOCS_MODE: "demo" },
        sandbox,
        onStderr: (chunk) => {
          stderr += chunk.toString("utf8");
        },
      }).exited;
      expect(exit.code).toBe(0);
      expect(stderr).toContain("abcdefgh12345678");
      const clean = sanitizeStderr(stderr, 1024);
      expect(clean).not.toContain("abcdefgh12345678");
      expect(clean).toContain("[REDACTED]");
    });
  });
});
