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
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
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
const GIT_CONFIG =
  '[core]\n\tbare = false\n[remote "origin"]\n\turl = https://elsewhere.example/app.git\n';

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
      mkdirSync(join(ws, ".git", "info"), { recursive: true });
      writeFileSync(join(ws, ".git", "config"), GIT_CONFIG);
      writeFileSync(join(ws, ".git", "info", "exclude"), "# none\n");
      // A submodule's git directory, which `git status` enters; `worktrees`
      // does not exist yet.
      mkdirSync(join(ws, ".git", "modules", "sub", "hooks"), {
        recursive: true,
      });
      writeFileSync(join(ws, ".git", "modules", "sub", "config"), GIT_CONFIG);
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
        // As the governance session passes them; hooks and worktrees do not
        // exist yet.
        protectedPaths: {
          files: [
            join(ws, ".git", "config"),
            join(ws, ".git", "config.worktree"),
            join(ws, ".git", "commondir"),
          ],
          directories: [
            join(ws, ".git", "hooks"),
            join(ws, ".git", "info"),
            join(ws, ".git", "modules"),
            join(ws, ".git", "worktrees"),
          ],
        },
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
      // git-control-protection is live-probed here; this test is the CI gate
      // before local backends are required to provide it.
      expect(sandbox.report).toMatchObject({
        level: "enforced",
        adapter: adapter.id,
        planes: [
          "filesystem-read-deny",
          "filesystem-write-allowlist",
          "network-deny",
          "environment-filter",
          "git-control-protection",
        ],
        isolation: "local",
        workspace: {
          declared: "shared",
          effective: "shared",
          verification: "not-required",
          gitControlProtection: "verified",
          complete: true,
        },
      });
      expect(sandbox.report.warnings.join("\n")).not.toContain(
        "git-control-protection",
      );
      expect(open.report.planes).not.toContain("network-deny");
      expect(open.report.planes).toContain("git-control-protection");
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

    it("keeps git control files and hooks read-only inside the writable workspace", async () => {
      const git = join(ws, ".git");
      const attempts = [
        `echo '[remote "origin"]' >> .git/config`,
        `printf '\\turl = https://git.acme.example/app\\n' >> .git/config`,
        "mkdir -p .git/hooks && printf '#!/bin/sh\\ntouch pwned\\n' > .git/hooks/pre-commit",
        "echo '*' > .git/info/exclude",
        "rm -f .git/info/exclude",
        "mv .git .git-moved",
        "mv .git/config .git/config.old",
      ];
      for (const command of attempts) {
        const result = await run(sandbox, command);
        expect(result.exitCode, command).not.toBe(0);
      }
      expect(readFileSync(join(git, "config"), "utf8")).toBe(GIT_CONFIG);
      expect(readFileSync(join(git, "info", "exclude"), "utf8")).toBe(
        "# none\n",
      );
      expect(existsSync(join(git, "hooks", "pre-commit"))).toBe(false);
      expect(existsSync(join(ws, ".git-moved"))).toBe(false);
      expect(existsSync(join(git, "config.old"))).toBe(false);
      // The rest of the git directory stays writable, so git keeps working.
      const allowed = await run(
        sandbox,
        "echo named > .git/description && mkdir -p .git/refs/heads && echo ok",
      );
      expect(allowed.exitCode, allowed.output).toBe(0);
      expect(readFileSync(join(git, "description"), "utf8")).toBe("named\n");
    });

    it("keeps submodule git directories and linked-worktree metadata read-only", async () => {
      const git = join(ws, ".git");
      const attempts = [
        // A submodule's own config and hooks, which `git status` runs.
        `echo '[core]' >> .git/modules/sub/config`,
        "printf '#!/bin/sh\\ntouch pwned\\n' > .git/modules/sub/hooks/pre-commit",
        // A new submodule git directory.
        "mkdir -p .git/modules/evil && echo '[core]' > .git/modules/evil/config",
        // A linked worktree's administrative directory, which does not
        // exist, and the files git follows in it.
        "mkdir -p .git/worktrees/w && echo ../evil > .git/worktrees/w/commondir",
        // Seatbelt also denies files that do not exist yet; bubblewrap cannot
        // guard one (its mount point would be an empty file on the host).
        ...(process.platform === "darwin"
          ? [
              "echo ../evil > .git/config.worktree",
              "echo ../evil > .git/commondir",
            ]
          : []),
      ];
      for (const command of attempts) {
        const result = await run(sandbox, command);
        expect(result.exitCode, command).not.toBe(0);
      }
      expect(readFileSync(join(git, "modules", "sub", "config"), "utf8")).toBe(
        GIT_CONFIG,
      );
      expect(readdirSync(join(git, "modules", "sub", "hooks"))).toEqual([]);
      expect(existsSync(join(git, "modules", "evil"))).toBe(false);
      expect(existsSync(join(git, "worktrees", "w"))).toBe(false);
      if (process.platform === "darwin")
        expect(existsSync(join(git, "config.worktree"))).toBe(false);
    });

    it("keeps a core.hooksPath directory in the working tree read-only, and reports git control as not verified", async () => {
      // husky's layout: hooksPath is .husky/_ and its scripts call .husky/*.
      mkdirSync(join(ws, ".husky", "_"), { recursive: true });
      writeFileSync(join(ws, ".husky", "_", "h"), "#!/bin/sh\n");
      const husky = await activateSandbox(config, {
        workspace: ws,
        homeDir: home,
        env: { ...process.env, HOME: home },
        protectedPaths: {
          files: [join(ws, ".git", "config")],
          directories: [join(ws, ".husky", "_")],
        },
      });
      try {
        const box = async (command: string) =>
          (await husky.exec(command, ws, { onData: () => {} })).exitCode;
        expect(await box("echo hook >> .husky/_/h")).not.toBe(0);
        expect(await box("echo hook > .husky/_/pre-commit")).not.toBe(0);
        expect(readFileSync(join(ws, ".husky", "_", "h"), "utf8")).toBe(
          "#!/bin/sh\n",
        );
        expect(existsSync(join(ws, ".husky", "_", "pre-commit"))).toBe(false);
        // The rest of the working tree, .husky/pre-commit included, is not
        // protected, which is why git control is not verified.
        expect(await box("echo ok > .husky/pre-commit")).toBe(0);
        expect(husky.report.planes).toContain("git-control-protection");
        expect(husky.report.workspace).toMatchObject({
          gitControlProtection: "not-verified",
        });
      } finally {
        await husky.dispose();
      }
    });

    it("cannot hold a linked include target in place, and reports git control as not verified for it", async () => {
      // `.git/config` includes `linked.cfg`, a link to `shared/real.cfg`.
      // Protection covers the file the link points to; the link is an entry
      // in the writable workspace.
      const target = join(ws, "shared", "real.cfg");
      const link = join(ws, "linked.cfg");
      mkdirSync(join(ws, "shared"));
      writeFileSync(target, "[user]\n\tname = someone\n");
      symlinkSync(target, link);
      const box = await activateSandbox(config, {
        workspace: ws,
        homeDir: home,
        env: { ...process.env, HOME: home },
        protectedPaths: {
          files: [join(ws, ".git", "config"), target],
          directories: [join(ws, ".git", "hooks")],
          links: [link],
        },
      });
      try {
        const attempt = async (command: string) =>
          (await box.exec(command, ws, { onData: () => {} })).exitCode;
        expect(await attempt(`echo x >> "${target}"`)).not.toBe(0);
        expect(readFileSync(target, "utf8")).toBe("[user]\n\tname = someone\n");
        // Nothing holds the link itself: a command can point it at a file of
        // its own, which is why the report cannot claim the protection.
        expect(
          await attempt(`ln -sfn "${join(ws, "evil.cfg")}" "${link}"`),
        ).toBe(0);
        expect(readlinkSync(link)).toBe(join(ws, "evil.cfg"));
        expect(box.report.planes).toContain("git-control-protection");
        expect(box.report.workspace).toMatchObject({
          gitControlProtection: "not-verified",
        });
        expect(box.report.warnings.join("\n")).toContain("symbolic link");
      } finally {
        await box.dispose();
        rmSync(link, { force: true });
        rmSync(join(ws, "shared"), { recursive: true, force: true });
      }
    });

    it("keeps the user's own git config read-only where the sandbox may write the home directory", async () => {
      // A distribution that lets commands write `~`: the global config git
      // reads there must not take a hooks path from a sandboxed command.
      const globalConfig = join(home, ".gitconfig");
      const original = "[user]\n\tname = someone\n";
      writeFileSync(globalConfig, original);
      const writableHome: SandboxPolicy = {
        ...config,
        filesystem: {
          ...config.filesystem,
          write: { allow: ["workspace", "tmp", "~"] },
        },
      };
      const context = (files: string[]) => ({
        workspace: ws,
        homeDir: home,
        env: { ...process.env, HOME: home },
        protectedPaths: { files, directories: [join(ws, ".git", "hooks")] },
      });
      const box = await activateSandbox(
        writableHome,
        context([join(ws, ".git", "config"), globalConfig]),
      );
      try {
        const attempt = async (command: string) =>
          (await box.exec(command, ws, { onData: () => {} })).exitCode;
        expect(
          await attempt(
            `printf '[core]\\n\\thooksPath = /tmp/x\\n' >> "${globalConfig}"`,
          ),
        ).not.toBe(0);
        expect(await attempt(`rm -f "${globalConfig}"`)).not.toBe(0);
        expect(
          await attempt(`mv "${globalConfig}" "${globalConfig}.old"`),
        ).not.toBe(0);
        expect(readFileSync(globalConfig, "utf8")).toBe(original);
        expect(existsSync(`${globalConfig}.old`)).toBe(false);
        // The rest of the home directory stays writable.
        expect(await attempt(`echo ok > "${join(home, "notes")}"`)).toBe(0);
        expect(box.report.planes).toContain("git-control-protection");
        expect(box.report.workspace).toMatchObject({
          gitControlProtection: "verified",
        });
      } finally {
        await box.dispose();
      }
      // A global config nobody has created yet cannot be guarded on Linux, so
      // git control is not verified for it, wherever the sandbox may write.
      const missing = await activateSandbox(
        writableHome,
        context([join(home, ".config", "git", "config")]),
      );
      try {
        expect(missing.report.workspace).toMatchObject({
          gitControlProtection: "not-verified",
        });
      } finally {
        await missing.dispose();
      }
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
          [
            "open via copy",
            `cp /usr/bin/open ./op; echo cp=$?; ./op -g "${script}"`,
          ],
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
