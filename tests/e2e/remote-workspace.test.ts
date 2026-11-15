import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
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
import { branded, launcher, type Result } from "../helpers/distribution.js";

// `sandbox.workspace: remote` end to end at the launcher: the agent edits a
// file and runs a command in a remote sandbox (a custom backend over a local directory), the host file stays as it
// was, the session leaves a patch, and `sandbox pull` applies it (and refuses
// a tampered one). The backend is a custom adapter over a local directory that runs each
// command with real /bin/sh, so the seed (tar, git init, commit) and the checkpoint
// (git diff) are the real scripts.
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
/** A custom backend whose "remote" is a local directory; commands run in it with real /bin/sh. */
const ADAPTER = `
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
const remote = process.env.RW_REMOTE_DIR;
export default () => ({
  id: "acme-remote",
  available: async () => ({ available: true }),
  capabilities: () => ({
    isolation: "remote",
    planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
    network: ["deny", "allow"],
    localProcesses: false,
  }),
  prepare: async () => ({
    files: {
      read: async (path) => {
        try { return readFileSync(join(remote, path)); }
        catch { throw Object.assign(new Error("no such file"), { code: "ENOENT" }); }
      },
      write: async (path, data) => {
        mkdirSync(dirname(join(remote, path)), { recursive: true });
        writeFileSync(join(remote, path), data);
      },
      stat: async (path) => {
        try {
          const info = statSync(join(remote, path));
          return { type: info.isDirectory() ? "directory" : "file", size: info.size };
        } catch { return undefined; }
      },
    },
    exec: (request, io) => {
      if (request.command.includes("piship-sandbox-ready")) {
        io.onStdout(Buffer.from("piship-sandbox-ready " + (request.env.PISHIP_PROBE_UNLISTED ?? "unset") + "\\n"));
        return Promise.resolve({ exitCode: 0 });
      }
      const cwd = request.workspacePath && request.workspacePath !== "."
        ? join(remote, ...request.workspacePath.split("/")) : remote;
      return new Promise((resolve, reject) => {
        const child = spawn("/bin/sh", ["-c", request.command], {
          cwd, env: { ...request.env, PATH: process.env.PATH }, stdio: ["ignore", "pipe", "pipe"],
        });
        child.stdout.on("data", io.onStdout);
        child.stderr.on("data", io.onStderr);
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ exitCode: code, signal }));
      });
    },
    dispose: async () => {},
  }),
});
`;

function build(services: Services) {
  const temp = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-remote-workspace-e2e-")),
  );
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
    .replace(
      /sandbox:\n {2}required: (true|false)\n/,
      [
        "sandbox:",
        "  required: true",
        "  provider: custom",
        "  adapter: ./adapters/remote-sandbox.mjs",
        "  workspace: remote",
        "",
      ].join("\n"),
    )
    .replace("defaultMode: plan", "defaultMode: build")
    .replace(
      "    - id: acme.models\n",
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: allow\n    - id: acme.models\n',
    );
  for (const marker of ["workspace: remote", "defaultMode: build"])
    if (!source.includes(marker)) throw new Error(`patch failed: ${marker}`);
  writeFileSync(manifest, source);
  mkdirSync(join(directory, "adapters"));
  writeFileSync(join(directory, "adapters", "remote-sandbox.mjs"), ADAPTER);
  const home = join(temp, "home");
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...services.env(),
    PISHIP_STATE_HOME: join(temp, "state"),
    PISHIP_NO_BROWSER: "1",
    HOME: home,
    USERPROFILE: home,
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
  const git = (...args: string[]) => {
    const done = spawnSync(
      "git",
      ["-c", "user.name=t", "-c", "user.email=t@invalid", ...args],
      { cwd: project, encoding: "utf8" },
    );
    expect(done.status, done.stderr).toBe(0);
  };
  git("init", "-q");
  writeFileSync(join(project, "a.txt"), "one\ntwo\n");
  git("add", "-A");
  git("commit", "-q", "-m", "base");
  return {
    temp,
    state: join(temp, "state", "acmecode"),
    project,
    run: (args: string[], extra: NodeJS.ProcessEnv = {}): Promise<Result> =>
      branded(command, args, {
        cwd: project,
        env: { ...env, ...extra },
        approve: (url) => services.approve(url),
      }),
  };
}

describe.skipIf(process.platform === "win32")(
  "remote workspace (local fixtures)",
  () => {
    it("edits in the sandbox, leaves the host alone, and applies the patch with sandbox pull", async () => {
      const services: Services = await startLocalServices();
      closers.push(() => services.close());
      const dist = build(services);
      const remote = join(dist.temp, "remote");
      mkdirSync(remote);
      const env = { RW_REMOTE_DIR: remote };
      const edited = join(dist.project, "a.txt");
      const login = await dist.run(["login"], env);
      expect(login.status, login.stderr).toBe(0);

      services.knobs.gatewayMode = "script";
      services.knobs.toolScript = [
        {
          name: "edit",
          arguments: {
            path: edited,
            edits: [{ oldText: "one", newText: "ONE" }],
          },
        },
        { name: "bash", arguments: { command: "cat a.txt" } },
      ];
      services.state.toolResults = [];
      const launched = await dist.run(["--smoke-model"], env);
      expect(launched.status, launched.stderr).toBe(0);
      // The sandbox saw the edit; the host did not.
      expect(services.state.toolResults.join("\n")).toContain("ONE");
      expect(readFileSync(edited, "utf8")).toBe("one\ntwo\n");
      expect(readFileSync(join(remote, "a.txt"), "utf8")).toBe("ONE\ntwo\n");
      expect(launched.stdout + launched.stderr).toMatch(/sandbox pull/);

      const patches = join(dist.state, "sandbox-workspace");
      const [key] = readdirSync(patches);
      const patchFile = join(patches, key as string, "latest.patch");
      const patch = readFileSync(patchFile);
      expect(patch.toString()).toContain("+ONE");

      // A tampered patch that also writes a git hook is refused as a whole.
      writeFileSync(
        patchFile,
        Buffer.concat([
          patch,
          Buffer.from(
            "diff --git a/.git/hooks/pre-commit b/.git/hooks/pre-commit\nnew file mode 100755\n--- /dev/null\n+++ b/.git/hooks/pre-commit\n@@ -0,0 +1 @@\n+evil\n",
          ),
        ]),
      );
      const refused = await dist.run(["sandbox", "pull", "--yes"], env);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toMatch(/refused as a whole/);
      expect(readFileSync(edited, "utf8")).toBe("one\ntwo\n");
      expect(() =>
        statSync(join(dist.project, ".git", "hooks", "pre-commit")),
      ).toThrow();

      // The genuine patch applies, and nothing is committed.
      writeFileSync(patchFile, patch);
      const pulled = await dist.run(["sandbox", "pull", "--yes"], env);
      expect(pulled.status, pulled.stderr).toBe(0);
      expect(readFileSync(edited, "utf8")).toBe("ONE\ntwo\n");
      const log = spawnSync("git", ["log", "--oneline"], {
        cwd: dist.project,
        encoding: "utf8",
      });
      expect(log.stdout.trim().split("\n")).toHaveLength(1);
    }, 600000);
  },
);
