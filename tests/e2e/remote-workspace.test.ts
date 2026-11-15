import { spawnSync } from "node:child_process";
import {
  cpSync,
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
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher, type Result } from "../helpers/distribution.js";
import { resolvePosixShell } from "../helpers/posix-shell.js";

// `sandbox.workspace: remote` end to end at the launcher: the agent edits a
// file and runs a command in a remote sandbox (a custom backend over a local directory), the host file stays as it
// was, the session leaves a patch, and `sandbox pull` applies it (and refuses
// a tampered one). The backend is a custom adapter over a local directory that runs each
// command with a real POSIX shell (/bin/sh; Git for Windows' sh.exe on Windows,
// see tests/helpers/posix-shell.ts), so the seed (tar, git init, commit) and the checkpoint
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

const posix = resolvePosixShell();
if (!posix && process.env.PISHIP_REQUIRE_SANDBOX === "1")
  throw new Error(
    "remote-workspace e2e needs a POSIX shell (Git for Windows sh.exe) and none was found; PISHIP_REQUIRE_SANDBOX=1 asks for these tests to run",
  );
if (!posix)
  console.warn(
    "remote-workspace e2e skipped: no POSIX shell found (Git for Windows sh.exe). Set PISHIP_REQUIRE_SANDBOX=1 to fail instead of skipping.",
  );
const sandboxEnv = (remote: string): NodeJS.ProcessEnv => ({
  RW_REMOTE_DIR: remote,
  RW_SHELL: posix?.shell,
  RW_PATH: posix?.path,
});

type Services = Awaited<ReturnType<typeof startLocalServices>>;
/** A custom backend whose "remote" is a local directory; commands run in it with a real POSIX shell (RW_SHELL, RW_PATH). */
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
        const env = { ...request.env, PATH: process.env.RW_PATH ?? process.env.PATH };
        if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
        const child = spawn(process.env.RW_SHELL ?? "/bin/sh", ["-c", request.command], {
          cwd, env, stdio: ["ignore", "pipe", "pipe"],
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
  const runIn = (
    cwd: string,
    args: string[],
    extra: NodeJS.ProcessEnv = {},
  ): Promise<Result> =>
    branded(command, args, {
      cwd,
      env: { ...env, ...extra },
      approve: (url) => services.approve(url),
    });
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
  git("config", "core.autocrlf", "false");
  writeFileSync(join(project, "a.txt"), "one\ntwo\n");
  git("add", "-A");
  git("commit", "-q", "-m", "base");
  return {
    temp,
    state: join(temp, "state", "acmecode"),
    project,
    run: (args: string[], extra: NodeJS.ProcessEnv = {}): Promise<Result> =>
      runIn(project, args, extra),
    runIn,
  };
}

describe.skipIf(!posix)("remote workspace (local fixtures)", () => {
  it("edits in the sandbox, leaves the host alone, and applies the patch with sandbox pull", async () => {
    const services: Services = await startLocalServices();
    closers.push(() => services.close());
    const dist = build(services);
    const remote = join(dist.temp, "remote");
    mkdirSync(remote);
    const env = sandboxEnv(remote);
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

    // A tampered patch that also plants a symlink is refused as a whole.
    // (A protected path alone is skipped; the unit tests cover that.)
    writeFileSync(
      patchFile,
      Buffer.concat([
        patch,
        Buffer.from(
          "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+.git/hooks\n\\ No newline at end of file\n",
        ),
      ]),
    );
    const refused = await dist.run(["sandbox", "pull", "--yes"], env);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/refused as a whole/);
    expect(readFileSync(edited, "utf8")).toBe("one\ntwo\n");
    expect(existsSync(join(dist.project, "link"))).toBe(false);

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
});

// Round trips: a change made in the sandbox is what the host tree holds after
// `sandbox pull`. One built distribution serves every case; each case gets its
// own project and its own "remote" directory.
describe.skipIf(!posix)("remote workspace round trips", () => {
  let services: Services;
  let dist: ReturnType<typeof build>;
  let cases = 0;
  beforeAll(async () => {
    services = await startLocalServices();
    dist = build(services);
    temporary.splice(temporary.indexOf(dist.temp), 1);
    const login = await dist.run(
      ["login"],
      sandboxEnv(join(dist.temp, "login-remote")),
    );
    expect(login.status, login.stderr).toBe(0);
  }, 300000);
  afterAll(async () => {
    await services.close();
    rmSync(dist.temp, { recursive: true, force: true });
  }, 60000);

  /** A fresh git project holding `files`, a sandbox that runs `command`, and the pull. */
  async function session(
    files: Record<string, string | Buffer>,
    command: string,
    options: {
      commit?: boolean;
      modes?: Record<string, number>;
      autocrlf?: "true" | "false";
      /** Check the files out again after the commit, as a clone would (CRLF under autocrlf). */
      checkout?: boolean;
      /** core.autocrlf from the launch on, after the files were committed under `autocrlf`. */
      launchAutocrlf?: "true";
    } = {},
  ) {
    const dir = join(dist.temp, `case-${++cases}`);
    const project = join(dir, "project");
    const remote = join(dir, "remote");
    mkdirSync(project, { recursive: true });
    mkdirSync(remote);
    const git = (...args: string[]) => {
      const done = spawnSync(
        "git",
        ["-c", "user.name=t", "-c", "user.email=t@invalid", ...args],
        { cwd: project, encoding: "utf8" },
      );
      expect(done.status, done.stderr).toBe(0);
    };
    git("init", "-q");
    git("config", "core.autocrlf", options.autocrlf ?? "false");
    for (const [name, data] of Object.entries(files)) {
      mkdirSync(dirname(join(project, name)), { recursive: true });
      writeFileSync(join(project, name), data, {
        mode: options.modes?.[name] ?? 0o644,
      });
    }
    if (options.commit !== false) {
      git("add", "-A");
      git("commit", "-q", "--allow-empty", "-m", "base");
    }
    if (options.checkout) {
      for (const name of Object.keys(files)) rmSync(join(project, name));
      git("checkout", "--", ".");
    }
    if (options.launchAutocrlf)
      git("config", "core.autocrlf", options.launchAutocrlf);
    const env = sandboxEnv(remote);
    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = [{ name: "bash", arguments: { command } }];
    const launched = await dist.runIn(project, ["--smoke-model"], env);
    expect(launched.status, launched.stderr).toBe(0);
    return {
      project,
      remote,
      launched,
      read: (name: string) => readFileSync(join(project, name)),
      pull: () => dist.runIn(project, ["sandbox", "pull", "--yes"], env),
      git: (...args: string[]) =>
        spawnSync("git", args, { cwd: project, encoding: "utf8" }).stdout,
    };
  }
  const bytes = (...values: number[]) => Buffer.from(values);

  it("round-trips a created and a modified binary file", async () => {
    const s = await session(
      { "mod.bin": bytes(1, 2, 3) },
      "printf '\\000\\377\\001\\376' > new.bin && printf '\\377\\000\\377\\000\\010' > mod.bin",
    );
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(s.read("new.bin").equals(bytes(0, 255, 1, 254))).toBe(true);
    expect(s.read("mod.bin").equals(bytes(255, 0, 255, 0, 8))).toBe(true);
  }, 120000);

  it("round-trips a deleted file", async () => {
    const s = await session({ "a.txt": "a\n", "b.txt": "b\n" }, "rm a.txt");
    expect((await s.pull()).status).toBe(0);
    expect(existsSync(join(s.project, "a.txt"))).toBe(false);
    expect(s.read("b.txt").toString()).toBe("b\n");
  }, 120000);

  it("round-trips a rename as a delete and an add", async () => {
    const s = await session({ "old.txt": "same\n" }, "mv old.txt new.txt");
    expect((await s.pull()).status).toBe(0);
    expect(existsSync(join(s.project, "old.txt"))).toBe(false);
    expect(s.read("new.txt").toString()).toBe("same\n");
  }, 120000);

  // Windows has no mode bits to add.
  it.skipIf(process.platform === "win32")(
    "round-trips an added executable bit",
    async () => {
      const s = await session({ "run.sh": "#!/bin/sh\n" }, "chmod +x run.sh");
      expect(statSync(join(s.project, "run.sh")).mode & 0o111).toBe(0);
      expect((await s.pull()).status).toBe(0);
      expect(statSync(join(s.project, "run.sh")).mode & 0o111).not.toBe(0);
    },
    120000,
  );

  it("round-trips unicode and space-containing names byte for byte", async () => {
    const s = await session(
      { "a.txt": "a\n" },
      "mkdir -p 目錄 && printf 'héllo\\n世界 \\360\\237\\230\\200\\n' > '目錄/檔 案.txt' && printf 'e' > '😀.txt'",
    );
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(
      s.read(join("目錄", "檔 案.txt")).equals(Buffer.from("héllo\n世界 😀\n")),
    ).toBe(true);
    expect(s.read("😀.txt").toString()).toBe("e");
  }, 120000);

  it("round-trips a new file into a repository with no commits", async () => {
    const s = await session({}, "printf 'b\\n' > b.txt", { commit: false });
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(s.read("b.txt").toString()).toBe("b\n");
  }, 120000);

  // Plain `git apply` needs no index entry; `--3way` alone refused this.
  it("round-trips a modified untracked file in a repository with no commits", async () => {
    const s = await session({ "a.txt": "a\n" }, "printf 'A\\n' > a.txt", {
      commit: false,
    });
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(s.read("a.txt").toString()).toBe("A\n");
  }, 120000);

  it("round-trips an empty repository whose only change is a nested directory", async () => {
    const s = await session(
      {},
      "mkdir -p deep/er/still && printf 'x\\n' > deep/er/still/f.txt",
      { commit: false },
    );
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(s.read("deep/er/still/f.txt").toString()).toBe("x\n");
  }, 120000);

  it("leaves a file skipped by policy at seed time untouched", async () => {
    const s = await session(
      { "a.txt": "a\n", ".env": "secret\n" },
      "ls -A; printf 'A\\n' > a.txt",
    );
    // Not uploaded, so the sandbox never had it.
    expect(existsSync(join(s.remote, ".env"))).toBe(false);
    expect((await s.pull()).status).toBe(0);
    expect(s.read("a.txt").toString()).toBe("A\n");
    expect(s.read(".env").toString()).toBe("secret\n");
  }, 120000);

  it("reports nothing to apply when the sandbox changed nothing", async () => {
    const s = await session({ "a.txt": "a\n" }, "cat a.txt");
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(pulled.stdout).toMatch(/no changes/);
    expect(s.read("a.txt").toString()).toBe("a\n");
  }, 120000);

  it("keeps an uncommitted local edit to a different file", async () => {
    const s = await session(
      { "a.txt": "a\n", "b.txt": "b\n" },
      "printf 'A\\n' > a.txt",
    );
    writeFileSync(join(s.project, "b.txt"), "local\n");
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(s.read("a.txt").toString()).toBe("A\n");
    expect(s.read("b.txt").toString()).toBe("local\n");
  }, 120000);

  it("never loses an uncommitted local edit to the same file", async () => {
    const lines = Array.from({ length: 12 }, (_, i) => `line${i + 1}\n`);
    const s = await session(
      { "a.txt": lines.join("") },
      "sed 's/^line1$/SANDBOX/' a.txt > t && mv t a.txt",
    );
    const local = lines.map((l, i) => (i === 11 ? "LOCAL\n" : l)).join("");
    writeFileSync(join(s.project, "a.txt"), local);
    const pulled = await s.pull();
    const now = s.read("a.txt").toString();
    // The hunks do not overlap, so plain `git apply` merges both edits.
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(now).toBe(local.replace("line1\n", "SANDBOX\n"));
  }, 120000);

  // The host repository converts line endings (the Windows default); the
  // patch is LF. Recorded here so a change in what `sandbox pull` does shows.
  it("pulls an LF patch into a repository with core.autocrlf=true without corrupting it", async () => {
    const s = await session(
      { "a.txt": "one\ntwo\nthree\n" },
      "printf 'ONE\\ntwo\\nthree\\nfour\\n' > a.txt",
      { autocrlf: "true" },
    );
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(s.read("a.txt").toString().replaceAll("\r\n", "\n")).toBe(
      "ONE\ntwo\nthree\nfour\n",
    );
  }, 120000);

  // A Windows checkout (core.autocrlf=true, CRLF on disk, LF in git) and a
  // sandbox tool that rewrites the file with LF: only the changed line comes
  // back, so it merges with a local edit to another line of the same file.
  it("pulls an LF rewrite of a CRLF checkout as the lines it changed", async () => {
    const lines = Array.from({ length: 12 }, (_, i) => `line${i + 1}\n`);
    const s = await session(
      { "a.txt": lines.join("") },
      "sed 's/^line1\\r$/SANDBOX/' a.txt | tr -d '\\r' > t && mv t a.txt",
      { autocrlf: "true", checkout: true },
    );
    const local = s.read("a.txt").toString().replace("line12\r\n", "LOCAL\r\n");
    expect(local.startsWith("line1\r\n")).toBe(true);
    writeFileSync(join(s.project, "a.txt"), local);
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(pulled.stdout).toMatch(/changed {2}a\.txt {2}\+1 -1/);
    expect(s.read("a.txt").toString()).toBe(
      local.replace("line1\r\n", "SANDBOX\r\n"),
    );
  }, 120000);

  // A file committed with CRLF before autocrlf was turned on still applies.
  it("pulls a one-line change to a file git stores with CRLF under core.autocrlf=true", async () => {
    const s = await session(
      { "a.txt": "one\r\ntwo\r\nthree\r\n" },
      "sed 's/one/ONE/' a.txt > t && mv t a.txt",
      { launchAutocrlf: "true" },
    );
    const pulled = await s.pull();
    expect(pulled.status, pulled.stderr).toBe(0);
    expect(s.read("a.txt").toString()).toBe("ONE\r\ntwo\r\nthree\r\n");
  }, 120000);
});
