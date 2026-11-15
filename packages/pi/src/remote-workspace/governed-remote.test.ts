// A governed session with `sandbox.workspace: remote`: the file tools keep the
// host's policy decision and then act in the sandbox, the seed is lazy and
// never prompts, and the sandbox's work is checkpointed for `sandbox pull`.
// The backend is a custom adapter whose "remote" is a local directory and
// whose exec runs real /bin/sh there.
import { execFileSync } from "node:child_process";
import {
  existsSync,
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
import type {
  ExtensionContext,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { ManagedFetch } from "@piship/contracts";
import {
  remoteWorkspacePaths,
  resolveLock,
  writeRemoteWorkspaceCheckpoint,
} from "@piship/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { governanceHooks } from "../builtins.js";
import { GovernanceSession } from "../governance-session.js";
import { governedTools } from "../governed-tools.js";

const posix = process.platform !== "win32";
const asRoot = typeof process.getuid === "function" && process.getuid() === 0;

interface Log {
  files: { op: string; path: string }[];
  commands: string[];
  failSeedOnce?: boolean;
  failDiff?: boolean;
}
const log = (): Log =>
  ((globalThis as { __pishipRemote?: Log }).__pishipRemote ??= {
    files: [],
    commands: [],
  });

function adapter(remote: string): string {
  return `
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
const remote = ${JSON.stringify(remote)};
const log = () => globalThis.__pishipRemote;
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
        log().files.push({ op: "read", path });
        try { return readFileSync(join(remote, path)); }
        catch (error) { throw Object.assign(new Error("no such file"), { code: "ENOENT" }); }
      },
      write: async (path, data) => {
        log().files.push({ op: "write", path });
        mkdirSync(dirname(join(remote, path)), { recursive: true });
        writeFileSync(join(remote, path), data);
      },
      stat: async (path) => {
        log().files.push({ op: "stat", path });
        try {
          const info = statSync(join(remote, path));
          return { type: info.isDirectory() ? "directory" : "file", size: info.size };
        } catch { return undefined; }
      },
    },
    exec: (request, io) => {
      log().commands.push(request.command);
      if (request.command.includes("piship-sandbox-ready")) {
        io.onStdout(Buffer.from("piship-sandbox-ready " + (request.env.PISHIP_PROBE_UNLISTED ?? "unset") + "\\n"));
        return Promise.resolve({ exitCode: 0 });
      }
      if (log().failSeedOnce && request.command.includes("tar -xf")) {
        log().failSeedOnce = false;
        io.onStdout(Buffer.from("disk full\\n"));
        return Promise.resolve({ exitCode: 1 });
      }
      if (log().failDiff && request.command.includes("git diff")) return Promise.resolve({ exitCode: 1 });
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
}

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0))
    await session.close().catch(() => undefined);
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  delete (globalThis as { __pishipRemote?: Log }).__pishipRemote;
  vi.restoreAllMocks();
});

function context(prompts: string[] = []): ExtensionContext {
  return {
    hasUI: true,
    ui: {
      confirm: async (title: string) => {
        prompts.push(title);
        return true;
      },
      select: async (title: string) => {
        prompts.push(title);
        return undefined;
      },
      setStatus: () => {},
      notify: () => {},
    },
  } as unknown as ExtensionContext;
}

async function open(options: { subagent?: boolean } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-gov-rw-")));
  roots.push(root);
  log();
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const remote = join(root, "remote");
  mkdirSync(distribution, { recursive: true });
  mkdirSync(remote);
  mkdirSync(workspace);
  const sh = (...args: string[]) =>
    execFileSync("git", args, { cwd: workspace, stdio: "ignore" });
  sh("init", "-q");
  writeFileSync(join(workspace, "notes.txt"), "workspace notes\n");
  writeFileSync(join(workspace, "secret.env"), "TOKEN=1\n");
  writeFileSync(join(workspace, "ask.txt"), "ask me\n");
  sh("add", "-A");
  sh("-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-qm", "i");
  for (const path of ["sandbox/acme.mjs", "resources/sandbox/acme.mjs"]) {
    mkdirSync(dirname(join(distribution, path)), { recursive: true });
    writeFileSync(join(distribution, path), adapter(remote));
  }
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha6",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "1.5.0" }',
      "deployment: { mode: personal }",
      "policy:",
      "  id: unit",
      "  version: 1",
      "  default: deny",
      "  defaults:",
      '    - { id: nosecret, action: filesystem.read, resource: "workspace/secret.env", effect: deny }',
      '    - { id: nowrite, action: filesystem.write, resource: "workspace/locked.txt", effect: deny }',
      '    - { id: askfile, action: filesystem.read, resource: "workspace/ask.txt", effect: ask }',
      '    - { id: read, action: filesystem.read, resource: "workspace/**", effect: allow }',
      '    - { id: write, action: filesystem.write, resource: "workspace/**", effect: allow }',
      '    - { id: shell, action: shell.execute, resource: "**", effect: allow }',
      '    - { id: tools, action: tool.execute, resource: "*", effect: allow }',
      "sandbox:",
      "  required: true",
      "  provider: custom",
      "  adapter: ./sandbox/acme.mjs",
      "  workspace: remote",
      "  network: { mode: deny }",
      "  environment: { allow: [PATH] }",
      "updates:",
      "  channel: stable",
      "audit:",
      "  enabled: true",
      "  sinks:",
      "    - { id: local, type: file, required: false }",
      "",
    ].join("\n"),
  );
  const lock = resolveLock(manifest);
  const stateDir = join(root, "state");
  const session = await GovernanceSession.open({
    lock: lock as Parameters<typeof GovernanceSession.open>[0]["lock"],
    distributionDir: distribution,
    stateDir,
    cwd: workspace,
    piVersion: "1.5.0",
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: join(root, "home"),
    ...(options.subagent ? { subagent: { parentSession: "parent" } } : {}),
  });
  sessions.push(session);
  const tools = governedTools(session, workspace);
  const tool = (name: string) => {
    const found = tools.find((item) => item.name === name) as ToolDefinition;
    return (params: unknown, ctx = context()) =>
      found.execute(
        "call",
        params as never,
        undefined,
        undefined,
        ctx as never,
      );
  };
  return { session, root, workspace, remote, stateDir, tool };
}

const fileCalls = (path: string) =>
  log().files.filter((entry) => entry.path === path);

describe.skipIf(!posix || asRoot)("a remote workspace session", () => {
  it("uploads nothing at activation or in Plan mode, then seeds lazily and once, never prompting", async () => {
    const { session, workspace, remote, tool } = await open();
    expect(readdirSync(remote)).toEqual([]);
    expect(log().files).toEqual([]);
    session.workflowMode = "plan";
    await expect(
      tool("write")({ path: "p.txt", content: "x" }),
    ).rejects.toThrow(/Plan mode/);
    expect(readdirSync(remote)).toEqual([]);
    expect(log().files).toEqual([]);
    session.workflowMode = "build";

    const prompts: string[] = [];
    const first = await tool("read")({ path: "notes.txt" }, context(prompts));
    expect(JSON.stringify(first)).toContain("workspace notes");
    expect(readFileSync(join(remote, "notes.txt"), "utf8")).toBe(
      "workspace notes\n",
    );
    // `deny` and `ask` files are skipped, and nothing asked about them.
    expect(existsSync(join(remote, "secret.env"))).toBe(false);
    expect(existsSync(join(remote, "ask.txt"))).toBe(false);
    expect(prompts).toEqual([]);
    expect(existsSync(join(remote, ".git"))).toBe(true);
    await tool("read")({ path: "notes.txt" });
    expect(
      log().commands.filter((command) => command.includes("tar -xf")),
    ).toHaveLength(1);
    // The host working tree was not touched.
    expect(readFileSync(join(workspace, "notes.txt"), "utf8")).toBe(
      "workspace notes\n",
    );
  });

  it("never lets a denied or asked-and-refused path reach the sandbox files", async () => {
    const { tool } = await open();
    await tool("read")({ path: "notes.txt" });
    expect(log().files.length).toBeGreaterThan(0);
    // Denied read, asked-and-refused read (the answer is "no"), denied write,
    // and a path outside the project: each refused.
    await expect(tool("read")({ path: "secret.env" })).rejects.toThrow(
      /not allowed/,
    );
    await expect(tool("read")({ path: "ask.txt" })).rejects.toThrow();
    await expect(
      tool("write")({ path: "locked.txt", content: "x" }),
    ).rejects.toThrow(/not allowed/);
    await expect(tool("read")({ path: "/etc/hosts" })).rejects.toThrow();
    // No file call of any kind named any of them.
    for (const name of ["secret.env", "ask.txt", "locked.txt"])
      expect(fileCalls(name)).toEqual([]);
    expect(
      log().files.filter(
        (entry) => entry.path.includes("etc") || entry.path.includes("hosts"),
      ),
    ).toEqual([]);
  });

  it("writes and edits in the sandbox, not on the host", async () => {
    const { workspace, remote, tool } = await open();
    await tool("write")({ path: "out/new.txt", content: "hello\n" });
    expect(readFileSync(join(remote, "out", "new.txt"), "utf8")).toBe(
      "hello\n",
    );
    expect(existsSync(join(workspace, "out"))).toBe(false);
    await tool("edit")({
      path: "notes.txt",
      edits: [{ oldText: "workspace", newText: "remote" }],
    });
    expect(readFileSync(join(remote, "notes.txt"), "utf8")).toBe(
      "remote notes\n",
    );
    expect(readFileSync(join(workspace, "notes.txt"), "utf8")).toBe(
      "workspace notes\n",
    );
    await expect(
      tool("edit")({
        path: "missing.txt",
        edits: [{ oldText: "a", newText: "b" }],
      }),
    ).rejects.toThrow();
  });

  it("fails the call when the seed fails and seeds again on the next call", async () => {
    const { remote, tool } = await open();
    log().failSeedOnce = true;
    await expect(tool("read")({ path: "notes.txt" })).rejects.toThrow(
      /seeding the sandbox failed/,
    );
    await expect(tool("read")({ path: "notes.txt" })).resolves.toBeDefined();
    expect(existsSync(join(remote, ".git"))).toBe(true);
  });

  it("checkpoints after a turn and at the end, with protected paths, and a failed checkpoint never throws", async () => {
    const { session, workspace, stateDir, tool } = await open();
    const handlers = new Map<
      string,
      (event: unknown, ctx: unknown) => unknown
    >();
    const api = {
      on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) =>
        handlers.set(event, handler),
      registerCommand: () => {},
    } as never;
    const extension = governanceHooks(session);
    (typeof extension === "function" ? extension : extension.factory)(api);
    await tool("write")({ path: "out/new.txt", content: "hello\n" });
    await handlers.get("agent_end")?.({}, context());
    const paths = remoteWorkspacePaths(stateDir, workspace);
    expect(readFileSync(paths.patch, "utf8")).toContain("out/new.txt");
    const meta = JSON.parse(readFileSync(paths.meta, "utf8"));
    expect(meta.files).toBe(1);
    expect(meta.protectedPaths).toEqual(
      expect.arrayContaining([".git/hooks", ".git/config"]),
    );
    // A failing diff is a notice, and the earlier checkpoint stays.
    log().failDiff = true;
    await expect(
      handlers.get("agent_end")?.({}, context()),
    ).resolves.toBeUndefined();
    expect(readFileSync(paths.patch, "utf8")).toContain("out/new.txt");
    log().failDiff = false;
    await tool("write")({ path: "second.txt", content: "2\n" });
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    await session.close();
    expect(readFileSync(paths.patch, "utf8")).toContain("second.txt");
    expect(stderr.mock.calls.join("")).toContain(
      "The sandbox changed 2 files. Review and apply them with: unit sandbox pull",
    );
  });

  it("never replaces another session's unapplied patch: parks its own and tells the user", async () => {
    const { session, workspace, stateDir, tool } = await open();
    const handlers = new Map<
      string,
      (event: unknown, ctx: unknown) => unknown
    >();
    const extension = governanceHooks(session);
    (typeof extension === "function" ? extension : extension.factory)({
      on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) =>
        handlers.set(event, handler),
      registerCommand: () => {},
    } as never);
    const earlier = Buffer.from("EARLIER SESSION PATCH\n");
    const slot = writeRemoteWorkspaceCheckpoint(stateDir, workspace, earlier, {
      session: "earlier",
      baseHead: null,
      files: 3,
    });
    await tool("write")({ path: "mine.txt", content: "m\n" });
    await handlers.get("agent_end")?.({}, context());
    expect(readFileSync(slot.patch)).toEqual(earlier);
    expect(JSON.parse(readFileSync(slot.meta, "utf8")).session).toBe("earlier");
    const parked = remoteWorkspacePaths(
      join(stateDir, "sandbox-workspace-parked", session.sessionId),
      workspace,
    );
    expect(readFileSync(parked.patch, "utf8")).toContain("mine.txt");

    // Once the earlier patch is pulled or discarded, the next checkpoint
    // takes the slot and the parked copy goes.
    rmSync(slot.patch);
    rmSync(slot.meta);
    await tool("write")({ path: "more.txt", content: "m\n" });
    await handlers.get("agent_end")?.({}, context());
    expect(readFileSync(slot.patch, "utf8")).toContain("mine.txt");
    expect(existsSync(parked.dir)).toBe(false);

    // Blocked again at the end: the closing line says where the work is.
    writeRemoteWorkspaceCheckpoint(stateDir, workspace, earlier, {
      session: "earlier-2",
      baseHead: null,
      files: 1,
    });
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    await session.close();
    const line = stderr.mock.calls.join("");
    expect(line).toContain("an earlier session's changes are still waiting");
    expect(line).toContain("sandbox pull --discard");
    expect(line).toContain(parked.dir);
    expect(readFileSync(slot.patch)).toEqual(earlier);
  });

  it("never lets a subagent child write the parent's checkpoint", async () => {
    const { session, workspace, stateDir, tool } = await open({
      subagent: true,
    });
    await tool("write")({ path: "child.txt", content: "c\n" });
    await session.remote?.checkpoint();
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    await session.close();
    const paths = remoteWorkspacePaths(stateDir, workspace);
    expect(existsSync(paths.patch)).toBe(false);
    expect(existsSync(paths.meta)).toBe(false);
    expect(stderr.mock.calls.join("")).not.toContain("sandbox pull");
  });

  it("takes no checkpoint when the sandbox was never used", async () => {
    const { session, workspace, stateDir } = await open();
    await session.close();
    expect(existsSync(remoteWorkspacePaths(stateDir, workspace).patch)).toBe(
      false,
    );
  });
});
