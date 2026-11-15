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
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type {
  ExtensionContext,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import type { ManagedFetch } from "@piship/contracts";
import {
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
  resolveLock,
  writeRemoteWorkspaceCheckpoint,
  writeRemoteWorkspacePulled,
} from "@piship/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { governanceHooks } from "../builtins.js";
import { GovernanceSession } from "../governance-session.js";
import { governedBashOperations, governedTools } from "../governed-tools.js";
import {
  CACHE_NOTICE_OVERLAY,
  CACHE_NOTICE_SAVING,
  CACHE_NOTICE_SKIPPED,
} from "./cache.js";

const posix = process.platform !== "win32";
const asRoot = typeof process.getuid === "function" && process.getuid() === 0;

interface Log {
  files: { op: string; path: string }[];
  commands: string[];
  failSeedOnce?: boolean;
  failDiff?: boolean;
  gone?: boolean;
  /** Snapshot cache: what prepare was asked to start from, the snapshots made and deleted. */
  prepares: (string | null)[];
  snapshotsMade: string[];
  deleted: string[];
  /** The commands that had run when each snapshot was taken. */
  atSnapshot: string[][];
  snapshotFail?: "unsupported" | "error";
  /** Fail the extract once, as an overlay that cannot be applied. */
  failOverlay?: boolean;
  /** Hold the snapshot, or the overlay's extract, until the call is cancelled. */
  holdSnapshot?: boolean;
  holdOverlay?: boolean;
  next: number;
}
const log = (): Log =>
  ((globalThis as { __pishipRemote?: Log }).__pishipRemote ??= {
    files: [],
    commands: [],
    prepares: [],
    snapshotsMade: [],
    deleted: [],
    atSnapshot: [],
    next: 0,
  });

function adapter(remote: string): string {
  return `
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
const remote = ${JSON.stringify(remote)};
const snaps = remote + "-snapshots";
const log = () => globalThis.__pishipRemote;
export default () => ({
  id: "acme-remote",
  deleteSnapshot: async (id) => {
    log().deleted.push(id);
    rmSync(join(snaps, id), { recursive: true, force: true });
  },
  available: async () => ({ available: true }),
  capabilities: () => ({
    isolation: "remote",
    planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
    network: ["deny", "allow"],
    localProcesses: false,
  }),
  prepare: async (request) => {
    log().prepares.push(request.template ?? null);
    // A new sandbox: empty, or the snapshot's filesystem.
    for (const name of readdirSync(remote)) rmSync(join(remote, name), { recursive: true, force: true });
    if (request.template) {
      const from = join(snaps, request.template);
      if (!existsSync(from)) throw Object.assign(new Error("no such snapshot"), { code: "SNAPSHOT_GONE" });
      cpSync(from, remote, { recursive: true });
    }
    return {
    snapshot: async ({ signal }) => {
      if (log().holdSnapshot)
        await new Promise((_, reject) => signal.addEventListener("abort", () => reject(new Error("aborted"))));
      if (log().snapshotFail === "unsupported") throw Object.assign(new Error("no snapshots"), { code: "SNAPSHOT_UNSUPPORTED" });
      if (log().snapshotFail) throw new Error("HTTP 503");
      log().atSnapshot.push([...log().commands]);
      const id = "snap-" + ++log().next;
      mkdirSync(snaps, { recursive: true });
      cpSync(remote, join(snaps, id), { recursive: true });
      log().snapshotsMade.push(id);
      return { id };
    },
    files: {
      read: async (path) => {
        if (log().gone) throw Object.assign(new Error("raw"), { code: "SANDBOX_GONE" });
        log().files.push({ op: "read", path });
        try { return readFileSync(join(remote, path)); }
        catch (error) { throw Object.assign(new Error("no such file"), { code: "ENOENT" }); }
      },
      write: async (path, data) => {
        if (log().gone) throw Object.assign(new Error("raw"), { code: "SANDBOX_GONE" });
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
      if (log().gone && !request.command.includes("piship-sandbox-ready"))
        return Promise.reject(Object.assign(new Error("raw"), { code: "SANDBOX_GONE" }));
      if (request.command.includes("piship-sandbox-ready")) {
        io.onStdout(Buffer.from("piship-sandbox-ready " + (request.env.PISHIP_PROBE_UNLISTED ?? "unset") + "\\n"));
        return Promise.resolve({ exitCode: 0 });
      }
      if (log().holdOverlay && request.command.includes("piship-keep.idx"))
        return new Promise((resolve) => io.signal.addEventListener("abort", () => resolve({ exitCode: null })));
      if (log().failOverlay && request.command.includes("piship-keep.idx")) {
        log().failOverlay = false;
        io.onStdout(Buffer.from("snapshot damaged\\n"));
        return Promise.resolve({ exitCode: 1 });
      }
      if (log().failSeedOnce && request.command.includes("tar -xzf")) {
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
        io.signal.addEventListener("abort", () => child.kill(), { once: true });
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ exitCode: code, signal }));
      });
    },
    dispose: async () => {},
    };
  },
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

async function open(
  options: {
    subagent?: boolean;
    sandbox?: string[];
    setup?: (workspace: string) => void;
    /** A second session of the same project: same host files, state and distribution. */
    reuse?: { root: string };
  } = {},
) {
  const root =
    options.reuse?.root ??
    realpathSync(mkdtempSync(join(tmpdir(), "piship-gov-rw-")));
  if (!options.reuse) roots.push(root);
  log();
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const remote = join(root, "remote");
  const manifest = join(distribution, "piship.yaml");
  if (!options.reuse) {
    mkdirSync(distribution, { recursive: true });
    mkdirSync(remote);
    mkdirSync(workspace);
    const sh = (...args: string[]) =>
      execFileSync("git", args, { cwd: workspace, stdio: "ignore" });
    sh("init", "-q");
    writeFileSync(join(workspace, "notes.txt"), "workspace notes\n");
    writeFileSync(join(workspace, "secret.env"), "TOKEN=1\n");
    writeFileSync(join(workspace, "ask.txt"), "ask me\n");
    options.setup?.(workspace);
    sh("add", "-A");
    sh(
      "-c",
      "user.name=t",
      "-c",
      "user.email=t@x.invalid",
      "commit",
      "-qm",
      "i",
    );
    for (const path of ["sandbox/acme.mjs", "resources/sandbox/acme.mjs"]) {
      mkdirSync(dirname(join(distribution, path)), { recursive: true });
      writeFileSync(join(distribution, path), adapter(remote));
    }
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
        ...(options.sandbox ?? []),
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
  }
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
  // A custom adapter declares no workdir; the mapping of sandbox paths reads
  // the manifest's, as it does for the e2b-compatible provider's default.
  (session.manifest.sandbox as { workdir?: string }).workdir =
    "/home/user/workspace";
  const tools = governedTools(session, workspace);
  const tool = (name: string) => {
    const found = tools.find((item) => item.name === name) as ToolDefinition;
    return (params: unknown, ctx = context(), signal?: AbortSignal) =>
      found.execute("call", params as never, signal, undefined, ctx as never);
  };
  return { session, root, workspace, remote, stateDir, tool };
}

const fileCalls = (path: string) =>
  log().files.filter((entry) => entry.path === path);

const approving = (prompts: string[] = []) =>
  ({
    hasUI: true,
    ui: {
      confirm: async () => true,
      select: async (title: string, choices: string[]) => {
        prompts.push(title);
        return choices[0];
      },
      setStatus: () => {},
      notify: () => {},
    },
  }) as unknown as ExtensionContext;

describe.skipIf(!posix || asRoot)("a remote workspace session", () => {
  it("maps a path the sandbox printed to the project file, judged by policy as the host path", async () => {
    const { remote, tool } = await open();
    const sandboxRoot = "/home/user/workspace";
    expect(
      JSON.stringify(await tool("read")({ path: `${sandboxRoot}/notes.txt` })),
    ).toContain("workspace notes");
    await tool("write")({ path: `${sandboxRoot}/out/n.txt`, content: "n\n" });
    expect(readFileSync(join(remote, "out", "n.txt"), "utf8")).toBe("n\n");
    // The mapped path is the host path: its policy applies.
    await expect(
      tool("read")({ path: `${sandboxRoot}/secret.env` }),
    ).rejects.toThrow(/not allowed/);
    // Not on a segment boundary, or leaving the workdir: still outside.
    await expect(
      tool("read")({ path: `${sandboxRoot}2/notes.txt` }),
    ).rejects.toThrow();
    await expect(
      tool("read")({ path: `${sandboxRoot}/../../../etc/hosts` }),
    ).rejects.toThrow();
  });

  it("returns an image read from the sandbox as an image, reading the file once", async () => {
    const { remote, tool } = await open();
    await tool("read")({ path: "notes.txt" }); // seeds the sandbox first
    const png = Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
      "base64",
    );
    writeFileSync(join(remote, "pic.png"), png);
    writeFileSync(join(remote, "fake.png"), "not an image\n");
    const reads = () =>
      fileCalls("pic.png").filter((call) => call.op === "read").length;
    const before = reads();
    const result = (await tool("read")({ path: "pic.png" })) as {
      content: { type: string }[];
    };
    expect(result.content.map((block) => block.type)).toContain("image");
    expect(reads() - before).toBe(1);
    const text = (await tool("read")({ path: "fake.png" })) as {
      content: { type: string; text?: string }[];
    };
    expect(JSON.stringify(text)).toContain("not an image");
    expect(text.content.some((block) => block.type === "image")).toBe(false);
  });

  it("uploads a policy-withheld file once the user approves its read, and keeps it out of the patch unless changed", async () => {
    const { session, workspace, remote, stateDir, tool } = await open();
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
    await tool("read")({ path: "notes.txt" });
    expect(existsSync(join(remote, "ask.txt"))).toBe(false);
    const prompts: string[] = [];
    expect(
      JSON.stringify(
        await tool("read")({ path: "ask.txt" }, approving(prompts)),
      ),
    ).toContain("ask me");
    expect(prompts.length).toBeGreaterThan(0);
    expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe("ask me\n");
    await handlers.get("agent_end")?.({}, context());
    const paths = remoteWorkspacePaths(stateDir, workspace);
    // Seeded content is the baseline: nothing changed yet.
    expect(
      existsSync(paths.patch) ? readFileSync(paths.patch, "utf8") : "",
    ).toBe("");
    await tool("edit")(
      { path: "ask.txt", edits: [{ oldText: "ask me", newText: "asked" }] },
      approving(),
    );
    await handlers.get("agent_end")?.({}, context());
    const patch = readFileSync(paths.patch, "utf8");
    expect(patch).toContain("-ask me");
    expect(patch).toContain("+asked");
    expect(patch).not.toContain("new file mode");
  });

  it("edits a policy-withheld file straight away once the read is approved", async () => {
    const { remote, tool } = await open();
    await tool("edit")(
      { path: "ask.txt", edits: [{ oldText: "ask me", newText: "done" }] },
      approving(),
    );
    expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe("done\n");
  });

  it("tells the user what to do when the sandbox expired, in every tool", async () => {
    const { session, workspace, tool } = await open();
    await tool("read")({ path: "notes.txt" });
    log().gone = true;
    const message =
      /The sandbox expired or was lost\. Changes up to the last checkpoint are saved: exit, run unit sandbox pull/;
    await expect(tool("read")({ path: "notes.txt" })).rejects.toThrow(message);
    await expect(
      tool("write")({ path: "w.txt", content: "x" }),
    ).rejects.toThrow(message);
    await expect(
      governedBashOperations(session, "bash").exec("ls", workspace, {
        onData: () => {},
      }),
    ).rejects.toThrow(message);
  });

  it("says why a file is not in the sandbox", async () => {
    const { tool } = await open({
      sandbox: ["  remote: { seed: { maxFileMiB: 1 } }"],
      setup: (workspace) =>
        writeFileSync(
          join(workspace, "big.bin"),
          Buffer.alloc(2 * 1024 * 1024),
        ),
    });
    await expect(tool("read")({ path: "big.bin" })).rejects.toThrow(
      /big\.bin is not in the sandbox: it is over the per-file upload cap/,
    );
  });

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
      log().commands.filter((command) => command.includes("tar -xzf")),
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
      "2 files changed in the sandbox; run unit sandbox pull to bring them to this machine",
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
    expect(line).toContain(
      "An earlier session's changes are waiting too; run unit sandbox pull once for each.",
    );
    expect(line).not.toContain("move");
    expect(readFileSync(slot.patch)).toEqual(earlier);
  });

  it("tells the user at start about unapplied changes, and the agent about the remote workspace", async () => {
    const { session, workspace, stateDir } = await open();
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
    const notices: string[] = [];
    const ui = {
      ...context(),
      ui: {
        ...context().ui,
        notify: (message: string) => notices.push(message),
      },
    };
    const sections: Record<string, string> = {};
    handlers.get("before_agent_start")?.(
      { systemPromptOptions: { sections } },
      ui,
    );
    expect(sections.piship_remote_workspace).toMatch(
      /remote sandbox at \/home\/user\/workspace.*`unit sandbox pull`.*single baseline commit.*Changes made by subagents are discarded/,
    );

    for (const [state, id, files] of [
      [stateDir, "one", 2],
      [join(stateDir, "sandbox-workspace-parked", "two"), "two", 1],
    ] as const)
      writeRemoteWorkspaceCheckpoint(state, workspace, Buffer.from("P\n"), {
        session: id,
        baseHead: null,
        files,
      });
    handlers.get("session_start")?.({}, ui);
    handlers.get("session_start")?.({}, ui);
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatch(
      /^Earlier sandbox changes to 3 files \(saved .* UTC\) are still waiting\. Run unit sandbox pull first; this session starts from your host files\.$/,
    );
  });

  it("tells a subagent child its changes are discarded", async () => {
    const { session } = await open({ subagent: true });
    const sections: Record<string, string> = {};
    const extension = governanceHooks(session);
    (typeof extension === "function" ? extension : extension.factory)({
      on: (event: string, handler: (event: unknown) => unknown) => {
        if (event === "before_agent_start")
          handler({ systemPromptOptions: { sections } });
      },
      registerCommand: () => {},
    } as never);
    expect(sections.piship_remote_workspace).toContain(
      "You are a subagent: your file changes are discarded when you finish, so report findings or patch text instead of editing files.",
    );
  });

  it("offers background tasks, which run in the sandbox", async () => {
    const { tool } = await open();
    const started = await tool("task_start")({ command: "echo hi" }, {
      ...context(),
      sessionManager: SessionManager.inMemory(tmpdir()),
    } as never);
    expect(JSON.stringify(started)).not.toContain("run on this machine");
    expect(log().commands.some((command) => command.includes("tar -xzf"))).toBe(
      true,
    );
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

/** The session's hooks, with a UI whose notices are collected. */
function hooks(session: GovernanceSession) {
  const handlers = new Map<
    string,
    (event: unknown, ctx: unknown) => Promise<unknown> | unknown
  >();
  const extension = governanceHooks(session);
  (typeof extension === "function" ? extension : extension.factory)({
    on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) =>
      handlers.set(event, handler),
    registerCommand: () => {},
  } as never);
  const notices: string[] = [];
  const ui = {
    ...context(),
    ui: { ...context().ui, notify: (message: string) => notices.push(message) },
  };
  handlers.get("session_start")?.({}, ui);
  const sections: Record<string, string> = {};
  return {
    notices,
    sections,
    /** A turn's start: returns the message the model gets, if any. */
    turn: async () =>
      (await handlers.get("before_agent_start")?.(
        { systemPromptOptions: { sections } },
        ui,
      )) as { message?: { content: string } } | undefined,
    end: () => handlers.get("agent_end")?.({}, ui),
    message: (event: unknown) => handlers.get("message_end")?.(event, ui),
  };
}

const patchOf = (stateDir: string, workspace: string) => {
  const paths = remoteWorkspacePaths(stateDir, workspace);
  return existsSync(paths.patch) ? readFileSync(paths.patch, "utf8") : "";
};
const refreshNotices = (notices: string[]) =>
  notices.filter((line) => /changed on this machine|^Sent /.test(line));

describe.skipIf(!posix || asRoot)("host edits during a remote session", () => {
  const read = async (tool: (p: unknown) => Promise<unknown>, path: string) =>
    JSON.stringify(await tool({ path }));

  it("sends a file the user changed on this machine, keeps it out of the patch, and tells the model", async () => {
    const { session, workspace, remote, stateDir, tool } = await open();
    const h = hooks(session);
    await read(tool("read"), "notes.txt");
    writeFileSync(join(workspace, "notes.txt"), "fixed in the IDE\n");
    writeFileSync(join(workspace, "fresh.txt"), "new file\n");
    const result = await h.turn();
    expect(readFileSync(join(remote, "notes.txt"), "utf8")).toBe(
      "fixed in the IDE\n",
    );
    expect(readFileSync(join(remote, "fresh.txt"), "utf8")).toBe("new file\n");
    expect(h.notices).toContain(
      "Sent 2 files you changed on this machine to the sandbox",
    );
    expect(result?.message?.content).toContain("notes.txt");
    await h.end();
    expect(patchOf(stateDir, workspace)).toBe("");
    // Nothing changed since: a quiet turn.
    expect(await h.turn()).toBeUndefined();
    expect(refreshNotices(h.notices)).toHaveLength(1);
    // The agent's own later edit is the only change in the patch.
    await tool("edit")({
      path: "notes.txt",
      edits: [{ oldText: "IDE", newText: "editor" }],
    });
    await h.end();
    const patch = patchOf(stateDir, workspace);
    expect(patch).toContain("+fixed in the editor");
    expect(patch).not.toContain("new file");
  });

  it("applies a host deletion the agent did not touch", async () => {
    const { session, workspace, remote, stateDir, tool } = await open();
    const h = hooks(session);
    await read(tool("read"), "notes.txt");
    rmSync(join(workspace, "notes.txt"));
    await h.turn();
    expect(existsSync(join(remote, "notes.txt"))).toBe(false);
    await h.end();
    expect(patchOf(stateDir, workspace)).toBe("");
  });

  it("sends a file the seed left out as too large once the user shrinks it, and not before", async () => {
    const { session, workspace, remote, tool } = await open({
      sandbox: ["  remote: { seed: { maxFileMiB: 1 } }"],
      setup: (workspace) =>
        writeFileSync(join(workspace, "big.txt"), "x".repeat(2 * 1024 * 1024)),
    });
    const h = hooks(session);
    await read(tool("read"), "notes.txt");
    expect(existsSync(join(remote, "big.txt"))).toBe(false);
    expect(await h.turn()).toBeUndefined();
    expect(existsSync(join(remote, "big.txt"))).toBe(false);
    writeFileSync(join(workspace, "big.txt"), "now small\n");
    await h.turn();
    expect(readFileSync(join(remote, "big.txt"), "utf8")).toBe("now small\n");
  });

  it("keeps the sandbox copy when the agent changed the same file, and says so once", async () => {
    const { session, workspace, remote, tool } = await open();
    const h = hooks(session);
    await tool("write")({ path: "notes.txt", content: "agent version\n" });
    writeFileSync(join(workspace, "notes.txt"), "user version\n");
    const result = await h.turn();
    expect(readFileSync(join(remote, "notes.txt"), "utf8")).toBe(
      "agent version\n",
    );
    const line =
      "notes.txt changed on this machine and in the sandbox; the sandbox copy is kept. `unit sandbox pull` will merge or flag it.";
    expect(refreshNotices(h.notices)).toEqual([line]);
    expect(result?.message?.content).toContain("your copy was kept");
    writeFileSync(join(workspace, "notes.txt"), "user version two\n");
    await h.turn();
    expect(refreshNotices(h.notices)).toEqual([line]);
  });

  it("treats a file a mid-session pull wrote to the host as in sync", async () => {
    const { session, workspace, remote, stateDir, tool } = await open();
    const h = hooks(session);
    await tool("write")({ path: "notes.txt", content: "agent version\n" });
    await h.end();
    const checkpoint = readRemoteWorkspaceCheckpoint(stateDir, workspace);
    expect(checkpoint?.patch.length).toBeGreaterThan(0);
    // What `sandbox pull` does: the patch lands on the host, and a marker names the commit.
    writeFileSync(join(workspace, "notes.txt"), "agent version\n");
    writeRemoteWorkspacePulled(stateDir, workspace, {
      session: session.sessionId,
      checkpointCommit: checkpoint?.meta.checkpointCommit ?? "",
    });
    expect(await h.turn()).toBeUndefined();
    expect(refreshNotices(h.notices)).toEqual([]);
    await session.remote?.checkpoint(true);
    expect(patchOf(stateDir, workspace)).toBe("");
    // After the baseline moved, a later host edit still reaches the sandbox.
    writeFileSync(join(workspace, "notes.txt"), "agent version, then user\n");
    await h.turn();
    expect(readFileSync(join(remote, "notes.txt"), "utf8")).toBe(
      "agent version, then user\n",
    );
    await h.end();
    expect(patchOf(stateDir, workspace)).toBe("");
  });

  it("does nothing with sandbox.remote.refresh: off", async () => {
    const { session, workspace, remote, tool } = await open({
      sandbox: ["  remote: { refresh: off }"],
    });
    const h = hooks(session);
    await read(tool("read"), "notes.txt");
    writeFileSync(join(workspace, "notes.txt"), "fixed in the IDE\n");
    await h.turn();
    expect(readFileSync(join(remote, "notes.txt"), "utf8")).toBe(
      "workspace notes\n",
    );
    expect(h.sections.piship_remote_workspace).toContain(
      "Edits the user makes on their machine during this session are not visible to you.",
    );
  });

  it("warns once and carries on when the sandbox cannot be reached", async () => {
    const { session, workspace, tool } = await open();
    const h = hooks(session);
    await read(tool("read"), "notes.txt");
    writeFileSync(join(workspace, "notes.txt"), "fixed in the IDE\n");
    log().gone = true;
    await h.turn();
    await h.turn();
    expect(
      h.notices.filter((line) =>
        line.startsWith("Edits you made on this machine"),
      ),
    ).toHaveLength(1);
  });
});

describe.skipIf(!posix || asRoot)("sandbox.remote.setup", () => {
  const withLock = (workspace: string) => {
    writeFileSync(join(workspace, "lock.txt"), "lock\n");
    writeFileSync(join(workspace, ".gitignore"), "deps/\n");
  };

  it("runs once after the seed and folds its tracked-file changes into the baseline", async () => {
    const { session, workspace, remote, stateDir, tool } = await open({
      setup: withLock,
      sandbox: [
        '  remote: { setup: "mkdir deps && echo d > deps/a && echo rewritten >> lock.txt" }',
      ],
    });
    const h = hooks(session);
    await tool("read")({ path: "notes.txt" });
    await tool("read")({ path: "notes.txt" });
    expect(h.notices.filter((l) => l.startsWith("Running setup"))).toEqual([
      "Running setup in the sandbox: mkdir deps && echo d > deps/a && echo rewritten >> lock.txt",
    ]);
    expect(h.notices.some((l) => l.startsWith("Setup changed 1 file"))).toBe(
      true,
    );
    expect(readFileSync(join(remote, "deps", "a"), "utf8")).toBe("d\n");
    await tool("write")({ path: "out.txt", content: "agent\n" });
    await h.end();
    const patch = patchOf(stateDir, workspace);
    expect(patch).toContain("+agent");
    expect(patch).not.toContain("rewritten");
    expect(patch).not.toContain("deps");
    await h.turn();
    expect(h.sections.piship_remote_workspace).toContain(
      "ran once after the upload",
    );
  });

  it("is cancelled by Esc in a file tool, takes no snapshot of it, and runs again on the next call", async () => {
    const { session, workspace, remote, tool } = await open({
      setup: withLock,
      sandbox: [
        '  remote: { setup: "test -e go || exec sleep 30", cacheKeyFiles: ["lock.txt"], cache: snapshot }',
      ],
    });
    const h = hooks(session);
    const abort = new AbortController();
    const writing = tool("write")(
      { path: "out.txt", content: "agent\n" },
      context(),
      abort.signal,
    ).catch((error: unknown) => error);
    for (
      let i = 0;
      i < 500 && !log().commands.includes("test -e go || exec sleep 30");
      i++
    )
      await new Promise((done) => setTimeout(done, 10));
    abort.abort();
    expect(String(await writing)).toMatch(/cancelled.*next tool call/);
    expect(existsSync(join(remote, "out.txt"))).toBe(false);
    expect(existsSync(join(workspace, "out.txt"))).toBe(false);
    expect(log().snapshotsMade).toEqual([]);
    expect(h.notices.some((l) => l.startsWith("Setup failed"))).toBe(false);
    writeFileSync(join(remote, "go"), "");
    await tool("read")({ path: "notes.txt" });
    expect(h.notices.filter((l) => l.startsWith("Running setup"))).toHaveLength(
      2,
    );
    expect(log().snapshotsMade).toHaveLength(1);
  });

  it("warns with the exit code and last lines when it fails, and tells the model", async () => {
    const { session, tool } = await open({
      sandbox: ['  remote: { setup: "echo no registry; exit 3" }'],
    });
    const h = hooks(session);
    await tool("read")({ path: "notes.txt" });
    const failed = h.notices.find((l) => l.startsWith("Setup failed"));
    expect(failed).toContain("echo no registry; exit 3 (exit 3)");
    expect(failed).toContain("no registry");
    await h.turn();
    expect(h.sections.piship_remote_workspace).toContain(
      "The setup command failed",
    );
  });
});

describe.skipIf(!posix || asRoot)("a subagent child's changes", () => {
  const final = {
    role: "assistant",
    content: [{ type: "text", text: "done" }],
  };
  it("are reported to the parent in the final message once it wrote", async () => {
    const { session, tool } = await open({ subagent: true });
    const h = hooks(session);
    expect(h.message({ message: final })).toBeUndefined();
    await tool("write")({ path: "child.txt", content: "c\n" });
    const midway = {
      role: "assistant",
      content: [{ type: "toolCall", id: "1", name: "write", arguments: {} }],
    };
    expect(h.message({ message: midway })).toBeUndefined();
    const out = h.message({ message: final }) as {
      message: { content: { text: string }[] };
    };
    expect(out.message.content.at(-1)?.text).toBe(
      "\n\nNote: this subagent's file changes were not kept (remote workspace). Apply them from its report.",
    );
  });

  it("are not mentioned for the parent session itself", async () => {
    const { session, tool } = await open();
    const h = hooks(session);
    await tool("write")({ path: "p.txt", content: "p\n" });
    expect(h.message({ message: final })).toBeUndefined();
  });
});

describe.skipIf(!posix || asRoot)("sandbox.remote.cache", () => {
  const SETUP =
    "mkdir -p node_modules/x && echo d > node_modules/x/a && echo built >> lock.txt";
  const withFiles = (workspace: string) => {
    writeFileSync(join(workspace, "lock.txt"), "lock\n");
    writeFileSync(join(workspace, "old.txt"), "old\n");
    writeFileSync(join(workspace, ".gitignore"), "node_modules/\n");
  };
  const remoteLine = (cache = "snapshot", setup = SETUP) =>
    `  remote: { setup: "${setup}", cacheKeyFiles: ["lock.txt"], cache: ${cache} }`;
  const started = async (
    first: Awaited<ReturnType<typeof open>>,
  ): Promise<ReturnType<typeof hooks>> => {
    const h = hooks(first.session);
    await first.tool("read")({ path: "notes.txt" });
    return h;
  };
  const cacheJson = (stateDir: string, workspace: string) =>
    join(remoteWorkspacePaths(stateDir, workspace).dir, "cache.json");
  const stored = (stateDir: string, workspace: string) =>
    JSON.parse(readFileSync(cacheJson(stateDir, workspace), "utf8"));
  const saved = "Saved the sandbox setup; the next session starts from it.";

  it("saves after a successful setup and before the agent's first command or write", async () => {
    const first = await open({
      setup: withFiles,
      sandbox: [remoteLine()],
    });
    const h = await started(first);
    expect(log().snapshotsMade).toEqual(["snap-1"]);
    // Only the seed and the setup command had run: nothing of the agent's.
    const before = log().atSnapshot[0] ?? [];
    expect(before.at(-1)).toContain("piship-baseline");
    expect(before.some((c) => c.includes(SETUP))).toBe(true);
    expect(before.some((c) => c.includes("agent-ran"))).toBe(false);
    expect(
      first.session.remote?.touched,
      "nothing ran before the snapshot",
    ).toBe(false);
    await first.tool("write")({ path: "agent.txt", content: "agent-ran\n" });
    expect(h.notices.filter((l) => l === saved)).toHaveLength(1);
    const file = cacheJson(first.stateDir, first.workspace);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(stored(first.stateDir, first.workspace)).toMatchObject({
      version: 1,
      snapshotId: "snap-1",
      key: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(readFileSync(file, "utf8")).not.toMatch(/token|secret|password/i);
    // The agent's file is not in the snapshot.
    expect(
      existsSync(join(first.root, "remote-snapshots", "snap-1", "agent.txt")),
    ).toBe(false);
    expect(
      existsSync(
        join(
          first.root,
          "remote-snapshots",
          "snap-1",
          "node_modules",
          "x",
          "a",
        ),
      ),
    ).toBe(true);
  });

  it("saves the snapshot when the session's first action is a background task", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    await first.tool("task_start")({ command: "echo hi" }, {
      ...context(),
      sessionManager: SessionManager.inMemory(tmpdir()),
    } as never);
    expect(log().snapshotsMade).toEqual(["snap-1"]);
    expect(stored(first.stateDir, first.workspace)).toMatchObject({
      snapshotId: "snap-1",
    });
  });

  it("starts the next session from the snapshot, overlays the host files and runs no setup", async () => {
    const first = await open({
      setup: withFiles,
      sandbox: [remoteLine()],
    });
    await started(first);
    // The host changed meanwhile: a file deleted, another edited, a new one.
    rmSync(join(first.workspace, "old.txt"));
    writeFileSync(join(first.workspace, "notes.txt"), "newer notes\n");
    writeFileSync(join(first.workspace, "added.txt"), "added\n");
    // A file the snapshot holds that the policy now withholds from the upload.
    writeFileSync(
      join(first.root, "remote-snapshots", "snap-1", "secret.env"),
      "TOKEN=1\n",
    );
    log().commands.length = 0;
    const second = await open({ reuse: first });
    const h = await started(second);
    expect(log().prepares).toEqual([null, "snap-1"]);
    expect(log().commands.some((c) => c.includes(SETUP))).toBe(false);
    expect(h.notices.some((l) => l.startsWith("Running setup"))).toBe(false);
    expect(log().snapshotsMade).toEqual(["snap-1"]);
    const sandbox = (path: string) => join(first.remote, path);
    expect(readFileSync(sandbox("notes.txt"), "utf8")).toBe("newer notes\n");
    expect(existsSync(sandbox("added.txt"))).toBe(true);
    expect(existsSync(sandbox("old.txt"))).toBe(false);
    expect(existsSync(sandbox("secret.env"))).toBe(false);
    // The setup output the snapshot carries is still there, ignored.
    expect(readFileSync(sandbox("node_modules/x/a"), "utf8")).toBe("d\n");
    // One baseline commit, and nothing of the overlay is a change.
    const commits = execFileSync("git", ["rev-list", "--count", "HEAD"], {
      cwd: first.remote,
      encoding: "utf8",
    });
    expect(commits.trim()).toBe("1");
    expect(existsSync(sandbox(".piship-seed.keep"))).toBe(false);
    expect(existsSync(sandbox(".piship-seed.started"))).toBe(false);
    await h.turn();
    expect(h.sections.piship_remote_workspace).toContain(
      "restored from a cache",
    );
    await second.session.remote?.checkpoint(true);
    expect(patchOf(second.stateDir, second.workspace)).toBe("");
    // Later work is the only change in the patch.
    await second.tool("write")({ path: "later.txt", content: "later\n" });
    await second.session.remote?.checkpoint(true);
    const patch = patchOf(second.stateDir, second.workspace);
    expect(patch).toContain("+later");
    expect(patch).not.toContain("node_modules");
    expect(patch).not.toContain("added.txt");
  });

  it("rebuilds and deletes the old snapshot when a key file changes", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    await started(first);
    writeFileSync(join(first.workspace, "lock.txt"), "lock 2\n");
    const second = await open({ reuse: first });
    const h = await started(second);
    expect(log().prepares).toEqual([null, null]);
    expect(h.notices.some((l) => l.startsWith("Running setup"))).toBe(true);
    expect(log().snapshotsMade).toEqual(["snap-1", "snap-2"]);
    expect(log().deleted).toEqual(["snap-1"]);
    expect(stored(first.stateDir, first.workspace).snapshotId).toBe("snap-2");
  });

  it("falls back to the base template once, with one notice, when the snapshot is gone", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    await started(first);
    rmSync(join(first.root, "remote-snapshots"), { recursive: true });
    const second = await open({ reuse: first });
    const h = await started(second);
    expect(log().prepares).toEqual([null, "snap-1", null]);
    expect(
      h.notices.filter(
        (l) =>
          l ===
          "The cached sandbox setup was no longer available; setting up again.",
      ),
    ).toHaveLength(1);
    expect(h.notices.some((l) => l.startsWith("Running setup"))).toBe(true);
    // A fresh snapshot replaces the lost one.
    expect(stored(first.stateDir, first.workspace).snapshotId).toBe("snap-2");
  });

  it("cleans the sandbox, sets up again and drops the snapshot when the overlay fails", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    await started(first);
    log().failOverlay = true;
    const second = await open({ reuse: first });
    const h = await started(second);
    expect(log().prepares).toEqual([null, "snap-1"]);
    expect(
      h.notices.filter(
        (l) =>
          l ===
          "The cached sandbox setup could not be applied; setting up again.",
      ),
    ).toHaveLength(1);
    expect(h.notices.some((l) => l.startsWith("Running setup"))).toBe(true);
    expect(readFileSync(join(first.remote, "node_modules/x/a"), "utf8")).toBe(
      "d\n",
    );
    // A sandbox that fell back is not saved, and the unusable snapshot goes.
    expect(log().snapshotsMade).toEqual(["snap-1"]);
    expect(log().deleted).toEqual(["snap-1"]);
    expect(existsSync(cacheJson(first.stateDir, first.workspace))).toBe(false);
    await second.session.remote?.checkpoint(true);
    expect(patchOf(second.stateDir, second.workspace)).toBe("");
  });

  const until = async (found: () => boolean) => {
    for (let i = 0; i < 500 && !found(); i++)
      await new Promise((done) => setTimeout(done, 10));
    expect(found()).toBe(true);
  };

  it("says when a save takes a while, and Esc skips it: no cache entry, the sandbox keeps working, the next session sets up again", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    const h = hooks(first.session);
    log().holdSnapshot = true;
    const abort = new AbortController();
    const reading = first
      .tool("read")({ path: "notes.txt" }, context(), abort.signal)
      .catch(() => undefined);
    await until(() => h.notices.includes(CACHE_NOTICE_SAVING));
    abort.abort();
    await reading;
    expect(h.notices).toContain(CACHE_NOTICE_SKIPPED);
    expect(h.notices.some((l) => l.includes("could not be saved"))).toBe(false);
    expect(log().snapshotsMade).toEqual([]);
    expect(existsSync(cacheJson(first.stateDir, first.workspace))).toBe(false);
    // Seeded: the next call neither sets up nor saves again.
    log().holdSnapshot = false;
    await first.tool("read")({ path: "notes.txt" });
    expect(h.notices.filter((l) => l.startsWith("Running setup"))).toHaveLength(
      1,
    );
    const second = await open({ reuse: first });
    const again = await started(second);
    expect(log().prepares).toEqual([null, null]);
    expect(again.notices.some((l) => l.startsWith("Running setup"))).toBe(true);
  });

  it("keeps the cache when the overlay is cancelled, and overlays it on the next call", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    await started(first);
    const second = await open({ reuse: first });
    const h = hooks(second.session);
    log().holdOverlay = true;
    const abort = new AbortController();
    const reading = second
      .tool("read")({ path: "notes.txt" }, context(), abort.signal)
      .catch((error: unknown) => error);
    await until(() =>
      log().commands.some((c) => c.includes("piship-keep.idx")),
    );
    abort.abort();
    // Pi's read reports its own "aborted" for a cancelled call.
    expect(await reading).toBeInstanceOf(Error);
    expect(h.notices).not.toContain(CACHE_NOTICE_OVERLAY);
    expect(log().deleted).toEqual([]);
    expect(stored(first.stateDir, first.workspace).snapshotId).toBe("snap-1");
    log().holdOverlay = false;
    await second.tool("read")({ path: "notes.txt" });
    expect(h.notices.some((l) => l.startsWith("Running setup"))).toBe(false);
    expect(log().deleted).toEqual([]);
  });

  it("takes no snapshot when setup fails, without a setup command, or with cache: off", async () => {
    const failing = await open({
      sandbox: [remoteLine("snapshot", "echo no; exit 3")],
    });
    await started(failing);
    expect(log().snapshotsMade).toEqual([]);
    expect(existsSync(cacheJson(failing.stateDir, failing.workspace))).toBe(
      false,
    );
    const bare = await open({ sandbox: ["  remote: { cache: snapshot }"] });
    await started(bare);
    expect(log().snapshotsMade).toEqual([]);
    const off = await open({ sandbox: [remoteLine("off")] });
    await started(off);
    expect(log().snapshotsMade).toEqual([]);
    expect(existsSync(cacheJson(off.stateDir, off.workspace))).toBe(false);
  });

  it("remembers an unsupported backend for a day, silently", async () => {
    log().snapshotFail = "unsupported";
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    const h = await started(first);
    expect(h.notices.some((l) => /snapshot|sandbox setup/i.test(l))).toBe(
      false,
    );
    const state = stored(first.stateDir, first.workspace);
    expect(state.snapshotId).toBeUndefined();
    expect(Date.parse(state.unsupportedUntil) - Date.now()).toBeGreaterThan(
      23 * 3600 * 1000,
    );
    // Even a backend that would now answer is not asked.
    delete log().snapshotFail;
    const second = await open({ reuse: first });
    await started(second);
    expect(log().snapshotsMade).toEqual([]);
  });

  it("warns once when saving fails and tries again next session", async () => {
    log().snapshotFail = "error";
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    const h = await started(first);
    await first.tool("write")({ path: "a.txt", content: "a\n" });
    expect(
      h.notices.filter((l) =>
        l.startsWith("The sandbox setup could not be saved"),
      ),
    ).toHaveLength(1);
    expect(existsSync(cacheJson(first.stateDir, first.workspace))).toBe(false);
    delete log().snapshotFail;
    const second = await open({ reuse: first });
    await started(second);
    expect(log().snapshotsMade).toEqual(["snap-1"]);
  });

  it("ignores a damaged, malformed or expired cache.json", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    await started(first);
    const file = cacheJson(first.stateDir, first.workspace);
    const good = stored(first.stateDir, first.workspace);
    const second = async (content: string) => {
      writeFileSync(file, content);
      log().prepares.length = 0;
      await started(await open({ reuse: first }));
      return [...log().prepares];
    };
    expect(await second("{not json")).toEqual([null]);
    expect(
      await second(JSON.stringify({ ...good, snapshotId: "../x" })),
    ).toEqual([null]);
    expect(
      await second(JSON.stringify({ ...good, snapshotId: "a b" })),
    ).toEqual([null]);
    expect(await second(JSON.stringify({ ...good, key: "abc" }))).toEqual([
      null,
    ]);
    expect(await second(JSON.stringify({ ...good, version: 2 }))).toEqual([
      null,
    ]);
    // Expired: not used, and replaced with a new snapshot, deleting the old.
    const old = new Date(Date.now() - 8 * 24 * 3600 * 1000).toISOString();
    const before = [...log().deleted];
    expect(await second(JSON.stringify({ ...good, createdAt: old }))).toEqual([
      null,
    ]);
    expect(log().deleted.length).toBeGreaterThan(before.length);
    // Fresh and valid: used.
    writeFileSync(
      file,
      JSON.stringify(stored(first.stateDir, first.workspace)),
    );
    log().prepares.length = 0;
    await started(await open({ reuse: first }));
    expect(log().prepares).toHaveLength(1);
    expect(log().prepares[0]).toMatch(/^snap-/);
  });

  it("does not use the cache for a subagent child", async () => {
    const first = await open({ setup: withFiles, sandbox: [remoteLine()] });
    await started(first);
    log().prepares.length = 0;
    const child = await open({ reuse: first, subagent: true });
    await started(child);
    expect(log().prepares).toEqual([null]);
  });
});
