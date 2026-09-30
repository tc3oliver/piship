import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type ActivationContext,
  activateSandbox,
  describeContainment,
} from "./activate.js";
import {
  capabilityMismatch,
  claimedGuarantees,
  requiredPlanes,
  type SandboxCapabilities,
  type SandboxExecIO,
  type SandboxExecResult,
  type SandboxWorkspaceDeclaration,
  workspaceDeclaration,
} from "./backend.js";
import type { ProtectedPaths, SandboxPolicy } from "./profile.js";
import { selectAdapter } from "./select.js";
import { fakeWrappingBackend } from "./testing/fake-backend.js";
import {
  runShell,
  sharedBackend,
  snapshotBackend,
  syncedBackend,
  type WorkspaceFake,
  workspaceCapabilities,
} from "./testing/workspace-fakes.js";
import {
  describeWorkspace,
  gitControlUnproven,
  hooksInWorkingTree,
  missingControlFileInWritablePath,
  missingControlFiles,
  missingFilesWarning,
  removeSentinelDirectory,
  WORKSPACE_VALIDITY_MS,
  type WorkspaceReport,
} from "./workspace.js";

const posix = process.platform !== "win32";
const root_ = typeof process.getuid === "function" && process.getuid() === 0;

const policy = (overrides: Partial<SandboxPolicy> = {}): SandboxPolicy => ({
  required: true,
  filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: { allow: ["LANG"] },
  ...overrides,
});

const HOOK = "#!/bin/sh\necho hook\n";
const CONFIG = "[core]\n\tbare = false\n";
const NONCE = /^[0-9a-f]{32}$/;
const TIME = Date.parse("2026-09-29T12:00:00Z");

let root: string;
let workspace: string;
let git: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-workspace-")));
  workspace = join(root, "ws");
  git = join(workspace, ".git");
  mkdirSync(join(git, "hooks"), { recursive: true });
  mkdirSync(join(workspace, "sub"));
  writeFileSync(join(git, "config"), CONFIG);
  writeFileSync(join(git, "hooks", "pre-commit"), HOOK);
  writeFileSync(join(workspace, "README.md"), "hello\n");
});
afterEach(() => {
  // Undo read-only modes a protection test set, then remove everything.
  for (const path of [
    workspace,
    git,
    join(git, "hooks"),
    join(git, "info"),
    join(workspace, ".husky"),
    join(workspace, ".husky", "_"),
  ])
    if (existsSync(path)) chmodSync(path, 0o755);
  if (existsSync(join(git, "config"))) chmodSync(join(git, "config"), 0o644);
  rmSync(root, { recursive: true, force: true });
});

/**
 * The git control paths as the governance session passes them: the config
 * exists, `commondir` and `config.worktree` normally do not.
 */
const gitProtection = (): ProtectedPaths => ({
  files: [
    join(git, "config"),
    join(git, "config.worktree"),
    join(git, "commondir"),
  ],
  directories: [join(git, "hooks"), join(git, "info")],
});

/** Only the protected files that exist: what a backend guarding them by path does. */
const existingProtection = (): ProtectedPaths => ({
  files: [join(git, "config")],
  directories: [join(git, "hooks"), join(git, "info")],
});

const activate = (
  fake: WorkspaceFake,
  extra: Partial<ActivationContext> = {},
  config: SandboxPolicy = policy(),
) =>
  activateSandbox(config, {
    workspace,
    homeDir: join(root, "home"),
    backend: fake.backend,
    env: { PATH: "/usr/bin", LANG: "C.UTF-8" },
    settleMs: 200,
    ...extra,
  });

type Active = Awaited<ReturnType<typeof activateSandbox>>;

const run = async (sandbox: Active, command: string, signal?: AbortSignal) => {
  let output = "";
  const result = await sandbox.exec(command, workspace, {
    onData: (chunk) => {
      output += chunk.toString("utf8");
    },
    ...(signal ? { signal } : {}),
  });
  return { ...result, output };
};

/** Every path below `dir`, relative, sorted. */
function tree(dir: string): string[] {
  const output: string[] = [];
  const walk = (current: string) => {
    for (const name of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, name.name);
      output.push(relative(dir, path));
      if (name.isDirectory()) walk(path);
    }
  };
  walk(dir);
  return output.sort();
}

const hash = (path: string) =>
  createHash("sha256")
    .update(tree(path).join("\n"))
    .update(
      tree(path)
        .map((rel) => {
          try {
            return readFileSync(join(path, rel), "utf8");
          } catch {
            return "";
          }
        })
        .join("\n"),
    )
    .digest("hex");

const sentinels = () => {
  const location = join(git, "piship-workspace");
  return existsSync(location) ? readdirSync(location) : [];
};

/** A backend's workspace check: the exact command PiShip sent, if any. */
const checks = (fake: WorkspaceFake) =>
  fake.requests.filter((request) =>
    request.command.includes("echo piship-ws done"),
  );

/** Nothing a report or diagnostics line prints may carry a nonce, token, or path. */
function expectNoSecrets(sandbox: Active, fake: WorkspaceFake) {
  const text = [
    JSON.stringify(sandbox.report),
    JSON.stringify(sandbox.workspace()),
    describeContainment(sandbox.report, sandbox.workspace()),
  ].join("\n");
  expect(text).not.toMatch(/[0-9a-f]{32}/);
  expect(text).not.toContain(root);
  for (const check of checks(fake))
    for (const token of check.command.match(/[0-9a-f]{32}/g) ?? [])
      expect(text).not.toContain(token);
}

describe("workspace declaration and guarantees", () => {
  const remote = (
    workspace: unknown,
    planes: string[] = [
      "workspace-confinement",
      "git-control-protection",
      "network-deny",
      "environment-filter",
    ],
  ) =>
    ({
      isolation: "remote",
      planes,
      network: ["deny", "allow"],
      localProcesses: false,
      workspace,
    }) as SandboxCapabilities;

  it("defaults to snapshot and treats a local backend as shared", () => {
    expect(
      workspaceDeclaration({
        isolation: "remote",
        planes: [],
        network: [],
        localProcesses: false,
      }),
    ).toEqual({ declaration: { mode: "snapshot" } });
    expect(
      workspaceDeclaration({
        isolation: "local",
        planes: [],
        network: [],
        localProcesses: true,
        workspace: { mode: "bogus" } as unknown as SandboxWorkspaceDeclaration,
      }),
    ).toEqual({ declaration: { mode: "shared" } });
  });

  it.each([
    [{ mode: "mounted" }, "mode is not snapshot, synchronized, or shared"],
    [
      { mode: "synchronized", propagationMs: 0 },
      "propagationMs must be an integer from 1 to 60000",
    ],
    [
      { mode: "synchronized", propagationMs: 60_001 },
      "propagationMs must be an integer",
    ],
    [
      { mode: "synchronized", propagationMs: 1.5 },
      "propagationMs must be an integer",
    ],
    [
      { mode: "shared", propagationMs: 100 },
      "applies only to a synchronized workspace",
    ],
    [{ mode: "shared", sentinelDir: "/abs" }, "must be workspace-relative"],
    [{ mode: "shared", sentinelDir: "a/../b" }, "must not contain .."],
    [{ mode: "shared", sentinelDir: "a\\b" }, "must use / separators"],
    [{ mode: "shared", sentinelDir: "" }, "non-empty string"],
    [
      { mode: "snapshot", sentinelDir: ".sync" },
      "does not apply to a snapshot",
    ],
    ["shared", "not an object"],
  ])(
    "rejects the malformed declaration %j before prepare",
    async (declaration, reason) => {
      expect(capabilityMismatch(remote(declaration), "deny")).toContain(reason);
      const fake = sharedBackend({ capabilities: remote(declaration) });
      await expect(activate(fake)).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining("malformed workspace"),
      });
      expect(fake.prepared()).toBe(0);
    },
  );

  it("requires the filesystem guarantee that matches isolation and workspace", () => {
    expect(requiredPlanes("deny", "local")).toEqual([
      "filesystem-read-deny",
      "filesystem-write-allowlist",
      "network-deny",
      "environment-filter",
    ]);
    for (const mode of ["shared", "synchronized", "snapshot"] as const)
      expect(requiredPlanes("allow", "local", mode)).toEqual([
        "filesystem-read-deny",
        "filesystem-write-allowlist",
        "environment-filter",
      ]);
    expect(requiredPlanes("deny", "remote", "snapshot")).toEqual([
      "host-filesystem-isolation",
      "network-deny",
      "environment-filter",
    ]);
    for (const mode of ["shared", "synchronized"] as const) {
      expect(requiredPlanes("allow", "remote", mode)).toEqual([
        "workspace-confinement",
        "git-control-protection",
        "environment-filter",
      ]);
      expect(capabilityMismatch(remote({ mode }), "deny")).toBeUndefined();
      expect(capabilityMismatch(remote({ mode }), "allow")).toBeUndefined();
    }
  });

  it("fails a shared or synchronized backend that lacks a workspace guarantee", () => {
    for (const mode of ["shared", "synchronized"] as const)
      for (const plane of ["workspace-confinement", "git-control-protection"]) {
        const planes = [
          "workspace-confinement",
          "git-control-protection",
          "environment-filter",
        ].filter((item) => item !== plane);
        expect(capabilityMismatch(remote({ mode }, planes), "allow")).toBe(
          `it does not provide ${plane}`,
        );
      }
    // host-filesystem-isolation does not stand in for either.
    expect(
      capabilityMismatch(
        remote({ mode: "snapshot" }, [
          "host-filesystem-isolation",
          "environment-filter",
        ]),
        "allow",
      ),
    ).toBeUndefined();
  });

  it("refuses a shared or synchronized backend that also claims host isolation", () => {
    for (const mode of ["shared", "synchronized"] as const) {
      const capabilities = remote({ mode }, [
        "workspace-confinement",
        "git-control-protection",
        "host-filesystem-isolation",
        "environment-filter",
      ]);
      expect(capabilityMismatch(capabilities, "allow")).toBe(
        `it claims host-filesystem-isolation although its workspace is ${mode}, which reaches this host's files`,
      );
      expect(claimedGuarantees(capabilities, "allow")).not.toContain(
        "host-filesystem-isolation",
      );
    }
  });

  it("never reports workspace-confinement for a local backend", () => {
    expect(
      claimedGuarantees(
        {
          isolation: "local",
          planes: [
            "filesystem-read-deny",
            "filesystem-write-allowlist",
            "environment-filter",
            "workspace-confinement",
          ],
          network: ["deny", "allow"],
          localProcesses: true,
        },
        "allow",
      ),
    ).toEqual([
      "filesystem-read-deny",
      "filesystem-write-allowlist",
      "environment-filter",
    ]);
  });
});

describe("a snapshot backend", () => {
  it("is never checked and writes nothing into the workspace", async () => {
    const before = tree(workspace);
    // Reads the file from the backend's copy instead of running `cat`, so the
    // test needs no shell (Windows has no /bin/sh).
    const fake: WorkspaceFake = snapshotBackend({
      exec: async (_request, io) => {
        io.onStdout(readFileSync(join(fake.remote() ?? "", "README.md")));
        return { exitCode: 0 };
      },
    });
    const sandbox = await activate(fake, { protectedPaths: gitProtection() });
    expect(sandbox.report.workspace).toEqual({
      declared: "snapshot",
      effective: "snapshot",
      verification: "not-required",
      gitControlProtection: "not-applicable",
      complete: false,
    });
    expect((await run(sandbox, "cat README.md")).output).toBe("hello\n");
    expect(checks(fake)).toHaveLength(0);
    expect(sandbox.workspace()).toEqual(sandbox.report.workspace);
    expect(tree(workspace)).toEqual(before);
    expect(describeContainment(sandbox.report)).toContain(
      "Workspace: snapshot. Remote commands see a copy, not the files the agent edits; this is not a complete coding-agent workspace.",
    );
    await sandbox.dispose();
  });
});

describe.skipIf(!posix)(
  "a shared or synchronized workspace is verified",
  () => {
    it("proves a shared workspace in both directions before the first command, then cleans up", async () => {
      const fake = sharedBackend();
      const reports: WorkspaceReport[] = [];
      const sandbox = await activate(fake, { now: () => TIME });
      sandbox.onWorkspaceReport((report) => reports.push(report));
      // Nothing is written at activation (Plan mode, doctor).
      expect(existsSync(join(git, "piship-workspace"))).toBe(false);
      expect(sandbox.report.workspace).toMatchObject({
        declared: "shared",
        effective: "snapshot",
        verification: "pending",
        complete: false,
      });
      expect(describeContainment(sandbox.report)).toContain(
        "Workspace: shared declared, verified before the first sandboxed command.",
      );
      expect((await run(sandbox, "cat README.md")).output).toBe("hello\n");
      expect(sandbox.workspace()).toEqual({
        declared: "shared",
        effective: "shared",
        verification: "verified",
        hostToSandbox: "immediate",
        sandboxToHost: "immediate",
        windowMs: 10_000,
        gitControlProtection: "attested-renames",
        verifiedAt: "2026-09-29T12:00:00Z",
        complete: true,
      });
      expect(reports).toEqual([sandbox.workspace()]);
      // The check ran first and exactly once; the sentinel is gone.
      expect(
        fake.requests.map((request) =>
          request.command.includes("piship-ws done"),
        ),
      ).toEqual([false, true, false]);
      expect(sentinels()).toEqual([]);
      expect(
        describeContainment(sandbox.report, sandbox.workspace()),
      ).toContain(
        "Workspace: shared (verified 2026-09-29T12:00:00Z, both directions immediate).",
      );
      // The command the agent asked for never carries the check's tokens.
      expect(fake.commands()).toEqual(["cat README.md"]);
      expectNoSecrets(sandbox, fake);
      await sandbox.dispose();
    });

    it("verifies a synchronized workspace within its window", async () => {
      const fake = syncedBackend({ delayMs: 300 });
      const sandbox = await activate(fake, { now: () => TIME });
      await run(sandbox, "true");
      expect(sandbox.workspace()).toMatchObject({
        declared: "synchronized",
        effective: "synchronized",
        verification: "verified",
        hostToSandbox: "delayed",
        sandboxToHost: "delayed",
        complete: true,
      });
      expect(describeWorkspace(sandbox.workspace() as WorkspaceReport)).toBe(
        "Workspace: synchronized (verified 2026-09-29T12:00:00Z, within 2000 ms).",
      );
      expectNoSecrets(sandbox, fake);
      await sandbox.dispose();
    });

    it("lowers a declared shared workspace that propagates with a delay to synchronized, and warns", async () => {
      const fake = syncedBackend({
        delayMs: 500,
        declaration: { mode: "shared" },
      });
      const sandbox = await activate(fake, { now: () => TIME });
      expect((await run(sandbox, "echo ran")).output).toBe("ran\n");
      expect(sandbox.workspace()).toMatchObject({
        declared: "shared",
        effective: "synchronized",
        verification: "verified",
        complete: true,
        reason: "a direction was delayed, which a mount would not be",
      });
      expect(
        describeContainment(sandbox.report, sandbox.workspace()),
      ).toContain(
        "Workspace: synchronized (declared shared; verified 2026-09-29T12:00:00Z, within 10000 ms).",
      );
      await sandbox.dispose();
    });

    it.each([
      [
        "the host does not see sandbox changes",
        { toHost: false },
        { hostToSandbox: "delayed", sandboxToHost: "missing" },
        "the host did not see sandbox changes",
      ],
      [
        "the sandbox does not see host changes",
        { toSandbox: false },
        { hostToSandbox: "missing", sandboxToHost: "delayed" },
        "the sandbox did not see host changes",
      ],
      [
        "nothing propagates",
        { toSandbox: false, toHost: false },
        { hostToSandbox: "missing", sandboxToHost: "missing" },
        "neither side saw the other's changes",
      ],
    ])(
      "reports a snapshot, naming the working direction, when %s",
      async (_name, directions, propagation, reason) => {
        const fake = syncedBackend({
          delayMs: 100,
          declaration: { mode: "synchronized", propagationMs: 1000 },
          ...directions,
        });
        const sandbox = await activate(fake, { now: () => TIME });
        // A lowered mode is a warning: the command still runs.
        expect((await run(sandbox, "echo ran")).output).toBe("ran\n");
        expect(sandbox.workspace()).toEqual({
          declared: "synchronized",
          effective: "snapshot",
          verification: "failed",
          ...propagation,
          windowMs: 1000,
          gitControlProtection: "attested-renames",
          verifiedAt: "2026-09-29T12:00:00Z",
          reason,
          complete: false,
        });
        expect(
          describeContainment(sandbox.report, sandbox.workspace()),
        ).toContain(
          `Workspace: snapshot (declared synchronized; ${reason}). Not a complete coding-agent workspace.`,
        );
        expect(sentinels()).toEqual([]);
        await sandbox.dispose();
      },
    );

    it("never reports a declared snapshot as complete, whatever the backend does", async () => {
      const fake = syncedBackend({
        delayMs: 10,
        declaration: { mode: "snapshot" },
        capabilities: {
          isolation: "remote",
          planes: ["host-filesystem-isolation", "environment-filter"],
          network: ["deny", "allow"],
          localProcesses: false,
          workspace: { mode: "snapshot" },
        },
      });
      const sandbox = await activate(
        fake,
        {},
        policy({ network: { mode: "allow" } }),
      );
      await run(sandbox, "true");
      expect(sandbox.workspace()).toMatchObject({
        effective: "snapshot",
        complete: false,
      });
      expect(checks(fake)).toHaveLength(0);
      await sandbox.dispose();
    });
  },
);

describe.skipIf(!posix)(
  "git control files must stay read-only in a shared workspace",
  () => {
    it("fails closed before the agent's command when the sandbox can change them, and changes nothing", async () => {
      const fake = sharedBackend();
      const hooks = hash(join(git, "hooks"));
      const sandbox = await activate(fake, {
        protectedPaths: gitProtection(),
        now: () => TIME,
      });
      await expect(run(sandbox, "echo agent")).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining(
          "a protected git control file was writable from the sandbox",
        ),
      });
      // The agent's command never reached the backend, nor does a later one.
      await expect(run(sandbox, "echo again")).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
      });
      expect(fake.commands()).toEqual([]);
      expect(checks(fake)).toHaveLength(1);
      // The probe changed nothing and removed what it created.
      expect(readFileSync(join(git, "config"), "utf8")).toBe(CONFIG);
      expect(hash(join(git, "hooks"))).toBe(hooks);
      expect(readdirSync(join(git, "hooks"))).toEqual(["pre-commit"]);
      expect(existsSync(join(git, "info"))).toBe(false);
      expect(existsSync(join(git, "commondir"))).toBe(false);
      expect(existsSync(join(git, "config.worktree"))).toBe(false);
      expect(sentinels()).toEqual([]);
      expect(sandbox.workspace()).toMatchObject({
        effective: "snapshot",
        verification: "failed",
        complete: false,
      });
      await sandbox.dispose();
    });

    it("fails closed when only a protected directory is writable", async () => {
      const fake = sharedBackend();
      chmodSync(join(git, "config"), 0o444);
      const sandbox = await activate(fake, {
        protectedPaths: existingProtection(),
      });
      const result = run(sandbox, "echo agent");
      if (root_) await result.catch(() => undefined);
      else
        await expect(result).rejects.toMatchObject({
          code: "SANDBOX_UNAVAILABLE",
          message: expect.stringContaining(
            "a file could be created in a protected git directory",
          ),
        });
      expect(readdirSync(join(git, "hooks"))).toEqual(["pre-commit"]);
      expect(existsSync(join(git, "info"))).toBe(false);
      await sandbox.dispose();
    });

    it("fails closed when a protected file that does not exist yet can be created", async () => {
      // A backend that guards only what exists on the host: the existing
      // config and the hooks and info trees are read-only, .git is not.
      mkdirSync(join(git, "info"));
      chmodSync(join(git, "config"), 0o444);
      chmodSync(join(git, "hooks"), 0o555);
      chmodSync(join(git, "info"), 0o555);
      const fake = sharedBackend();
      const sandbox = await activate(fake, { protectedPaths: gitProtection() });
      const result = run(sandbox, "echo agent");
      if (root_) await result.catch(() => undefined);
      else
        await expect(result).rejects.toMatchObject({
          code: "SANDBOX_UNAVAILABLE",
          message: expect.stringContaining(
            "a protected git control file that does not exist yet could be created from the sandbox",
          ),
        });
      expect(fake.commands()).toEqual([]);
      // What the probe created is gone; the existing files are untouched.
      expect(existsSync(join(git, "commondir"))).toBe(false);
      expect(existsSync(join(git, "config.worktree"))).toBe(false);
      expect(readFileSync(join(git, "config"), "utf8")).toBe(CONFIG);
      expect(readdirSync(join(git, "hooks"))).toEqual(["pre-commit"]);
      expect(readdirSync(join(git, "info"))).toEqual([]);
      expect(sentinels()).toEqual([]);
      await sandbox.dispose();
    });

    it.skipIf(root_)(
      "removes only the empty files the probe created",
      async () => {
        const fake = sharedBackend({
          check: async (request, io) => {
            const result = await runShell(workspace, request, io);
            // Someone fills one of the files the probe created; a link takes
            // the other one's place.
            writeFileSync(join(git, "commondir"), "../evil\n");
            renameSync(join(git, "config.worktree"), join(root, "moved"));
            symlinkSync(join(root, "moved"), join(git, "config.worktree"));
            return result;
          },
        });
        const sandbox = await activate(fake, {
          protectedPaths: gitProtection(),
        });
        await expect(run(sandbox, "echo agent")).rejects.toMatchObject({
          code: "SANDBOX_UNAVAILABLE",
        });
        expect(readFileSync(join(git, "commondir"), "utf8")).toBe("../evil\n");
        expect(lstatSync(join(git, "config.worktree")).isSymbolicLink()).toBe(
          true,
        );
        expect(existsSync(join(root, "moved"))).toBe(true);
        await sandbox.dispose();
      },
    );

    it.skipIf(root_)(
      "removes nothing through a link that replaced the git directory",
      async () => {
        const other = join(root, "other-git");
        mkdirSync(other);
        for (const name of ["commondir", "config.worktree"])
          writeFileSync(join(other, name), "");
        const fake = sharedBackend({
          check: async (request, io) => {
            const result = await runShell(workspace, request, io);
            renameSync(git, join(root, "moved-git"));
            symlinkSync(other, git);
            return result;
          },
        });
        const sandbox = await activate(fake, {
          protectedPaths: gitProtection(),
        });
        await expect(run(sandbox, "echo agent")).rejects.toMatchObject({
          code: "SANDBOX_UNAVAILABLE",
        });
        expect(readdirSync(other).sort()).toEqual([
          "commondir",
          "config.worktree",
        ]);
        await sandbox.dispose();
      },
    );

    describe.skipIf(root_)("renames of protected paths", () => {
      // Protection by path alone: the files and trees that exist are
      // read-only, the git directory and the workspace root are not.
      beforeEach(() => {
        mkdirSync(join(git, "info"));
        chmodSync(join(git, "config"), 0o444);
        chmodSync(join(git, "hooks"), 0o555);
        chmodSync(join(git, "info"), 0o555);
      });

      /** A shared backend whose check runs after `prefix`, with `swap` applied to the script. */
      const shimmed = (
        prefix: string,
        swap?: readonly [string, string],
      ): WorkspaceFake =>
        sharedBackend({
          check: (request, io) =>
            runShell(
              workspace,
              {
                ...request,
                command: `${prefix}\n${swap ? request.command.replaceAll(swap[0], swap[1]) : request.command}`,
              },
              io,
            ),
        });

      // A device number per path depth: every path differs from its parent,
      // as a mount point does.
      // The check hands `stat` paths as `./<path>`; the shim reads `<path>`.
      const MOUNTS = `stat() { p=\${3#./}; if [ "$p" = . ]; then echo 0; else n=$(printf '%s' "$p" | tr -cd / | wc -c); echo $((n + 1)); fi; }`;
      // The same, except that .git shares the device of the workspace root.
      const UNPINNED_GIT = `stat() { p=\${3#./}; if [ "$p" = . ] || [ "$p" = .git ]; then echo 0; else n=$(printf '%s' "$p" | tr -cd / | wc -c); echo $((n + 1)); fi; }`;
      const SAME_DEVICE = "stat() { echo 1; }";

      const checked = async (fake: WorkspaceFake) => {
        const sandbox = await activate(fake, {
          protectedPaths: existingProtection(),
          now: () => TIME,
        });
        expect((await run(sandbox, "echo agent")).output).toBe("agent\n");
        const report = sandbox.workspace();
        await sandbox.dispose();
        return report;
      };

      it("is not verified when a protected path could be renamed", async () => {
        const report = await checked(sharedBackend());
        expect(report).toMatchObject({
          effective: "shared",
          verification: "verified",
          gitControlProtection: "not-verified",
        });
        // Nothing was renamed to find out.
        expect(readdirSync(git).sort()).toEqual([
          "config",
          "hooks",
          "info",
          "piship-workspace",
        ]);
        expect(readdirSync(workspace).sort()).toEqual([
          ".git",
          "README.md",
          "sub",
        ]);
      });

      it("passes when every protected path is a mount point", async () => {
        expect(await checked(shimmed(MOUNTS))).toMatchObject({
          gitControlProtection: "attested-renames",
        });
      });

      it("is not verified when the git directory above them could be renamed", async () => {
        expect(await checked(shimmed(UNPINNED_GIT))).toMatchObject({
          gitControlProtection: "not-verified",
        });
      });

      it("finds mount points of the same filesystem in the mount table", async () => {
        const table = join(root, "mountinfo");
        const line = (path: string) =>
          `36 35 8:1 / ${join(workspace, path)} rw,relatime - ext4 /dev/sda1 rw\n`;
        writeFileSync(
          table,
          [".git", ".git/config", ".git/hooks", ".git/info"].map(line).join(""),
        );
        const fake = (path: string) =>
          shimmed(SAME_DEVICE, ["/proc/self/mountinfo", path]);
        expect(await checked(fake(table))).toMatchObject({
          gitControlProtection: "attested-renames",
        });
        // Without the git directory itself in the table it could be moved.
        writeFileSync(
          table,
          [".git/config", ".git/hooks", ".git/info"].map(line).join(""),
        );
        expect(await checked(fake(table))).toMatchObject({
          gitControlProtection: "not-verified",
        });
        // A table that does not exist proves nothing.
        expect(await checked(fake(join(root, "no-such-table")))).toMatchObject({
          gitControlProtection: "not-verified",
        });
      });

      it("is not verified when the workspace root is writable, though nothing in the git directory is", async () => {
        // The sentinel directory is made up front so the host can still use
        // it; .git itself hangs from a writable root and could be moved.
        mkdirSync(join(git, "piship-workspace"), { mode: 0o700 });
        chmodSync(git, 0o555);
        expect(await checked(sharedBackend())).toMatchObject({
          gitControlProtection: "not-verified",
        });
      });
    });

    /**
     * A backend that keeps every protected path out of reach: nothing in
     * .git can be created, written, or renamed, and neither can .git itself.
     * The sentinel directory is made up front so the host can still use it.
     */
    const outOfReach = (hooksInTree = false) => {
      mkdirSync(join(git, "info"));
      mkdirSync(join(git, "piship-workspace"), { mode: 0o700 });
      if (hooksInTree)
        mkdirSync(join(workspace, ".husky", "_"), { recursive: true });
      chmodSync(join(git, "config"), 0o444);
      chmodSync(join(git, "hooks"), 0o555);
      chmodSync(join(git, "info"), 0o555);
      chmodSync(git, 0o555);
      if (hooksInTree) {
        chmodSync(join(workspace, ".husky", "_"), 0o555);
        chmodSync(join(workspace, ".husky"), 0o555);
      }
      chmodSync(workspace, 0o555);
    };

    it.skipIf(root_)(
      "passes when the backend keeps them read-only, and finds nothing it could rename",
      async () => {
        outOfReach();
        const fake = sharedBackend();
        const sandbox = await activate(fake, {
          protectedPaths: gitProtection(),
          now: () => TIME,
        });
        expect((await run(sandbox, "echo agent")).output).toBe("agent\n");
        expect(sandbox.workspace()).toMatchObject({
          effective: "shared",
          gitControlProtection: "attested-renames",
          complete: true,
        });
        expect(readdirSync(join(git, "hooks"))).toEqual(["pre-commit"]);
        expect(readdirSync(join(git, "info"))).toEqual([]);
        expect(existsSync(join(git, "commondir"))).toBe(false);
        await sandbox.dispose();
      },
    );

    it.skipIf(root_)(
      "is not verified when the protected list is known to be incomplete, though everything listed is out of reach",
      async () => {
        outOfReach();
        const fake = sharedBackend();
        const sandbox = await activate(fake, {
          protectedPaths: {
            ...gitProtection(),
            unverified: "the git config lists too much",
          },
          now: () => TIME,
        });
        expect((await run(sandbox, "echo agent")).output).toBe("agent\n");
        expect(sandbox.workspace()).toMatchObject({
          effective: "shared",
          verification: "verified",
          gitControlProtection: "not-verified",
          complete: true,
        });
        expect(sandbox.report.warnings).toContain(
          "git control is not verified: the git config lists too much",
        );
        await sandbox.dispose();
      },
    );

    it.skipIf(root_)(
      "is not verified when core.hooksPath names a directory in the working tree, though that too is out of reach",
      async () => {
        outOfReach(true);
        const protectedPaths = gitProtection();
        const fake = sharedBackend();
        const sandbox = await activate(fake, {
          protectedPaths: {
            ...protectedPaths,
            directories: [
              ...protectedPaths.directories,
              join(workspace, ".husky", "_"),
            ],
          },
          now: () => TIME,
        });
        expect((await run(sandbox, "echo agent")).output).toBe("agent\n");
        // The workspace is fine and the commands run; the scripts git runs
        // from the working tree are not something the check can vouch for.
        expect(sandbox.workspace()).toMatchObject({
          effective: "shared",
          verification: "verified",
          gitControlProtection: "not-verified",
          complete: true,
        });
        await sandbox.dispose();
      },
    );

    describe.skipIf(root_)("a protected path named like an option", () => {
      // core.hooksPath = -h: the path reaches mkdir, stat, and cd, which would
      // take it for a flag and make the check look at the wrong thing.
      it("is tried as a directory, and fails closed when it is writable", async () => {
        mkdirSync(join(workspace, "-h"));
        const fake = sharedBackend();
        const sandbox = await activate(fake, {
          protectedPaths: { files: [], directories: [join(workspace, "-h")] },
        });
        await expect(run(sandbox, "echo agent")).rejects.toMatchObject({
          code: "SANDBOX_UNAVAILABLE",
          message: expect.stringContaining(
            "a file could be created in a protected git directory",
          ),
        });
        // The probe file is gone; the directory was there before.
        expect(readdirSync(join(workspace, "-h"))).toEqual([]);
        await sandbox.dispose();
      });

      it("passes as a directory the sandbox cannot write", async () => {
        mkdirSync(join(workspace, "-h"));
        chmodSync(join(workspace, "-h"), 0o555);
        const fake = sharedBackend();
        const sandbox = await activate(fake, {
          protectedPaths: { files: [], directories: [join(workspace, "-h")] },
        });
        expect((await run(sandbox, "echo agent")).output).toBe("agent\n");
        await sandbox.dispose();
      });

      it("is found movable when it is a file in a writable directory", async () => {
        writeFileSync(join(workspace, "-h"), "");
        chmodSync(join(workspace, "-h"), 0o444);
        const fake = sharedBackend();
        const sandbox = await activate(fake, {
          protectedPaths: { files: [join(workspace, "-h")], directories: [] },
        });
        await run(sandbox, "echo agent");
        expect(sandbox.workspace()).toMatchObject({
          verification: "verified",
          gitControlProtection: "not-verified",
        });
        await sandbox.dispose();
      });

      it("is a sentinel directory that works", async () => {
        const fake = sharedBackend({
          declaration: { mode: "shared", sentinelDir: "-x" },
        });
        const sandbox = await activate(fake, { projectOrigin: "company" });
        await run(sandbox, "echo agent");
        expect(sandbox.workspace()).toMatchObject({
          effective: "shared",
          verification: "verified",
        });
        expect(readdirSync(join(workspace, "-x", "piship-workspace"))).toEqual(
          [],
        );
        await sandbox.dispose();
      });
    });

    it("fails closed when the check exits non-zero", async () => {
      const fake = sharedBackend({
        check: async () => ({ exitCode: 2 }),
      });
      const sandbox = await activate(fake);
      await expect(run(sandbox, "echo agent")).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining("did not report back (exit 2)"),
      });
      expect(fake.commands()).toEqual([]);
      expect(sentinels()).toEqual([]);
      await sandbox.dispose();
    });

    it("fails closed when the check times out", async () => {
      const hang = (_request: unknown, io: SandboxExecIO) =>
        new Promise<SandboxExecResult>((resolvePromise) => {
          io.signal.addEventListener("abort", () =>
            resolvePromise({ exitCode: 0 }),
          );
        });
      const fake = sharedBackend({
        declaration: { mode: "synchronized", propagationMs: 1 },
        check: hang,
      });
      const sandbox = await activate(fake, { probeTimeoutMs: 200 });
      await expect(run(sandbox, "echo agent")).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining("did not complete"),
      });
      expect(fake.commands()).toEqual([]);
      expect(sentinels()).toEqual([]);
      await sandbox.dispose();
    });

    it("does not count a cancelled check as a result", async () => {
      let calls = 0;
      const fake = sharedBackend({
        check: (request, io) => {
          calls++;
          if (calls === 1)
            return new Promise((resolvePromise) => {
              io.signal.addEventListener("abort", () =>
                resolvePromise({ exitCode: 0 }),
              );
            });
          return runShell(workspace, request, io);
        },
      });
      const sandbox = await activate(fake);
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 50);
      await expect(
        run(sandbox, "echo agent", controller.signal),
      ).rejects.toThrow("aborted");
      expect(sandbox.workspace()?.verification).toBe("pending");
      expect((await run(sandbox, "echo agent")).output).toBe("agent\n");
      expect(sandbox.workspace()?.verification).toBe("verified");
      expect(sentinels()).toEqual([]);
      await sandbox.dispose();
    });
  },
);

describe.skipIf(!posix)("the sentinel location", () => {
  it.each([
    [
      "no .git",
      () => rmSync(git, { recursive: true }),
      "the workspace has no .git directory",
    ],
    [
      "a .git file (linked worktree)",
      () => {
        rmSync(git, { recursive: true });
        writeFileSync(git, "gitdir: /elsewhere/.git/worktrees/ws\n");
      },
      "the workspace's .git is a file (a linked worktree)",
    ],
    [
      "a .git symbolic link",
      () => {
        const real = join(root, "real-git");
        mkdirSync(real);
        rmSync(git, { recursive: true });
        symlinkSync(real, git);
      },
      "the workspace's .git is a symbolic link",
    ],
  ])(
    "is unverifiable with %s, and the command still runs",
    async (_name, arrange, reason) => {
      arrange();
      const fake = sharedBackend();
      const sandbox = await activate(fake, { now: () => TIME });
      expect((await run(sandbox, "echo ran")).output).toBe("ran\n");
      expect(sandbox.workspace()).toMatchObject({
        declared: "shared",
        effective: "snapshot",
        verification: "unverifiable",
        complete: false,
      });
      expect(sandbox.workspace()?.reason).toContain(reason);
      expect(
        describeContainment(sandbox.report, sandbox.workspace()),
      ).toContain(
        "Workspace: snapshot (declared shared; no PiShip-owned location to verify it: ",
      );
      expect(existsSync(join(root, "real-git", "piship-workspace"))).toBe(
        false,
      );
      await sandbox.dispose();
    },
  );

  it("never follows a planted link out of the workspace", async () => {
    const outside = join(root, "outside");
    mkdirSync(outside);
    symlinkSync(outside, join(git, "piship-workspace"));
    const fake = sharedBackend();
    const sandbox = await activate(fake);
    await run(sandbox, "true");
    expect(sandbox.workspace()).toMatchObject({
      verification: "unverifiable",
      reason:
        "a component of the location is a symbolic link or not a directory",
    });
    expect(readdirSync(outside)).toEqual([]);
    await sandbox.dispose();
  });

  it.each([
    ["unknown", "unverifiable"],
    ["external", "unverifiable"],
    ["company", "verified"],
  ] as const)(
    "uses a working-tree sentinelDir only in a company project (origin %s)",
    async (origin, verification) => {
      const fake = sharedBackend({
        declaration: { mode: "shared", sentinelDir: ".sync/area" },
      });
      const sandbox = await activate(fake, { projectOrigin: origin });
      await run(sandbox, "true");
      expect(sandbox.workspace()?.verification).toBe(verification);
      if (verification === "unverifiable")
        expect(existsSync(join(workspace, ".sync"))).toBe(false);
      else
        expect(
          readdirSync(join(workspace, ".sync", "area", "piship-workspace")),
        ).toEqual([]);
      await sandbox.dispose();
    },
  );

  it("uses a sentinelDir inside the git directory whatever the origin", async () => {
    const fake = sharedBackend({
      declaration: { mode: "shared", sentinelDir: ".git/sync" },
    });
    const sandbox = await activate(fake, { projectOrigin: "external" });
    await run(sandbox, "true");
    expect(sandbox.workspace()?.verification).toBe("verified");
    expect(readdirSync(join(git, "sync", "piship-workspace"))).toEqual([]);
    await sandbox.dispose();
  });

  it("removes only nonce directories older than a day", async () => {
    const location = join(git, "piship-workspace");
    mkdirSync(location, { recursive: true });
    const old = "a".repeat(32);
    const fresh = "b".repeat(32);
    const linked = "c".repeat(32);
    const target = join(root, "target");
    mkdirSync(target);
    writeFileSync(join(target, "keep"), "keep");
    for (const name of [old, fresh, "not-a-nonce"])
      mkdirSync(join(location, name));
    symlinkSync(target, join(location, linked));
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 3600_000);
    utimesSync(join(location, old), twoDaysAgo, twoDaysAgo);
    utimesSync(join(location, "not-a-nonce"), twoDaysAgo, twoDaysAgo);
    const fake = sharedBackend();
    const sandbox = await activate(fake);
    await run(sandbox, "true");
    expect(sentinels().sort()).toEqual([fresh, linked, "not-a-nonce"].sort());
    expect(readdirSync(target)).toEqual(["keep"]);
    await sandbox.dispose();
  });

  it("never deletes recursively: a stale directory that holds other names stays", async () => {
    const location = join(git, "piship-workspace");
    mkdirSync(location, { recursive: true });
    const own = "a".repeat(32);
    const foreign = "b".repeat(32);
    const nested = "c".repeat(32);
    mkdirSync(join(location, own));
    for (const name of ["h2s", "s2h", "s2h.tmp"])
      writeFileSync(join(location, own, name), "token");
    mkdirSync(join(location, foreign));
    writeFileSync(join(location, foreign, "h2s"), "token");
    writeFileSync(join(location, foreign, "notes.txt"), "keep");
    // A directory where an own name is expected to be a file.
    mkdirSync(join(location, nested, "h2s"), { recursive: true });
    writeFileSync(join(location, nested, "h2s", "keep"), "keep");
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 3600_000);
    for (const name of [own, foreign, nested])
      utimesSync(join(location, name), twoDaysAgo, twoDaysAgo);
    const fake = sharedBackend();
    const sandbox = await activate(fake);
    await run(sandbox, "true");
    // The directory of own files goes; the others are left as they were.
    expect(sentinels().sort()).toEqual([foreign, nested].sort());
    expect(readdirSync(join(location, foreign)).sort()).toEqual([
      "h2s",
      "notes.txt",
    ]);
    expect(readFileSync(join(location, nested, "h2s", "keep"), "utf8")).toBe(
      "keep",
    );
    await sandbox.dispose();
  });

  it("removes only its own files from its own directory when the sandbox left others", async () => {
    let extra: string | undefined;
    const fake = sharedBackend({
      check: async (request, io) => {
        const result = await runShell(workspace, request, io);
        const [nonce] = readdirSync(join(git, "piship-workspace"));
        extra = join(git, "piship-workspace", nonce ?? "", "dropped");
        writeFileSync(extra, "kept");
        return result;
      },
    });
    const sandbox = await activate(fake);
    await run(sandbox, "true");
    expect(sandbox.workspace()?.verification).toBe("verified");
    expect(extra && readFileSync(extra, "utf8")).toBe("kept");
    expect(readdirSync(join(extra ?? "", ".."))).toEqual(["dropped"]);
    await sandbox.dispose();
  });

  describe("removeSentinelDirectory", () => {
    const base = [".git", "piship-workspace"];
    const nonce = "d".repeat(32);
    const location = () => join(git, "piship-workspace");
    let victim: string;
    beforeEach(() => {
      victim = join(root, "victim");
      mkdirSync(join(victim, nonce), { recursive: true });
      writeFileSync(join(victim, nonce, "h2s"), "host file");
      writeFileSync(join(victim, nonce, "data"), "host file");
    });
    const intact = () => {
      expect(readdirSync(join(victim, nonce)).sort()).toEqual(["data", "h2s"]);
      expect(readFileSync(join(victim, nonce, "data"), "utf8")).toBe(
        "host file",
      );
    };

    it("removes the files a run makes and the directory", () => {
      mkdirSync(join(location(), nonce), { recursive: true });
      for (const name of ["h2s", "s2h", "s2h.tmp"])
        writeFileSync(join(location(), nonce, name), "token");
      expect(removeSentinelDirectory(workspace, base, nonce)).toBe(true);
      expect(readdirSync(location())).toEqual([]);
    });

    it("deletes nothing through a link that replaced the location", () => {
      symlinkSync(victim, location());
      expect(removeSentinelDirectory(workspace, base, nonce)).toBe(false);
      expect(
        removeSentinelDirectory(workspace, base, nonce, { onlyOwn: true }),
      ).toBe(false);
      intact();
    });

    it("deletes nothing through a link that replaced the git directory", () => {
      renameSync(git, join(root, "moved-git"));
      symlinkSync(victim, git);
      // The victim also holds the location, so the whole path resolves.
      mkdirSync(join(victim, "piship-workspace"));
      renameSync(join(victim, nonce), join(victim, "piship-workspace", nonce));
      expect(removeSentinelDirectory(workspace, base, nonce)).toBe(false);
      expect(
        readdirSync(join(victim, "piship-workspace", nonce)).sort(),
      ).toEqual(["data", "h2s"]);
    });

    it("deletes nothing through a link that replaced the nonce directory", () => {
      mkdirSync(location(), { recursive: true });
      symlinkSync(join(victim, nonce), join(location(), nonce));
      expect(removeSentinelDirectory(workspace, base, nonce)).toBe(false);
      intact();
    });

    it("unlinks regular files only, never a link or a directory of an own name", () => {
      mkdirSync(join(location(), nonce), { recursive: true });
      const outside = join(victim, "outside-file");
      writeFileSync(outside, "host file");
      symlinkSync(outside, join(location(), nonce, "s2h"));
      mkdirSync(join(location(), nonce, "h2s"));
      writeFileSync(join(location(), nonce, "h2s", "keep"), "keep");
      writeFileSync(join(location(), nonce, "s2h.tmp"), "token");
      expect(removeSentinelDirectory(workspace, base, nonce)).toBe(false);
      expect(readFileSync(outside, "utf8")).toBe("host file");
      expect(readdirSync(join(location(), nonce)).sort()).toEqual([
        "h2s",
        "s2h",
      ]);
      expect(readFileSync(join(location(), nonce, "h2s", "keep"), "utf8")).toBe(
        "keep",
      );
    });

    it("leaves a directory that holds another name alone when asked to", () => {
      mkdirSync(join(location(), nonce), { recursive: true });
      writeFileSync(join(location(), nonce, "h2s"), "token");
      writeFileSync(join(location(), nonce, "notes"), "keep");
      expect(
        removeSentinelDirectory(workspace, base, nonce, { onlyOwn: true }),
      ).toBe(false);
      expect(readdirSync(join(location(), nonce)).sort()).toEqual([
        "h2s",
        "notes",
      ]);
    });
  });

  it("does not follow a link that replaces the location during a check", async () => {
    const victim = join(root, "victim");
    const fake = sharedBackend({
      // A short window: the host cannot read the sandbox's token back through
      // the link, and waits the window out.
      declaration: { mode: "synchronized", propagationMs: 300 },
      check: async (request, io) => {
        const result = await runShell(workspace, request, io);
        const location = join(git, "piship-workspace");
        const [nonce] = readdirSync(location);
        // A leftover sandbox process swaps the location for a link to a host
        // directory that holds a directory of the same name.
        mkdirSync(join(victim, nonce ?? ""), { recursive: true });
        writeFileSync(join(victim, nonce ?? "", "h2s"), "host file");
        writeFileSync(join(victim, nonce ?? "", "data"), "host file");
        renameSync(location, join(root, "moved-location"));
        symlinkSync(victim, location);
        return result;
      },
    });
    const sandbox = await activate(fake);
    await run(sandbox, "true");
    const [nonce] = readdirSync(victim);
    expect(readdirSync(join(victim, nonce ?? "")).sort()).toEqual([
      "data",
      "h2s",
    ]);
    await sandbox.dispose();
  });

  it("removes the sentinel when the process exits during a check", () => {
    const module = pathToFileURL(
      join(
        fileURLToPath(new URL(".", import.meta.url)),
        "..",
        "dist",
        "workspace.js",
      ),
    ).href;
    const script = `
      const { readdirSync, writeSync } = await import("node:fs");
      const { verifyWorkspace } = await import(${JSON.stringify(module)});
      const [ws, location] = process.argv.slice(1);
      await verifyWorkspace(async () => {
        writeSync(1, readdirSync(location).join(","));
        process.exit(0);
      }, {
        workspace: ws,
        origin: "unknown",
        declaration: { mode: "shared" },
        protectedPaths: { files: [], directories: [] },
      });
    `;
    const child = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        script,
        workspace,
        join(git, "piship-workspace"),
      ],
      { encoding: "utf8" },
    );
    expect(child.stderr).toBe("");
    expect(child.stdout).toMatch(NONCE);
    expect(sentinels()).toEqual([]);
  });
});

describe.skipIf(!posix)("the validity window", () => {
  it("checks again before the next command after 30 minutes or a new environment", async () => {
    let now = TIME;
    let epoch = "pod-1";
    const fake = sharedBackend({ epoch: () => epoch });
    const sandbox = await activate(fake, { now: () => now });
    await run(sandbox, "one");
    await run(sandbox, "two");
    expect(checks(fake)).toHaveLength(1);
    now += WORKSPACE_VALIDITY_MS - 1;
    await run(sandbox, "three");
    expect(checks(fake)).toHaveLength(1);
    now += 1;
    await run(sandbox, "four");
    expect(checks(fake)).toHaveLength(2);
    epoch = "pod-2";
    await run(sandbox, "five");
    expect(checks(fake)).toHaveLength(3);
    // Each check ran before the command that found the result expired.
    const order = fake.requests
      .filter((request) => !request.command.includes("piship-sandbox-ready"))
      .map((request) =>
        request.command.includes("piship-ws done") ? "check" : request.command,
      );
    expect(order).toEqual([
      "check",
      "one",
      "two",
      "three",
      "check",
      "four",
      "check",
      "five",
    ]);
    expect(sandbox.workspace()?.verifiedAt).toBe(
      new Date(now).toISOString().replace(".000Z", "Z"),
    );
    await sandbox.dispose();
  });

  it("runs one check for concurrent first commands", async () => {
    const fake = sharedBackend();
    const sandbox = await activate(fake);
    await Promise.all([
      run(sandbox, "a"),
      run(sandbox, "b"),
      run(sandbox, "c"),
    ]);
    expect(checks(fake)).toHaveLength(1);
    await sandbox.dispose();
  });
});

describe("hooksInWorkingTree", () => {
  const paths = (...directories: string[]): ProtectedPaths => ({
    files: [],
    directories,
  });
  it("is true only for a protected directory in the working tree", () => {
    const ws = join(root, "ws");
    expect(hooksInWorkingTree(ws, paths(join(ws, ".husky", "_")))).toBe(true);
    expect(hooksInWorkingTree(ws, paths(join(ws, ".githooks")))).toBe(true);
    expect(
      hooksInWorkingTree(
        ws,
        paths(join(ws, ".git", "hooks"), join(ws, ".git", "worktrees")),
      ),
    ).toBe(false);
    // Outside the workspace, or a git directory of a linked worktree.
    expect(
      hooksInWorkingTree(
        ws,
        paths(join(root, "elsewhere", "hooks"), join(root, "main", ".git")),
      ),
    ).toBe(false);
    expect(hooksInWorkingTree(ws, paths())).toBe(false);
    // A sibling whose name starts like .git is not the git directory.
    expect(hooksInWorkingTree(ws, paths(join(ws, ".github", "hooks")))).toBe(
      true,
    );
  });
});

describe("missingControlFileInWritablePath", () => {
  const paths = (...files: string[]): ProtectedPaths => ({
    files,
    directories: [],
  });
  // What Seatbelt is: the files git follows in `.git` are guarded when missing.
  const seatbeltLike = { guardsMissingFiles: true };

  it("is true only for a protected file that does not exist, in the working tree", () => {
    writeFileSync(join(workspace, ".gitconfig"), "[core]\n");
    const missing = (...files: string[]) =>
      missingControlFileInWritablePath(
        workspace,
        paths(...files),
        seatbeltLike,
      );
    // An include the sandbox could create, and one that is there already.
    expect(missing(join(workspace, ".gitconfig.local"))).toBe(true);
    expect(missing(join(workspace, ".gitconfig"))).toBe(false);
    expect(
      missing(join(workspace, ".gitconfig"), join(workspace, "sub", "cfg")),
    ).toBe(true);
    // Files git follows in the git directory are the guarded set's own
    // business, and a file outside the workspace is not the sandbox's.
    expect(missing(join(git, "commondir"), join(git, "config.worktree"))).toBe(
      false,
    );
    expect(missing(join(root, "elsewhere", "cfg"))).toBe(false);
    expect(missing()).toBe(false);
  });

  it("also counts a missing file in another path the sandbox may write, such as the home directory", () => {
    const home = join(root, "home");
    mkdirSync(home);
    writeFileSync(join(home, ".gitconfig"), "[user]\n");
    const missing = (...files: string[]) =>
      missingControlFileInWritablePath(workspace, paths(...files), {
        ...seatbeltLike,
        writable: [home],
      });
    // A global config nobody has created, which the sandbox could create.
    expect(missing(join(home, ".config", "git", "config"))).toBe(true);
    expect(missing(join(home, ".gitconfig"))).toBe(false);
    // Outside every writable path it is read-only already, and the workspace's
    // own .git is the guarded set's business.
    expect(missing(join(root, "elsewhere", "cfg"))).toBe(false);
    expect(missing(join(git, "commondir"))).toBe(false);
    // Without the writable path the home directory is not the sandbox's.
    expect(
      missingControlFileInWritablePath(
        workspace,
        paths(join(home, ".config", "git", "config")),
        seatbeltLike,
      ),
    ).toBe(false);
  });

  it("counts the files git follows in .git too when the isolator cannot guard a file that does not exist, as bubblewrap cannot", () => {
    const files = [join(git, "config"), join(git, "commondir")];
    files.push(join(git, "config.worktree"));
    const protectedFiles = paths(...files);
    // .git/config exists; commondir and config.worktree do not.
    expect(missingControlFiles(workspace, protectedFiles)).toEqual([
      join(git, "commondir"),
      join(git, "config.worktree"),
    ]);
    expect(
      missingControlFiles(workspace, protectedFiles, {
        guardsMissingFiles: false,
      }),
    ).toEqual([join(git, "commondir"), join(git, "config.worktree")]);
    // An isolator that guards a missing file leaves them to itself.
    expect(
      missingControlFiles(workspace, protectedFiles, seatbeltLike),
    ).toEqual([]);
    // Nothing is missing once the files exist, and PiShip created none.
    writeFileSync(join(git, "commondir"), "..\n");
    writeFileSync(join(git, "config.worktree"), "");
    expect(missingControlFiles(workspace, protectedFiles)).toEqual([]);
  });

  it("does not count a missing file outside every path the sandbox may write", () => {
    expect(
      missingControlFiles(workspace, paths(join(root, "elsewhere", "cfg"))),
    ).toEqual([]);
    expect(
      missingControlFiles(workspace, paths("/etc/piship-no-such-gitconfig")),
    ).toEqual([]);
  });
});

describe("missingFilesWarning", () => {
  it("names the files, relative to the workspace, and why git control is not verified", () => {
    const warning = missingFilesWarning(
      workspace,
      [
        join(git, "commondir"),
        join(git, "config.worktree"),
        join(root, "home", ".gitconfig"),
      ],
      "linux-bubblewrap",
      true,
    );
    expect(warning).toContain(
      "git control is not verified: linux-bubblewrap cannot guard a protected file that does not exist yet",
    );
    expect(warning).toContain(
      "(.git/commondir, .git/config.worktree, 1 outside the workspace)",
    );
    expect(warning).toContain("does not create placeholder files");
    // Never a host path outside the workspace, or the workspace's own path.
    expect(warning).not.toContain(root);
    // A backend that only fails to say it can guard them is worded so.
    expect(
      missingFilesWarning(
        workspace,
        [join(git, "commondir")],
        "acme-local",
        false,
      ),
    ).toContain("acme-local does not say it can guard a protected file");
    expect(
      missingFilesWarning(workspace, [], "acme-local", false),
    ).toBeUndefined();
  });
});

describe("gitControlUnproven", () => {
  it("is true for an incomplete list, for either backend, and for what each one cannot show", () => {
    const paths = (extra: Partial<ProtectedPaths> = {}): ProtectedPaths => ({
      files: [],
      directories: [],
      ...extra,
    });
    for (const backend of ["local", "remote"] as const) {
      expect(gitControlUnproven(workspace, paths(), backend)).toBe(false);
      expect(
        gitControlUnproven(workspace, paths({ unverified: "why" }), backend),
      ).toBe(true);
      expect(
        gitControlUnproven(
          workspace,
          paths({ directories: [join(workspace, ".githooks")] }),
          backend,
        ),
      ).toBe(true);
    }
    // A missing config file in the working tree: only a local backend cannot
    // show it, since a remote check tries to create it.
    const missing = paths({ files: [join(workspace, ".gitconfig.local")] });
    expect(gitControlUnproven(workspace, missing, "local")).toBe(true);
    expect(gitControlUnproven(workspace, missing, "remote")).toBe(false);
    // The same for a global config that does not exist in a directory the
    // sandbox may write: a remote check reaches only the workspace.
    const home = join(root, "home");
    const global = paths({ files: [join(home, ".gitconfig")] });
    expect(gitControlUnproven(workspace, global, "local")).toBe(false);
    const writable = { writable: [home] };
    expect(gitControlUnproven(workspace, global, "local", writable)).toBe(true);
    expect(gitControlUnproven(workspace, global, "remote", writable)).toBe(
      false,
    );
  });

  it("is true for a local isolator that cannot guard the files git follows in .git while they are missing, and only for it", () => {
    const followed = {
      files: [join(git, "config"), join(git, "commondir")],
      directories: [],
    };
    // Bubblewrap: no mount point for a file that does not exist.
    expect(gitControlUnproven(workspace, followed, "local")).toBe(true);
    expect(
      gitControlUnproven(workspace, followed, "local", {
        guardsMissingFiles: false,
      }),
    ).toBe(true);
    // Seatbelt denies the path itself: unchanged.
    expect(
      gitControlUnproven(workspace, followed, "local", {
        guardsMissingFiles: true,
      }),
    ).toBe(false);
    // A remote check tries to create the file, and does not ask.
    expect(gitControlUnproven(workspace, followed, "remote")).toBe(false);
    // Present, both are proven.
    writeFileSync(join(git, "commondir"), "..\n");
    expect(gitControlUnproven(workspace, followed, "local")).toBe(false);
  });
});

describe("the workspace sentence", () => {
  const base = {
    windowMs: 10_000,
    gitControlProtection: "attested-renames",
  } as const;
  it.each([
    [
      {
        declared: "snapshot",
        effective: "snapshot",
        verification: "not-required",
        complete: false,
        gitControlProtection: "not-applicable",
      },
      "Workspace: snapshot. Remote commands see a copy, not the files the agent edits; this is not a complete coding-agent workspace.",
    ],
    [
      {
        declared: "shared",
        effective: "snapshot",
        verification: "pending",
        complete: false,
        gitControlProtection: "pending",
      },
      "Workspace: shared declared, verified before the first sandboxed command.",
    ],
    [
      {
        ...base,
        declared: "shared",
        effective: "shared",
        verification: "verified",
        verifiedAt: "2026-09-29T12:00:00Z",
        complete: true,
      },
      "Workspace: shared (verified 2026-09-29T12:00:00Z, both directions immediate).",
    ],
    [
      {
        ...base,
        declared: "synchronized",
        effective: "synchronized",
        verification: "verified",
        windowMs: 4000,
        verifiedAt: "2026-09-29T12:00:00Z",
        complete: true,
      },
      "Workspace: synchronized (verified 2026-09-29T12:00:00Z, within 4000 ms).",
    ],
    [
      {
        ...base,
        declared: "shared",
        effective: "snapshot",
        verification: "failed",
        reason: "the sandbox did not see host changes",
        complete: false,
      },
      "Workspace: snapshot (declared shared; the sandbox did not see host changes). Not a complete coding-agent workspace.",
    ],
    [
      {
        ...base,
        declared: "shared",
        effective: "snapshot",
        verification: "unverifiable",
        reason: "the workspace has no .git directory",
        complete: false,
      },
      "Workspace: snapshot (declared shared; no PiShip-owned location to verify it: the workspace has no .git directory).",
    ],
  ] as const)("describes %j", (report, text) => {
    expect(describeWorkspace(report as WorkspaceReport)).toBe(text);
  });

  it("adds the workspace to the containment line only for remote backends", async () => {
    const fake = sharedBackend();
    const sandbox = await activate(fake);
    expect(describeContainment(sandbox.report)).toBe(
      "enforced by acme-shared (required, attested by the backend): network-deny, environment-filter, git-control-protection, workspace-confinement; network deny. Contains shell commands; MCP stdio servers cannot be contained by this backend and do not start, not the agent process or in-process extensions. The sandbox reaches this host's files only through the workspace, where it does not enforce sandbox.filesystem path rules: a read-denied path inside the workspace is readable by sandboxed commands. Workspace: shared declared, verified before the first sandboxed command.",
    );
    expect(sandbox.report.isolation).toBe("remote");
    await sandbox.dispose();
    expect(workspaceCapabilities({ mode: "shared" }).isolation).toBe("remote");
  });
});

const native = selectAdapter();
const nativeReady = (await native.available()).available;
const requireSandbox = process.env.PISHIP_REQUIRE_SANDBOX === "1";

describe.skipIf(!nativeReady && !requireSandbox)(
  "a local backend's git-control-protection is live-probed",
  () => {
    it("proves it for a backend that keeps protected paths read-only", async () => {
      const sandbox = await activateSandbox(policy(), {
        workspace,
        homeDir: join(root, "home"),
        backend: fakeWrappingBackend(native, true),
      });
      expect(sandbox.report.planes).toContain("git-control-protection");
      expect(sandbox.report.workspace).toEqual({
        declared: "shared",
        effective: "shared",
        verification: "not-required",
        gitControlProtection: "verified",
        complete: true,
      });
      expect(describeContainment(sandbox.report)).not.toContain("Workspace:");
      await sandbox.dispose();
    });

    it("does not report it as verified when core.hooksPath names a directory in the working tree", async () => {
      mkdirSync(join(workspace, ".husky", "_"), { recursive: true });
      const activateWith = (directory: string) =>
        activateSandbox(policy(), {
          workspace,
          homeDir: join(root, "home"),
          backend: fakeWrappingBackend(native, true),
          protectedPaths: { files: [], directories: [directory] },
        });
      const inTree = await activateWith(join(workspace, ".husky", "_"));
      // The plane is proven for the protected paths; the hook scripts the
      // directory runs are project files, so the report cannot say verified.
      expect(inTree.report.planes).toContain("git-control-protection");
      expect(inTree.report.workspace).toMatchObject({
        gitControlProtection: "not-verified",
      });
      await inTree.dispose();
      const inGit = await activateWith(join(git, "hooks"));
      expect(inGit.report.workspace).toMatchObject({
        gitControlProtection: "verified",
      });
      await inGit.dispose();
    });

    it("does not report it as verified, and says why, while an isolator that cannot guard a missing file has files git follows in .git missing", async () => {
      const files = [
        join(git, "config"),
        join(git, "config.worktree"),
        join(git, "commondir"),
      ];
      const activateWith = (guardsMissingFiles?: boolean) =>
        activateSandbox(policy(), {
          workspace,
          homeDir: join(root, "home"),
          backend: fakeWrappingBackend(
            native,
            true,
            guardsMissingFiles === undefined ? {} : { guardsMissingFiles },
          ),
          protectedPaths: {
            files,
            directories: [join(git, "hooks"), join(git, "info")],
          },
        });
      const notVerified = (sandbox: Awaited<ReturnType<typeof activateWith>>) =>
        expect(sandbox.report.workspace).toMatchObject({
          gitControlProtection: "not-verified",
        });

      // Bubblewrap: no mount point for a file that does not exist. Reported,
      // never failed, and nothing is created in the project.
      const cannot = await activateWith(false);
      expect(cannot.report.level).toBe("enforced");
      expect(cannot.report.planes).toContain("git-control-protection");
      notVerified(cannot);
      expect(cannot.report.warnings).toContainEqual(
        expect.stringContaining(
          "acme-local cannot guard a protected file that does not exist yet (.git/config.worktree, .git/commondir)",
        ),
      );
      expect(existsSync(join(git, "commondir"))).toBe(false);
      expect(existsSync(join(git, "config.worktree"))).toBe(false);
      await cannot.dispose();

      // A backend that says nothing about it is treated the same.
      const silent = await activateWith();
      notVerified(silent);
      expect(silent.report.warnings).toContainEqual(
        expect.stringContaining("acme-local does not say it can guard"),
      );
      await silent.dispose();

      // Seatbelt denies the path itself: verified, as before.
      const guards = await activateWith(true);
      expect(guards.report.workspace).toMatchObject({
        gitControlProtection: "verified",
      });
      expect(guards.report.warnings.join("\n")).not.toContain(
        "does not exist yet",
      );
      await guards.dispose();

      // With the files there, an isolator that cannot guard a missing one has
      // nothing missing.
      writeFileSync(join(git, "commondir"), "..\n");
      writeFileSync(join(git, "config.worktree"), "");
      const present = await activateWith(false);
      expect(present.report.workspace).toMatchObject({
        gitControlProtection: "verified",
      });
      expect(present.report.warnings.join("\n")).not.toContain(
        "does not exist yet",
      );
      await present.dispose();
    });

    it("does not report it as verified while a config file git includes from the working tree does not exist", async () => {
      const include = join(workspace, ".gitconfig.local");
      const activateWith = () =>
        activateSandbox(policy(), {
          workspace,
          homeDir: join(root, "home"),
          backend: fakeWrappingBackend(native, true),
          protectedPaths: { files: [include], directories: [] },
        });
      // Nothing can guard a file that is not there, and git follows it if it
      // appears, so the plane is proven for the paths that exist and no more.
      const missing = await activateWith();
      expect(missing.report.planes).toContain("git-control-protection");
      expect(missing.report.workspace).toMatchObject({
        gitControlProtection: "not-verified",
      });
      await missing.dispose();
      writeFileSync(include, "[core]\n");
      const present = await activateWith();
      expect(present.report.workspace).toMatchObject({
        gitControlProtection: "verified",
      });
      await present.dispose();
    });

    it("does not report it as verified when the protected list is known to be incomplete, and says why", async () => {
      const sandbox = await activateSandbox(policy(), {
        workspace,
        homeDir: join(root, "home"),
        backend: fakeWrappingBackend(native, true),
        protectedPaths: {
          files: [],
          directories: [],
          unverified: "the git config lists too much",
        },
      });
      expect(sandbox.report.planes).toContain("git-control-protection");
      expect(sandbox.report.workspace).toMatchObject({
        gitControlProtection: "not-verified",
      });
      expect(sandbox.report.warnings).toContain(
        "git control is not verified: the git config lists too much",
      );
      await sandbox.dispose();
    });

    it("warns, and does not claim it, for a backend that ignores writeProtect", async () => {
      const sandbox = await activateSandbox(policy(), {
        workspace,
        homeDir: join(root, "home"),
        backend: fakeWrappingBackend(native, true, {
          ignoreWriteProtect: true,
        }),
      });
      // Reported, not yet required: the launch still succeeds.
      expect(sandbox.report.level).toBe("enforced");
      expect(sandbox.report.planes).not.toContain("git-control-protection");
      expect(sandbox.report.workspace?.gitControlProtection).toBe(
        "not-verified",
      );
      expect(sandbox.report.warnings.join("\n")).toContain(
        "git-control-protection is not proven",
      );
      await sandbox.dispose();
    });
  },
);
