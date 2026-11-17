import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  activateSandbox,
  customBackend,
  type SandboxExecIO,
  type SandboxExecRequest,
} from "@piship/sandbox";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ARCHIVE, MARKER } from "../remote-workspace/seed.js";
import {
  probeRemoteWorkspace,
  type RemoteWorkspaceData,
  remoteWorkspaceLines,
} from "./remote-workspace.js";
import type { DoctorSection } from "./report.js";

let dir: string;
beforeEach(() => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "piship-doctor-rw-")));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** A sandbox that is a local directory; `path` is the PATH its commands see. */
const local = (path = process.env.PATH ?? "") => ({
  files: {
    read: async () => Buffer.alloc(0),
    write: async () => undefined,
    stat: async () => ({ type: "directory" as const, size: 0 }),
  },
  exec: async (
    command: string,
    _cwd: string,
    options: { onData(chunk: Buffer): void },
  ) => {
    try {
      options.onData(
        execFileSync("/bin/sh", ["-c", command], {
          cwd: dir,
          env: { PATH: path },
          stdio: ["ignore", "pipe", "ignore"],
        }),
      );
      return { exitCode: 0 };
    } catch {
      return { exitCode: 1 };
    }
  },
});

describe.skipIf(process.platform === "win32")("probeRemoteWorkspace", () => {
  it("finds an empty directory with tar and git", async () => {
    expect(await probeRemoteWorkspace(local(), dir)).toEqual({
      files: true,
      tar: true,
      gzip: true,
      git: true,
      directory: "empty",
    });
  });

  it("tells a missing tool, an unfinished seed of ours, and a filled directory apart", async () => {
    expect(
      await probeRemoteWorkspace(local("/nonexistent"), dir),
    ).toMatchObject({ tar: false, git: false });
    writeFileSync(join(dir, MARKER), "");
    writeFileSync(join(dir, ARCHIVE), "");
    expect((await probeRemoteWorkspace(local(), dir)).directory).toBe("marker");
    writeFileSync(join(dir, ".bashrc"), "");
    mkdirSync(join(dir, "src"));
    expect((await probeRemoteWorkspace(local(), dir)).directory).toBe(
      "not-empty",
    );
  });

  it("reports a failing file API, a failing command, and a missing file API", async () => {
    const files = {
      ...local().files,
      stat: async () => {
        throw new Error("boom");
      },
    };
    expect(
      await probeRemoteWorkspace({ ...local(), files }, dir),
    ).toMatchObject({ files: false, error: expect.stringContaining("boom") });
    expect(
      await probeRemoteWorkspace(
        { ...local(), exec: async () => ({ exitCode: 7 }) },
        dir,
      ),
    ).toMatchObject({ files: true, error: expect.stringContaining("exit 7") });
    expect(
      await probeRemoteWorkspace({ exec: local().exec }, dir),
    ).toMatchObject({ files: false });
  });
});

describe.skipIf(process.platform === "win32")(
  "probeRemoteWorkspace through the activated sandbox",
  () => {
    it("passes the file API check that the real wrapper serves", async () => {
      const remote = join(dir, "remote");
      const workspace = join(dir, "ws");
      mkdirSync(remote);
      mkdirSync(workspace);
      const statted: string[] = [];
      const backend = customBackend({
        id: "acme-remote",
        available: async () => ({ available: true }),
        capabilities: () => ({
          isolation: "remote",
          planes: [
            "host-filesystem-isolation",
            "network-deny",
            "environment-filter",
          ],
          network: ["deny"],
          localProcesses: false,
        }),
        prepare: async () => ({
          files: {
            read: async () => Buffer.alloc(0),
            write: async () => undefined,
            stat: async (path: string) => {
              statted.push(path);
              return undefined;
            },
          },
          exec: async (
            { command, workspacePath }: SandboxExecRequest,
            io: SandboxExecIO,
          ) => {
            io.onStdout(
              execFileSync("/bin/sh", ["-c", command], {
                cwd: join(remote, workspacePath ?? "."),
                env: { PATH: process.env.PATH ?? "" },
                stdio: ["ignore", "pipe", "ignore"],
              }),
            );
            return { exitCode: 0 };
          },
          dispose: async () => {},
        }),
      });
      const sandbox = await activateSandbox(
        {
          required: true,
          filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
          network: { mode: "deny" },
          environment: { allow: [] },
          remoteWorkspace: true,
        },
        {
          workspace,
          homeDir: join(dir, "home"),
          backend,
          env: {},
          settleMs: 2000,
        },
      );
      try {
        expect(await probeRemoteWorkspace(sandbox, workspace)).toEqual({
          files: true,
          tar: true,
          gzip: true,
          git: true,
          directory: "empty",
        });
        expect(statted).toEqual([MARKER]);
      } finally {
        await sandbox.dispose();
      }
    });
  },
);

function render(data: RemoteWorkspaceData): string[] {
  const lines: string[] = [];
  const row = (mark: string) => (label: string, value: string) =>
    lines.push(`${mark} ${label}: ${value}`);
  const out: DoctorSection = {
    ok: row("ok"),
    warn: row("warn"),
    bad: row("bad"),
    info: row("info"),
  };
  remoteWorkspaceLines(data, out);
  return lines;
}

describe("remoteWorkspaceLines", () => {
  const good = {
    files: true,
    tar: true,
    gzip: true,
    git: true,
    directory: "empty",
  } as const;
  const base = { command: "acme", network: "deny" };

  it("passes a ready sandbox and explains the denied network", () => {
    const lines = render({
      ...base,
      probe: good,
      waiting: { files: 0, patches: 0, latest: "" },
    });
    expect(lines).toEqual([
      "ok remote file API: the backend exposes read, write and stat",
      "ok remote tar: tar found in the sandbox",
      "ok remote gzip: gzip found in the sandbox",
      "ok remote git: git found in the sandbox",
      "ok remote directory: the project directory is empty",
      expect.stringMatching(
        /^info remote network: outbound denied: .*outside the project directory/,
      ),
      "ok waiting patch: none",
    ]);
  });

  it("fails each problem with a fix", () => {
    const lines = render({
      ...base,
      network: "allow",
      probe: {
        ...good,
        tar: false,
        gzip: false,
        git: false,
        directory: "not-empty",
      },
    });
    expect(lines).toContain(
      "bad remote tar: tar is not in the sandbox; use a template that includes it",
    );
    expect(lines).toContain(
      "bad remote git: git is not in the sandbox; use a template that includes it",
    );
    expect(lines.find((l) => l.startsWith("bad remote directory"))).toMatch(
      /not empty.*sandbox\.workdir/,
    );
    expect(lines).toContain(
      "info remote network: outbound allowed: dependencies can be installed at run time",
    );
    expect(
      render({
        ...base,
        probe: { ...good, files: false, error: "no file API" },
      })[0],
    ).toMatch(/^bad remote file API: no file API; use a sandbox backend/);
  });

  it("shows the setup command without running it, and warns when the network is denied", () => {
    const setup = { command: "npm ci", timeoutSeconds: 900 };
    expect(render({ ...base, network: "allow", setup, probe: good })).toContain(
      "info remote setup: npm ci (runs once after the upload, up to 900 s)",
    );
    expect(render({ ...base, setup, probe: good })).toContainEqual(
      expect.stringMatching(
        /^warn remote setup: npm ci .*network is denied, so an install will fail: set sandbox\.network\.mode: allow/,
      ),
    );
  });

  it("shows this project's setup cache state as one row", () => {
    expect(
      render({
        ...base,
        probe: good,
        cache:
          "no snapshot yet; the first session saves one after the setup command",
      }),
    ).toContain(
      "info remote setup cache: no snapshot yet; the first session saves one after the setup command",
    );
    expect(render({ ...base, probe: good }).join("\n")).not.toContain(
      "setup cache",
    );
  });

  it("names the waiting patch and its pull command, and says when nothing was checked", () => {
    expect(
      render({
        ...base,
        probe: good,
        waiting: { files: 3, patches: 2, latest: "2026-11-14T10:20:30.000Z" },
      }).at(-1),
    ).toBe(
      "warn waiting patch: 3 files in 2 unapplied sandbox patches (latest saved 2026-11-14 10:20 UTC); run acme sandbox pull",
    );
    expect(render({ ...base })).toEqual([
      expect.stringMatching(/^warn remote workspace: not checked/),
      expect.stringMatching(/^info remote network/),
      "info waiting patch: not checked: the project is not known",
    ]);
  });
});
