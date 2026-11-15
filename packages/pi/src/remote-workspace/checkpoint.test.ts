import { execFileSync, spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
  writeRemoteWorkspacePulled,
} from "@piship/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RemoteWorkspace } from "./checkpoint.js";
import type { SeedSandbox } from "./seed.js";

let base: string;
let project: string;
let remote: string;
let state: string;
let diffs: number;
let lastDiff: string;
let patch: string;
let failWrites: number;
const warnings: string[] = [];
const notices: string[] = [];

beforeEach(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), "piship-ckpt-")));
  project = join(base, "project");
  remote = join(base, "remote");
  state = join(base, "state");
  for (const dir of [project, remote, state]) mkdirSync(dir);
  diffs = 0;
  patch = "";
  failWrites = 0;
  warnings.length = 0;
  notices.length = 0;
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
const initProject = () => {
  git(project, "init", "-q");
  writeFileSync(join(project, "a.txt"), "a");
};

/** The checkpoint commit the fake sandbox reports for its nth patch read. */
const commitId = (n: number) => n.toString(16).padStart(40, "0");

/** The remote is a local directory; the patch read answers from `patch`. */
const sandbox: SeedSandbox = {
  files: {
    read: async () => Buffer.alloc(0),
    write: async (path, data) => {
      if (failWrites-- > 0) throw new Error("network down");
      writeFileSync(join(remote, path.slice(project.length + 1)), data);
    },
    stat: async () => undefined,
  },
  exec: (command, _cwd, options) =>
    new Promise((resolve) => {
      if (command.includes("commit-tree")) {
        diffs++;
        lastDiff = command;
        options.onData(Buffer.from(`${commitId(diffs)}\n${patch}`));
        return resolve({ exitCode: 0 });
      }
      const child = spawn("/bin/bash", ["-c", command], { cwd: remote });
      child.stdout.on("data", options.onData);
      child.stderr.on("data", options.onData);
      child.on("close", (exitCode) => resolve({ exitCode }));
    }),
};

const workspace = (
  session: string,
  maxPatchBytes?: number,
  extra: Partial<ConstructorParameters<typeof RemoteWorkspace>[0]> = {},
) =>
  new RemoteWorkspace({
    sandbox,
    root: project,
    stateDir: state,
    session,
    command: "piship",
    decide: async () => "allow",
    protectedPaths: () => [],
    seeded: () => {},
    warn: (message) => warnings.push(message),
    notify: (message) => notices.push(message),
    checkpoints: true,
    ...(maxPatchBytes ? { maxPatchBytes } : {}),
    ...extra,
  });
const diff = (name: string) =>
  `diff --git a/${name} b/${name}\n--- a/${name}\n+++ b/${name}\n`;
const slot = () => remoteWorkspacePaths(state, project);

describe.skipIf(process.platform === "win32")("RemoteWorkspace", () => {
  it("takes the per-turn checkpoint only after something ran, and the last one always", async () => {
    initProject();
    const ws = workspace("s1");
    await ws.ensureSeeded();
    expect(notices[0]).toMatch(/^Uploading 1 files \(0\.0 MiB\)/);
    await ws.checkpoint();
    expect(diffs).toBe(0);
    patch = diff("a.txt");
    await ws.track(Promise.resolve());
    await ws.checkpoint();
    await ws.checkpoint();
    expect(diffs).toBe(1);
    expect(readFileSync(slot().patch, "utf8")).toBe(patch);
    expect(await ws.finish()).toMatch(
      /^1 file changed in the sandbox; run piship sandbox pull/,
    );
    expect(diffs).toBe(2);
  });

  it("says in one line what the seed left out, and warns when policy withheld most of the project", async () => {
    initProject();
    for (const name of ["b", "c"])
      writeFileSync(join(project, `${name}.txt`), name);
    const ws = workspace("s8", undefined, {
      decide: async (path) => (path.endsWith("a.txt") ? "allow" : "skip"),
    });
    await ws.ensureSeeded();
    const left = notices.filter((line) => line.includes("Left out"));
    expect(left).toEqual([
      "Left out of the sandbox: 2 by policy. Policy withheld 2 of 3 project files, so the agent will not see most of the project.",
    ]);
    expect(notices.join("\n")).not.toContain("Your policy withheld");
    expect(ws.lookup()?.skipped(join(project, "b.txt"))).toBe("policy");

    notices.length = 0;
    rmSync(remote, { recursive: true });
    mkdirSync(remote);
    await workspace("s9", undefined, {
      decide: async (path) => (path.endsWith("b.txt") ? "skip" : "allow"),
    }).ensureSeeded();
    expect(notices.at(-1)).toBe("Left out of the sandbox: 1 by policy.");
  });

  it("remembers a seed failure no retry can cure, and retries a transient one", async () => {
    const ws = workspace("s2");
    await expect(ws.ensureSeeded()).rejects.toThrow(/git work tree/);
    initProject();
    await expect(ws.ensureSeeded()).rejects.toThrow(/git work tree/);

    const other = workspace("s3");
    failWrites = 1;
    await expect(other.ensureSeeded()).rejects.toThrow(/network down/);
    await expect(other.ensureSeeded()).resolves.toBeUndefined();
  });

  it("refuses a checkpoint over the cap, warns once, and keeps the earlier one", async () => {
    initProject();
    const ws = workspace("s4", 100);
    await ws.ensureSeeded();
    patch = diff("a.txt");
    await ws.track(Promise.resolve());
    await ws.checkpoint();
    expect(readFileSync(slot().patch, "utf8")).toBe(patch);
    patch = diff("a.txt").repeat(10);
    await ws.track(Promise.resolve());
    await ws.checkpoint();
    await ws.checkpoint();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/over the .*checkpoint cap/);
    expect(warnings[0]).toMatch(/last saved copy is kept/);
    expect(readFileSync(slot().patch, "utf8")).toBe(diff("a.txt"));
  });

  it("honours the manifest's seed limits and records its pull settings in the checkpoint", async () => {
    initProject();
    writeFileSync(join(project, "big.bin"), Buffer.alloc(2 * 1024 * 1024));
    const pull = { protectedFiles: "refuse", confirm: "required" } as const;
    const ws = workspace("s6", undefined, {
      seedLimits: { maxFileMiB: 1 },
      pull,
    });
    await ws.ensureSeeded();
    expect(existsSync(join(remote, "big.bin"))).toBe(false);
    expect(notices.at(-1)).toMatch(/1 over the per-file size cap/);
    patch = diff("a.txt");
    await ws.checkpoint(true);
    expect(JSON.parse(readFileSync(slot().meta, "utf8")).pull).toEqual(pull);

    const total = workspace("s7", undefined, {
      seedLimits: { maxTotalMiB: 1 },
    });
    writeFileSync(join(project, "big2.bin"), Buffer.alloc(1024 * 1024));
    writeFileSync(join(project, "big3.bin"), Buffer.alloc(1024 * 1024));
    await expect(total.ensureSeeded()).rejects.toThrow(
      /total cap.*\.gitignore/,
    );
  });

  it("parks its patch when another process holds the slot, and takes the slot back later", async () => {
    initProject();
    const ws = workspace("s5");
    await ws.ensureSeeded();
    patch = diff("a.txt");
    const lock = `${slot().dir}.lock`;
    mkdirSync(join(state, "sandbox-workspace"), { recursive: true });
    writeFileSync(lock, "");
    await ws.checkpoint(true);
    expect(existsSync(slot().patch)).toBe(false);
    expect(existsSync(join(state, "sandbox-workspace-parked", "s5"))).toBe(
      true,
    );
    // The agent undoes its work while the slot is still held: nothing stays parked.
    patch = "";
    await ws.checkpoint(true);
    expect(
      existsSync(
        remoteWorkspacePaths(
          join(state, "sandbox-workspace-parked", "s5"),
          project,
        ).dir,
      ),
    ).toBe(false);
    expect(await ws.finish()).toBeUndefined();
    patch = diff("a.txt");
    rmSync(lock);
    await ws.checkpoint(true);
    expect(readFileSync(slot().patch, "utf8")).toBe(patch);
    expect(existsSync(lock)).toBe(false);
  });

  it("records the checkpoint commit and diffs from it after its own patch was pulled", async () => {
    initProject();
    const ws = workspace("s6");
    await ws.ensureSeeded();
    patch = diff("a.txt");
    await ws.checkpoint(true);
    const first = commitId(1);
    expect(readRemoteWorkspaceCheckpoint(state, project)?.meta).toMatchObject({
      checkpointCommit: first,
    });
    // `sandbox pull` applied that patch and left its marker.
    writeRemoteWorkspacePulled(state, project, {
      session: "s6",
      checkpointCommit: first,
    });
    await ws.checkpoint(true);
    expect(lastDiff).toContain(`-p ${first}`);
    expect(lastDiff).toContain(`${first} "$c"`);
    expect(
      readRemoteWorkspaceCheckpoint(state, project)?.meta.checkpointCommit,
    ).toBe(commitId(2));
    // The marker was used up: the baseline stays where it moved.
    await ws.checkpoint(true);
    expect(lastDiff).toContain(`-p ${first}`);
  });

  it("never moves the baseline to a commit it did not record", async () => {
    initProject();
    const ws = workspace("s7");
    await ws.ensureSeeded();
    patch = diff("a.txt");
    await ws.checkpoint(true);
    const foreign = "f".repeat(40);
    writeRemoteWorkspacePulled(state, project, {
      session: "s7",
      checkpointCommit: foreign,
    });
    await ws.checkpoint(true);
    expect(lastDiff).not.toContain(foreign);
  });

  it("leaves a fresh lock alone and takes a stale one over without leftovers", async () => {
    initProject();
    const ws = workspace("s8");
    await ws.ensureSeeded();
    patch = diff("a.txt");
    const lock = `${slot().dir}.lock`;
    mkdirSync(join(state, "sandbox-workspace"), { recursive: true });
    writeFileSync(lock, "");
    await ws.checkpoint(true);
    expect(existsSync(lock)).toBe(true);
    expect(existsSync(slot().patch)).toBe(false);
    const old = new Date(Date.now() - 120_000);
    utimesSync(lock, old, old);
    await ws.checkpoint(true);
    expect(existsSync(slot().patch)).toBe(true);
    expect(existsSync(lock)).toBe(false);
    expect(
      readdirSync(join(state, "sandbox-workspace")).filter((n) =>
        n.includes(".lock"),
      ),
    ).toEqual([]);
  });
});
