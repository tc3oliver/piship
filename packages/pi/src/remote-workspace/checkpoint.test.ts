import { execFileSync, spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { remoteWorkspacePaths } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RemoteWorkspace } from "./checkpoint.js";
import type { SeedSandbox } from "./seed.js";

let base: string;
let project: string;
let remote: string;
let state: string;
let diffs: number;
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
      if (command.includes("git diff --cached")) {
        diffs++;
        options.onData(Buffer.from(patch));
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
});
