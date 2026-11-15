// A checkpoint written while `sandbox pull` waits at the y/N prompt is not
// the one that was applied and must not be archived or deleted.
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
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { runSandbox } from "./branded/sandbox.js";
import {
  remoteWorkspacePaths,
  writeRemoteWorkspaceCheckpoint,
} from "./remote-workspace.js";

const prompt = vi.hoisted(() => ({ during: () => {} }));
vi.mock("node:readline", async (original) => {
  const actual = await original<typeof import("node:readline")>();
  return {
    ...actual,
    createInterface: () => ({
      once: () => {},
      question: (_query: string, answer: (value: string) => void) => {
        prompt.during();
        answer("y");
      },
      close: () => {},
    }),
  };
});

let temp: string;
let repo: string;
let state: string;
let ctx: BrandedContext;
const err: string[] = [];

const git = (cwd: string, ...args: string[]) =>
  execFileSync(
    "git",
    ["-c", "user.name=t", "-c", "user.email=t@invalid", ...args],
    { cwd },
  );

function patchFor(content: string): Buffer {
  const clone = join(temp, `clone-${Math.random().toString(16).slice(2)}`);
  git(temp, "clone", "-q", repo, clone);
  writeFileSync(join(clone, "a.txt"), content);
  git(clone, "add", "-A");
  return git(clone, "diff", "--cached", "--binary", "HEAD");
}
const store = (patch: Buffer, session: string) =>
  writeRemoteWorkspaceCheckpoint(state, repo, patch, {
    session,
    baseHead: null,
    files: 1,
  });

beforeEach(() => {
  temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-pull-race-")));
  repo = join(temp, "repo");
  state = join(temp, "state");
  mkdirSync(repo);
  mkdirSync(state);
  git(repo, "init", "-q");
  writeFileSync(join(repo, "a.txt"), "one\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "base");
  err.length = 0;
  ctx = {
    stateDir: state,
    metadata: { app: { command: "demo" } },
    out: () => {},
    err: (m: string) => err.push(m),
  } as unknown as BrandedContext;
  vi.spyOn(process, "cwd").mockReturnValue(repo);
  Object.defineProperty(process.stdin, "isTTY", {
    value: true,
    configurable: true,
  });
});
afterEach(() => {
  prompt.during = () => {};
  vi.restoreAllMocks();
  rmSync(temp, { recursive: true, force: true });
});

describe("sandbox pull with a checkpoint that changes during the prompt", () => {
  it("archives the applied bytes and keeps the newer checkpoint", async () => {
    const applied = patchFor("two\n");
    store(applied, "first");
    const newer = patchFor("three\n");
    prompt.during = () => void store(newer, "second");
    await runSandbox(ctx, ["pull"]);
    const paths = remoteWorkspacePaths(state, repo);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("two\n");
    const archived = readdirSync(paths.applied).filter((n) =>
      n.endsWith(".patch"),
    );
    expect(readFileSync(join(paths.applied, archived[0] as string))).toEqual(
      applied,
    );
    expect(readFileSync(paths.patch)).toEqual(newer);
    expect(err.join("\n")).toMatch(/newer sandbox checkpoint/);
  });

  it("removes the checkpoint when it did not change", async () => {
    store(patchFor("two\n"), "first");
    await runSandbox(ctx, ["pull"]);
    expect(existsSync(remoteWorkspacePaths(state, repo).patch)).toBe(false);
  });
});
