// Who may start a subagent child: a record a running session published and a
// nonce only its children received, and the workspace they may work in.
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import type { PiShipError } from "@piship/contracts";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertChildWorkspace,
  authenticateSubagentChild,
  publishSubagentOwner,
  SUBAGENT_TOKEN_ENV,
  SUBAGENT_OWNER_DIRECTORY,
} from "./subagent-owner.js";

let dirs: string[] = [];
const temp = (prefix: string) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  dirs.push(dir);
  return dir;
};
afterEach(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  dirs = [];
});

const PARENT = { session: "s1-1", workspace: "/work/project" };
const publish = (state: string) => {
  const env: NodeJS.ProcessEnv = {};
  publishSubagentOwner(state, PARENT, env);
  return env;
};
const refusal = (run: () => unknown): string => {
  try {
    run();
  } catch (error) {
    return (error as Error).message;
  }
  throw new Error("expected a refusal");
};
const records = (state: string) =>
  readdirSync(join(state, SUBAGENT_OWNER_DIRECTORY));
const posixOnly = process.platform === "win32" ? it.skip : it;

describe("a child proves a running session started it", () => {
  it("is told the parent's session and workspace by the nonce in its environment", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    expect(env[SUBAGENT_TOKEN_ENV]).toMatch(/^[0-9a-f]{64}$/);
    expect(authenticateSubagentChild(state, env)).toEqual(PARENT);
  });

  it("takes the nonce out of the child's environment, whether or not it was good", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    authenticateSubagentChild(state, env);
    expect(env).not.toHaveProperty(SUBAGENT_TOKEN_ENV);
    const bad: NodeJS.ProcessEnv = { [SUBAGENT_TOKEN_ENV]: "a".repeat(64) };
    expect(() => authenticateSubagentChild(state, bad)).toThrow();
    expect(bad).not.toHaveProperty(SUBAGENT_TOKEN_ENV);
  });

  it("refuses the marker alone, a malformed nonce, and a nonce nobody published", () => {
    const state = temp("piship-owner-");
    publish(state);
    for (const env of [
      {},
      { [SUBAGENT_TOKEN_ENV]: "" },
      { [SUBAGENT_TOKEN_ENV]: "../../etc/passwd" },
      { [SUBAGENT_TOKEN_ENV]: "b".repeat(64) },
    ])
      expect(refusal(() => authenticateSubagentChild(state, env))).toContain(
        "not started by a running session",
      );
  });

  it("refuses when there is no state directory yet", () => {
    const state = join(temp("piship-owner-"), "absent");
    const env = { [SUBAGENT_TOKEN_ENV]: "c".repeat(64) };
    expect(refusal(() => authenticateSubagentChild(state, env))).toContain(
      "not started by a running session",
    );
  });

  it("refuses a record whose session has ended", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    const [name] = records(state);
    const path = join(state, SUBAGENT_OWNER_DIRECTORY, name as string);
    // A process that has exited: its ID names nobody now.
    const gone = spawnSync(process.execPath, ["-e", "0"]).pid;
    const record = JSON.parse(readFileSync(path, "utf8"));
    writeFileSync(path, JSON.stringify({ ...record, pid: gone }), {
      mode: 0o600,
    });
    expect(refusal(() => authenticateSubagentChild(state, env))).toContain(
      "not started by a running session",
    );
  });

  it("refuses a record written on another host", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    const [name] = records(state);
    const path = join(state, SUBAGENT_OWNER_DIRECTORY, name as string);
    const record = JSON.parse(readFileSync(path, "utf8"));
    writeFileSync(path, JSON.stringify({ ...record, host: "other" }), {
      mode: 0o600,
    });
    expect(refusal(() => authenticateSubagentChild(state, env))).toContain(
      "not started by a running session",
    );
  });

  it("refuses a record whose process ID now belongs to a process that started at another time", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    const [name] = records(state);
    const path = join(state, SUBAGENT_OWNER_DIRECTORY, name as string);
    const record = JSON.parse(readFileSync(path, "utf8"));
    // The writer was killed and its ID given to this process, which started
    // later than the record says the writer did.
    writeFileSync(
      path,
      JSON.stringify({
        ...record,
        identity: null,
        started: Date.now() - 24 * 60 * 60 * 1000,
      }),
      { mode: 0o600 },
    );
    expect(refusal(() => authenticateSubagentChild(state, env))).toContain(
      "not started by a running session",
    );
  });

  posixOnly("does not follow a link put in place of the record", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    const [name] = records(state);
    const path = join(state, SUBAGENT_OWNER_DIRECTORY, name as string);
    // A private copy of the same valid record, elsewhere, and a link to it.
    const copy = join(temp("piship-owner-copy-"), "record.json");
    writeFileSync(copy, readFileSync(path), { mode: 0o600 });
    rmSync(path);
    symlinkSync(copy, path);
    expect(refusal(() => authenticateSubagentChild(state, env))).toContain(
      "not started by a running session",
    );
  });

  posixOnly("refuses a record with other hard links, or open to others", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    const [name] = records(state);
    const path = join(state, SUBAGENT_OWNER_DIRECTORY, name as string);
    chmodSync(path, 0o640);
    expect(
      refusal(() => authenticateSubagentChild(state, { ...env })),
    ).toContain("not started by a running session");
    chmodSync(path, 0o600);
    linkSync(path, join(temp("piship-owner-link-"), "alias.json"));
    expect(
      refusal(() => authenticateSubagentChild(state, { ...env })),
    ).toContain("not started by a running session");
  });

  posixOnly("keeps the record private to its user", () => {
    const state = temp("piship-owner-");
    publish(state);
    const directory = join(state, SUBAGENT_OWNER_DIRECTORY);
    const mode = (path: string) =>
      Number.parseInt(
        spawnSync("stat", [
          process.platform === "darwin" ? "-f" : "-c",
          process.platform === "darwin" ? "%Lp" : "%a",
          path,
        ]).stdout.toString(),
        8,
      );
    expect(mode(directory)).toBe(0o700);
    expect(mode(join(directory, records(state)[0] as string))).toBe(0o600);
  });

  posixOnly(
    "refuses a record readable by others, and a symlinked directory",
    () => {
      const state = temp("piship-owner-");
      const env = publish(state);
      const directory = join(state, SUBAGENT_OWNER_DIRECTORY);
      chmodSync(directory, 0o755);
      expect(
        refusal(() => authenticateSubagentChild(state, { ...env })),
      ).toContain("not started by a running session");
      chmodSync(directory, 0o700);
      expect(authenticateSubagentChild(state, { ...env })).toEqual(PARENT);
      // The directory swapped for a link to another one holding the record.
      const elsewhere = join(temp("piship-owner-"), "owners");
      mkdirSync(elsewhere, { mode: 0o700 });
      for (const name of records(state))
        writeFileSync(
          join(elsewhere, name),
          readFileSync(join(directory, name)),
          { mode: 0o600 },
        );
      rmSync(directory, { recursive: true });
      symlinkSync(elsewhere, directory);
      expect(
        refusal(() => authenticateSubagentChild(state, { ...env })),
      ).toContain("not started by a running session");
    },
  );

  it("removes the records of sessions that are gone when the next one starts", () => {
    const state = temp("piship-owner-");
    publish(state);
    const [name] = records(state);
    const path = join(state, SUBAGENT_OWNER_DIRECTORY, name as string);
    const gone = spawnSync(process.execPath, ["-e", "0"]).pid;
    writeFileSync(
      path,
      JSON.stringify({ ...JSON.parse(readFileSync(path, "utf8")), pid: gone }),
      { mode: 0o600 },
    );
    publish(state);
    expect(records(state)).toHaveLength(1);
    expect(records(state)).not.toContain(name);
  });
});

describe("a child works in its parent's workspace", () => {
  it("accepts the workspace and the directories below it", () => {
    const root = temp("piship-workspace-");
    mkdirSync(join(root, "a", "b"), { recursive: true });
    for (const cwd of [root, join(root, "a"), join(root, "a", "b")])
      expect(() => assertChildWorkspace(root, cwd)).not.toThrow();
  });

  it("refuses a directory outside it, a sibling that shares its prefix, and a link out", () => {
    const root = temp("piship-workspace-");
    const project = join(root, "project");
    mkdirSync(project);
    mkdirSync(join(root, "project-other"));
    mkdirSync(join(root, "elsewhere"));
    symlinkSync(join(root, "elsewhere"), join(project, "out"));
    for (const cwd of [
      root,
      join(root, "project-other"),
      join(root, "elsewhere"),
      join(project, "out"),
      tmpdir(),
    ])
      expect(refusal(() => assertChildWorkspace(project, cwd))).toContain(
        "outside its parent's workspace",
      );
  });

  it("names the directory and the workspace in its refusal, and what to do", () => {
    const project = temp("piship-workspace-");
    const elsewhere = temp("piship-elsewhere-");
    let error: PiShipError | undefined;
    try {
      assertChildWorkspace(project, elsewhere);
    } catch (caught) {
      error = caught as PiShipError;
    }
    expect(error?.message).toContain(elsewhere);
    expect(error?.message).toContain(project);
    expect(error?.userAction).toBe(
      "Omit cwd in the subagent call, or start the session in that directory",
    );
  });

  // `git worktree add`, the way pi-code's isolation: worktree creates one.
  describe("the worktree pi-code gives an isolated agent", () => {
    const git = (cwd: string, ...args: string[]) =>
      execFileSync(
        "git",
        ["-c", "user.name=t", "-c", "user.email=t@example.com", ...args],
        { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      );
    const repository = () => {
      const dir = temp("piship-repository-");
      git(dir, "init", "-q");
      git(dir, "commit", "-q", "--allow-empty", "-m", "first");
      return dir;
    };
    // A name pi-code's pattern accepts, unique to this run.
    const worktreeName = () =>
      `pi-agent-worktree-scout-${randomBytes(4).toString("hex")}`;
    const addWorktree = (repo: string) => {
      const dir = join(tmpdir(), worktreeName());
      dirs.push(dir);
      git(
        repo,
        "worktree",
        "add",
        "-q",
        "-b",
        `b-${randomBytes(3).toString("hex")}`,
        dir,
      );
      return dir;
    };
    const outside = (project: string, directory: string) =>
      refusal(() => assertChildWorkspace(project, directory));

    it("is accepted for the workspace's own repository, from the root or a subdirectory", () => {
      const repo = repository();
      mkdirSync(join(repo, "sub"));
      const worktree = addWorktree(repo);
      expect(() => assertChildWorkspace(repo, worktree)).not.toThrow();
      expect(() =>
        assertChildWorkspace(join(repo, "sub"), worktree),
      ).not.toThrow();
    });

    it("is accepted when the workspace is itself a linked worktree of that repository", () => {
      const repo = repository();
      const first = addWorktree(repo);
      const second = addWorktree(repo);
      expect(() => assertChildWorkspace(first, second)).not.toThrow();
    });

    it("is refused for another repository's worktree, and when the workspace is no repository", () => {
      const repo = repository();
      const other = addWorktree(repository());
      expect(outside(repo, other)).toContain("outside");
      expect(outside(temp("piship-plain-"), addWorktree(repo))).toContain(
        "outside",
      );
    });

    it("is refused when forged: the right name and a .git file, but no worktree behind it", () => {
      const repo = repository();
      const real = addWorktree(repo);
      const dotGit = readFileSync(join(real, ".git"), "utf8");
      const forge = (content: string | undefined, name = worktreeName()) => {
        const dir = join(tmpdir(), name);
        dirs.push(dir);
        mkdirSync(dir);
        if (content !== undefined) writeFileSync(join(dir, ".git"), content);
        return dir;
      };
      // No .git file; a .git file that names nothing; one that names a
      // directory outside the repository's worktrees; and one that names a
      // real worktree's directory, which does not name the forged one back.
      expect(outside(repo, forge(undefined))).toContain("outside");
      expect(outside(repo, forge("gitdir: /somewhere\n"))).toContain("outside");
      expect(outside(repo, forge(`gitdir: ${join(repo, ".git")}\n`))).toContain(
        "outside",
      );
      expect(outside(repo, forge(dotGit))).toContain("outside");
      // The right content under the wrong name is not pi-code's either.
      const wrong = join(tmpdir(), `not-${worktreeName()}`);
      dirs.push(wrong);
      mkdirSync(wrong);
      writeFileSync(join(wrong, ".git"), dotGit);
      expect(outside(repo, wrong)).toContain("outside");
    });
  });

  it("refuses a directory that does not exist", () => {
    expect(
      refusal(() => assertChildWorkspace("/work", "/no/such/directory")),
    ).toContain("cannot be used");
  });
});
