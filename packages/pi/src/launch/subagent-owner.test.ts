// Who may start a subagent child: a record a running session published and a
// nonce only its children received, and the workspace they may work in.
import { spawnSync } from "node:child_process";
import {
  chmodSync,
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
  SUBAGENT_NONCE_ENV,
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
    expect(env[SUBAGENT_NONCE_ENV]).toMatch(/^[0-9a-f]{64}$/);
    expect(authenticateSubagentChild(state, env)).toEqual(PARENT);
  });

  it("takes the nonce out of the child's environment, whether or not it was good", () => {
    const state = temp("piship-owner-");
    const env = publish(state);
    authenticateSubagentChild(state, env);
    expect(env).not.toHaveProperty(SUBAGENT_NONCE_ENV);
    const bad: NodeJS.ProcessEnv = { [SUBAGENT_NONCE_ENV]: "a".repeat(64) };
    expect(() => authenticateSubagentChild(state, bad)).toThrow();
    expect(bad).not.toHaveProperty(SUBAGENT_NONCE_ENV);
  });

  it("refuses the marker alone, a malformed nonce, and a nonce nobody published", () => {
    const state = temp("piship-owner-");
    publish(state);
    for (const env of [
      {},
      { [SUBAGENT_NONCE_ENV]: "" },
      { [SUBAGENT_NONCE_ENV]: "../../etc/passwd" },
      { [SUBAGENT_NONCE_ENV]: "b".repeat(64) },
    ])
      expect(refusal(() => authenticateSubagentChild(state, env))).toContain(
        "not started by a running session",
      );
  });

  it("refuses when there is no state directory yet", () => {
    const state = join(temp("piship-owner-"), "absent");
    const env = { [SUBAGENT_NONCE_ENV]: "c".repeat(64) };
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

  it("accepts the git worktree pi-code gives an isolated agent, and no other temp directory", () => {
    const project = temp("piship-workspace-");
    const worktree = join(tmpdir(), `pi-agent-worktree-scout-${"0123abcd"}`);
    dirs.push(worktree);
    mkdirSync(worktree);
    // Not a worktree yet: no .git file.
    expect(refusal(() => assertChildWorkspace(project, worktree))).toContain(
      "outside",
    );
    writeFileSync(join(worktree, ".git"), "gitdir: /somewhere\n");
    expect(() => assertChildWorkspace(project, worktree)).not.toThrow();
    // The right content under the wrong name is not pi-code's.
    const other = join(tmpdir(), `not-pi-agent-worktree-${process.pid}`);
    dirs.push(other);
    mkdirSync(other);
    writeFileSync(join(other, ".git"), "gitdir: /somewhere\n");
    expect(refusal(() => assertChildWorkspace(project, other))).toContain(
      "outside",
    );
  });

  it("refuses a directory that does not exist", () => {
    expect(
      refusal(() => assertChildWorkspace("/work", "/no/such/directory")),
    ).toContain("cannot be used");
  });
});
