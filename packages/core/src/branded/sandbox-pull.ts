// `<command> sandbox pull`: review the patch a remote-workspace sandbox
// session left and apply it to the working tree. The patch is untrusted: it is
// validated first, shown, confirmed, and applied with `git apply --3way`,
// which neither commits nor runs any hook. With the main slot empty, the oldest
// patch another session parked for the project is pulled the same way.
// `--branch` applies it in a new git worktree on a new branch instead, and commits there.
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { PiShipError, printable } from "@piship/contracts";
import { runGit as git } from "../git-run.js";
import { shellArg } from "../invocation.js";
import {
  describeRemoteWorkspacePatch,
  listParkedRemoteWorkspaceCheckpoints,
  normalizeProjectRoot,
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
  validateRemoteWorkspacePatch,
  writeRemoteWorkspacePulled,
} from "../remote-workspace.js";
import type { BrandedContext } from "./context.js";

/**
 * What on this machine stops the patch from being written where it says: a
 * symlink on the path, a directory where a file goes, or a file where a parent
 * directory goes. Checked before anything is written.
 */
function pathProblem(
  root: string,
  files: readonly string[],
): { path: string; why: "symlink" | "directory" | "parent" } | undefined {
  for (const file of files) {
    let current = root;
    const segments = file.split("/");
    for (const [index, segment] of segments.entries()) {
      current = join(current, segment);
      let info: ReturnType<typeof lstatSync>;
      try {
        info = lstatSync(current);
      } catch {
        break; // not there yet: nothing below it exists either
      }
      if (info.isSymbolicLink()) return { path: file, why: "symlink" };
      const last = index === segments.length - 1;
      if (last && info.isDirectory()) return { path: file, why: "directory" };
      if (!last && !info.isDirectory()) return { path: file, why: "parent" };
    }
  }
  return undefined;
}

interface Snapshot {
  readonly files: Map<string, { data: Buffer; mode: number } | undefined>;
  /** Parent directories the patch may create: absent now, removed again if left empty. */
  readonly newDirs: string[];
}

/** The bytes, mode and existence of every file the patch names, so a failed write can be undone. */
function takeSnapshot(root: string, files: readonly string[]): Snapshot {
  const taken = new Map<string, { data: Buffer; mode: number } | undefined>();
  const newDirs = new Set<string>();
  for (const file of files) {
    const full = join(root, ...file.split("/"));
    try {
      taken.set(file, {
        data: readFileSync(full),
        mode: lstatSync(full).mode & 0o777,
      });
    } catch {
      taken.set(file, undefined);
    }
    let dir = dirname(full);
    while (dir !== root && dir.startsWith(root)) {
      try {
        lstatSync(dir);
        break;
      } catch {
        newDirs.add(dir);
        dir = dirname(dir);
      }
    }
  }
  return { files: taken, newDirs: [...newDirs].sort().reverse() };
}

/** Does the work tree still hold exactly the snapshot's bytes and modes? */
function matchesSnapshot(root: string, snapshot: Snapshot): boolean {
  for (const [file, before] of snapshot.files) {
    const full = join(root, ...file.split("/"));
    try {
      const now = {
        data: readFileSync(full),
        mode: lstatSync(full).mode & 0o777,
      };
      if (
        !before ||
        !now.data.equals(before.data) ||
        (process.platform !== "win32" && now.mode !== before.mode)
      )
        return false;
    } catch {
      if (before) return false;
    }
  }
  return true;
}

/** Put every named file back as it was, then report whether the tree matches the snapshot. */
function restoreSnapshot(root: string, snapshot: Snapshot): boolean {
  for (const [file, before] of snapshot.files) {
    const full = join(root, ...file.split("/"));
    try {
      if (before) {
        writeFileSync(full, before.data);
        chmodSync(full, before.mode);
      } else rmSync(full, { force: true });
    } catch {
      // reported by the check below
    }
  }
  for (const dir of snapshot.newDirs)
    try {
      rmdirSync(dir);
    } catch {
      // not empty or already gone
    }
  return matchesSnapshot(root, snapshot);
}

function failure(
  message: string,
  userAction?: string,
  code:
    | "CONFIG_INVALID"
    | "POLICY_DENIED"
    | "SANDBOX_UNAVAILABLE" = "CONFIG_INVALID",
): PiShipError {
  return new PiShipError(code, message, {
    component: "sandbox",
    ...(userAction ? { userAction } : {}),
  });
}

async function confirm(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.once("close", () => resolve(false));
    rl.question(question, (answer) => {
      rl.close();
      resolve(/^y(es)?$/i.test(answer.trim()));
    });
  });
}

function usage(command: string): string {
  return [
    `Usage: ${command} sandbox pull [--diff] [--yes] [--branch [<name>]]`,
    `       ${command} sandbox pull --discard`,
    "  --diff           also print the full diff before asking",
    "  --yes            apply without the y/N question",
    "  --branch [name]  apply on a new branch in a new git worktree and commit there; your checkout is not touched (default name sandbox/<session>)",
    "  --discard        drop the stored changes without applying them",
  ].join("\n");
}

export async function sandboxPull(
  ctx: BrandedContext,
  flags: readonly string[],
): Promise<void> {
  const command = ctx.metadata.app.command;
  if (flags.includes("--help") || flags.includes("-h")) {
    ctx.out(usage(command));
    return;
  }
  let yes = false;
  let discard = false;
  let showDiff = false;
  let branch: string | true | undefined;
  let unknown = false;
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    if (flag === "--yes") yes = true;
    else if (flag === "--discard") discard = true;
    else if (flag === "--diff") showDiff = true;
    else if (flag === "--branch") {
      const next = flags[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        branch = next;
        i++;
      } else branch = true;
    } else unknown = true;
  }
  if (unknown || (discard && (yes || showDiff || branch !== undefined)))
    throw new PiShipError(
      "CONFIG_INVALID",
      `${unknown ? "That option is not recognised. " : "--discard cannot be combined with other options. "}${usage(command)}`,
      {
        component: "sandbox",
        userAction: `Run ${command} sandbox pull --help, or ${command} sandbox pull --discard alone`,
        usage: true,
      },
    );
  const top = await git(process.cwd(), ["rev-parse", "--show-toplevel"]).catch(
    () => undefined,
  );
  if (top?.code !== 0)
    throw failure(
      "This directory is not inside a git work tree, and sandbox pull applies changes to the project the sandbox session was started for",
      `Change to your project's directory, then run ${ctx.metadata.app.command} sandbox pull there`,
    );
  const root = realpathSync.native(top.stdout.toString("utf8").trim());
  const paths = remoteWorkspacePaths(ctx.stateDir, root);
  const parked = listParkedRemoteWorkspaceCheckpoints(ctx.stateDir, root);
  const main = readRemoteWorkspaceCheckpoint(ctx.stateDir, root);
  const checkpoint = main ?? parked[0];
  // Where the patch being pulled lives: the main slot, or a parked session root.
  const sourceState = main ? ctx.stateDir : (parked[0]?.stateDir ?? "");
  if (!main && (existsSync(paths.patch) || existsSync(paths.meta))) {
    if (discard) {
      rmSync(paths.patch, { force: true });
      rmSync(paths.meta, { force: true });
      ctx.out("The unreadable stored sandbox checkpoint was discarded.");
      return;
    }
    throw failure(
      `The stored checkpoint record ${paths.meta} is unreadable (damaged or incomplete), so the patch ${paths.patch} cannot be pulled safely`,
      `Run ${ctx.metadata.app.command} sandbox pull --discard to drop it`,
    );
  }
  if (!checkpoint) {
    ctx.out(
      `No sandbox changes are waiting for ${root}. A remote-workspace session saves them when it ends.`,
    );
    return;
  }
  const storedPatch = remoteWorkspacePaths(sourceState, root).patch;
  const cmd = `${ctx.metadata.app.command} sandbox pull`;
  const remove = () => {
    const source = remoteWorkspacePaths(sourceState, root);
    rmSync(source.patch, { force: true });
    rmSync(source.meta, { force: true });
    if (sourceState === ctx.stateDir) return;
    // Drop the emptied parked directories; rmdir refuses one that still holds another project.
    for (let dir = source.dir; dir !== sourceState; dir = dirname(dir))
      try {
        rmdirSync(dir);
      } catch {
        return;
      }
    try {
      rmdirSync(sourceState);
    } catch {}
  };
  const others = () => {
    const more = listParkedRemoteWorkspaceCheckpoints(
      ctx.stateDir,
      root,
    ).length;
    if (more > 0)
      ctx.out(
        `${more} more sandbox patch${more === 1 ? " is" : "es are"} waiting; run ${cmd} again.`,
      );
  };
  if (
    normalizeProjectRoot(checkpoint.meta.projectRoot) !==
    normalizeProjectRoot(root)
  )
    throw failure(
      `The stored sandbox changes belong to ${checkpoint.meta.projectRoot}, not ${root}`,
      `Run cd ${shellArg(checkpoint.meta.projectRoot)}, then ${cmd} to pull them there, or ${cmd} --discard to drop them`,
    );
  const policy = checkpoint.meta.pull;
  const interactiveOnly = policy?.confirm === "required";
  if (yes && interactiveOnly)
    throw failure(
      "This distribution's policy requires an interactive review of sandbox changes, so --yes is not accepted",
      `Run ${cmd} in a terminal and answer the prompt`,
      "POLICY_DENIED",
    );
  if (discard) {
    remove();
    ctx.out("The stored sandbox changes were discarded.");
    others();
    return;
  }
  if (checkpoint.patch.length === 0) {
    remove();
    ctx.out("The sandbox session made no changes.");
    others();
    return;
  }
  const result = await validateRemoteWorkspacePatch(
    checkpoint.patch,
    checkpoint.meta.protectedPaths ?? [],
    { cwd: root, skipProtected: policy?.protectedFiles !== "refuse" },
  );
  if (!result.ok)
    throw failure(
      `The sandbox patch is refused as a whole and nothing was applied${result.protectedOnly ? " (this distribution's policy refuses a patch that touches protected files)" : ""}: ${result.refused.slice(0, 5).map(printable).join("; ")}${result.refused.length > 5 ? `; and ${result.refused.length - 5} more` : ""}`,
      `The patch is stored at ${storedPatch} for you to inspect or apply by hand. Run ${cmd} --discard to drop it`,
      "POLICY_DENIED",
    );
  // A path on this machine the patch cannot be written over, named with the next step.
  const refusePath = (problem: NonNullable<ReturnType<typeof pathProblem>>) => {
    const name = printable(problem.path);
    return failure(
      problem.why === "symlink"
        ? `The sandbox patch touches ${name}, which is or sits under a symbolic link on this machine. A sandbox patch never writes through or over a symlink, so nothing was applied`
        : problem.why === "directory"
          ? `The sandbox patch writes the file ${name}, but a directory with that name exists on this machine, so nothing was applied`
          : `The sandbox patch writes ${name}, but a parent of it exists on this machine as a file, not a directory, so nothing was applied`,
      problem.why === "symlink"
        ? `Change that file by hand, or replace the symlink with a regular file, then run ${cmd} again. The stored patch is at ${storedPatch}; run ${cmd} --discard to drop it`
        : `Move or remove ${problem.why === "directory" ? "that directory" : "that file"}, then run ${cmd} again. The stored patch is at ${storedPatch}`,
      "POLICY_DENIED",
    );
  };
  const problem =
    branch === undefined ? pathProblem(root, result.files) : undefined;
  if (problem) throw refusePath(problem);
  if (result.skipped.length > 0) {
    const n = result.skipped.length;
    ctx.out(
      `Skipped ${n} protected file${n === 1 ? "" : "s"}: ${result.skipped.slice(0, 5).map(printable).join(", ")}${n > 5 ? `, and ${n - 5} more` : ""}`,
    );
    if (result.files.length === 0) {
      remove();
      ctx.out("Nothing else was in the patch, so there is nothing to apply.");
      others();
      return;
    }
  }
  const head = (await git(root, ["rev-parse", "HEAD"])).stdout
    .toString("utf8")
    .trim();
  const base = checkpoint.meta.baseHead;
  if (branch === undefined && base && head && base !== head)
    ctx.out(
      `Your branch has moved since the session started (${base.slice(0, 7)} -> ${head.slice(0, 7)}); the patch is applied to the current tree.`,
    );
  // git's own --stat shortens names to their tail and prints unicode as octal; list full paths.
  const changes = await describeRemoteWorkspacePatch(
    checkpoint.patch,
    result.excludeArgs,
    root,
  );
  const LISTED = 50;
  for (const change of changes.slice(0, LISTED))
    ctx.out(
      `  ${change.kind === "changed" ? "changed" : change.kind.padEnd(7)}  ${printable(change.path)}${change.mode ? `  (mode ${change.mode})` : ""}  ${change.added === undefined ? "binary" : `+${change.added} -${change.removed}`}`,
    );
  if (changes.length > LISTED)
    ctx.out(
      `  and ${changes.length - LISTED} more; use ${cmd} --diff to see them`,
    );
  if (showDiff) ctx.out(printable(checkpoint.patch.toString("utf8")));
  else ctx.out(`The full diff is not shown; run ${cmd} --diff to see it.`);

  // --branch: a new branch in a new worktree, so the checkout in `root` is never written.
  let target = root;
  // Set only once `git worktree add` succeeded: cleanup never touches what this command did not make.
  let created: { path: string; name: string; start: string } | undefined;
  let finished = false;
  const sessionId =
    checkpoint.meta.session.replace(/[^0-9A-Za-z._-]/g, "").slice(0, 8) ||
    checkpoint.meta.createdAt.replace(/[^0-9A-Za-z]/g, "");
  const cmdBranch =
    typeof branch === "string"
      ? `${cmd} --branch ${shellArg(branch)}`
      : `${cmd} --branch`;
  // No hook and no fsmonitor in any git command of this flow. The user's own clean/smudge
  // filters stay, as in a normal pull: they are the user's git configuration.
  const quiet = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
  ];
  const bgit = (cwd: string, args: readonly string[], input?: Buffer) =>
    git(cwd, [...quiet, ...args], input);
  const abandon = async () => {
    if (!created) return;
    const { path, name, start } = created;
    created = undefined;
    const removed = await bgit(root, [
      "worktree",
      "remove",
      "--force",
      path,
    ]).catch(() => undefined);
    if (removed?.code !== 0) {
      // git made this directory a moment ago; it is ours to remove.
      rmSync(path, { recursive: true, force: true });
      await bgit(root, ["worktree", "prune"]).catch(() => undefined);
    }
    // Delete the ref only while it still points where this command put it.
    await bgit(root, ["update-ref", "-d", `refs/heads/${name}`, start]).catch(
      () => undefined,
    );
  };
  if (branch !== undefined) {
    const name = typeof branch === "string" ? branch : `sandbox/${sessionId}`;
    // `--branch` expands `@{-1}` and `@{u}` to another branch's name; accept only a name it echoes back.
    const valid = await git(root, ["check-ref-format", "--branch", name]);
    if (
      valid.code !== 0 ||
      valid.stdout.toString("utf8").trim() !== name ||
      name.includes("@{") ||
      name.startsWith("-") ||
      name === "HEAD" ||
      name === "@" ||
      Buffer.byteLength(name) > 200
    )
      throw failure(
        `${printable(name)} is not a valid branch name, so nothing was created`,
        `Run ${cmd} --branch <name> with a name git accepts (see git check-ref-format), or ${cmd} --branch for the default`,
      );
    if (
      (
        await git(root, [
          "show-ref",
          "--verify",
          "--quiet",
          `refs/heads/${name}`,
        ])
      ).code === 0
    )
      throw failure(
        `The branch ${printable(name)} already exists, so nothing was created`,
        `Run ${cmd} --branch <another name>. The stored patch is at ${storedPatch}`,
      );
    const path = join(
      dirname(root),
      `${basename(root)}-sandbox-${name.replace(/^sandbox\//, "").replace(/[^0-9A-Za-z._-]+/g, "-")}`,
    );
    let present = true;
    try {
      lstatSync(path);
    } catch {
      present = false;
    }
    if (present)
      throw failure(
        `${path} already exists, so no worktree was created`,
        `Run ${cmd} --branch <another name>, or remove that directory first`,
      );
    const baseKnown =
      !!base &&
      (await git(root, ["cat-file", "-e", `${base}^{commit}`])).code === 0;
    const start = baseKnown ? base : head;
    if (!start)
      throw failure(
        "This repository has no commit yet, so there is nothing to branch from",
        `Make a first commit, or run ${cmd} without --branch`,
      );
    const startLabel = baseKnown
      ? `${start.slice(0, 7)}, the commit the session started from`
      : base
        ? `your current HEAD ${start.slice(0, 7)} (the session's starting commit ${base.slice(0, 7)} is not in this repository)`
        : `your current HEAD ${start.slice(0, 7)}`;
    const added = await bgit(root, [
      "worktree",
      "add",
      "-q",
      "-b",
      name,
      path,
      start,
    ]);
    if (added.code !== 0)
      throw failure(
        `git could not create the worktree: ${printable(added.stderr).trim()}`,
        `Nothing was changed. Fix that, or run ${cmd} without --branch`,
        "SANDBOX_UNAVAILABLE",
      );
    created = {
      path,
      name,
      start: (await git(root, ["rev-parse", `refs/heads/${name}`])).stdout
        .toString("utf8")
        .trim(),
    };
    target = realpathSync.native(path);
    ctx.out(`Created branch ${name} in ${target} from ${startLabel}.`);
  }
  try {
    if (branch !== undefined) {
      const again = pathProblem(target, result.files);
      if (again) throw refusePath(again);
    }
    // What will happen, before the one prompt: plain apply touches only the work tree;
    // --3way merges against the index, stages what it writes, and may leave conflict markers.
    const apply = (extra: readonly string[]) =>
      (branch === undefined ? git : bgit)(
        target,
        ["apply", "--whitespace=nowarn", ...extra, ...result.excludeArgs, "-"],
        checkpoint.patch,
      );
    // Why git could not apply: a stale or edited tree is cured by committing; anything else is shown as git said it.
    const cannot = (stderr: string, what: string) => {
      const shown = printable(stderr).trim();
      if (branch !== undefined)
        return failure(
          `The sandbox patch does not fit a clean checkout of the branch's starting commit, so no branch or worktree was kept: ${shown}`,
          `The session started from your working tree, which held edits that are not in that commit. Run ${cmd} without --branch to apply the patch to your working tree, or commit your work and run ${cmdBranch} again. The stored patch is at ${storedPatch}`,
          "SANDBOX_UNAVAILABLE",
        );
      const edited = [...stderr.matchAll(/error: (.+?): does not match index/g)]
        .map((m) => printable(m[1] ?? ""))
        .join(", ");
      return failure(
        `${what}: ${shown}`,
        /does not match index|patch does not apply|does not exist in index|already exists in working directory/.test(
          stderr,
        )
          ? `Commit or stash your edits to ${edited || "the files the patch names"}, then run ${cmd} again (it then merges 3-way; conflicts get markers). The stored patch is at ${storedPatch}`
          : `The stored patch is at ${storedPatch}; run ${cmd} --discard to drop it`,
        "SANDBOX_UNAVAILABLE",
      );
    };
    const where =
      branch === undefined ? "your working tree" : "the new worktree";
    const plainCheck = await apply(["--check"]);
    let threeWay = false;
    if (plainCheck.code === 0)
      ctx.out(`${result.files.length} file(s) apply cleanly to ${where}.`);
    else {
      const merge = await apply(["--3way", "--check"]);
      const conflicts = [
        ...merge.stderr.matchAll(/Applied patch to '(.*)' with conflicts/g),
      ].map((m) => printable(m[1] ?? ""));
      if (merge.code !== 0)
        throw cannot(
          merge.stderr,
          "The sandbox patch cannot be applied to your working tree, and nothing was changed",
        );
      threeWay = true;
      ctx.out(
        conflicts.length > 0
          ? `The patch needs a 3-way merge and will conflict in: ${conflicts.join(", ")}. Conflict markers will be written there, and git will stage the patch's files.`
          : "The patch needs a 3-way merge against your index; git will stage the patch's files.",
      );
    }
    if (!yes) {
      if (!process.stdin.isTTY)
        throw failure(
          "sandbox pull needs confirmation and there is no terminal",
          interactiveOnly
            ? `Run ${cmdBranch} in a terminal`
            : `Review the changes, then run ${cmdBranch} --yes`,
        );
      if (
        !(await confirm(
          branch === undefined
            ? `Apply ${result.files.length} file(s) to ${root}? [y/N] `
            : `Commit ${result.files.length} file(s) on branch ${created?.name} in ${target}? [y/N] `,
        ))
      ) {
        await abandon();
        finished = true;
        ctx.out(
          `Nothing was applied${branch === undefined ? "" : " and the new branch and worktree were removed"}; the changes are still stored. Run ${cmdBranch} again to apply them, or ${cmd} --discard to drop them.`,
        );
        return;
      }
    }
    // The work tree may have changed during the prompt. Plain apply when the patch still fits
    // (git checks, then writes: a failed write is undone from the snapshot, never retried as a
    // merge); --3way only when it does not fit.
    const again = pathProblem(target, result.files);
    if (again)
      throw failure(
        `${printable(again.path)} changed on this machine while you were deciding, so nothing was applied`,
        `Run ${cmdBranch} again`,
      );
    const snapshot = takeSnapshot(target, result.files);
    const fits = (await apply(["--check"])).code === 0;
    threeWay = !fits;
    const applied = await apply(fits ? [] : ["--3way"]);
    if (applied.code !== 0) {
      // --3way conflicts leave markers in the file, an unmerged index entry, and the rest of
      // the patch applied and staged. Running pull again cannot work.
      const conflicted =
        fits || branch !== undefined
          ? []
          : (
              await git(target, [
                "diff",
                "--name-only",
                "--diff-filter=U",
                "-z",
              ])
            ).stdout
              .toString("utf8")
              .split("\0")
              .filter(Boolean);
      if (conflicted.length > 0)
        throw failure(
          `The patch did not fit your working tree, so git merged it (3-way) and it conflicts in ${conflicted.length} file(s): ${conflicted.slice(0, 5).map(printable).join(", ")}${conflicted.length > 5 ? ", ..." : ""}. Conflict markers are in the working tree, and the patch's other files are applied and staged.`,
          `Resolve the conflict markers and git add those files. Do not run pull again: the patch is already applied. The stored copy is kept; run ${cmd} --discard when you are done`,
          "SANDBOX_UNAVAILABLE",
        );
      // Not a conflict: git may have written some files before failing. Say what is true.
      const untouched = matchesSnapshot(target, snapshot);
      const restored = untouched || restoreSnapshot(target, snapshot);
      throw cannot(
        applied.stderr,
        untouched
          ? "The patch could not be applied and nothing was changed"
          : restored
            ? "The patch could not be written completely; the files it names were put back exactly as they were, so nothing was changed"
            : `The patch could not be written completely and some of ${[...snapshot.files.keys()].slice(0, 5).map(printable).join(", ")} could not be put back; check git status`,
      );
    }
    // --branch: commit the result so the branch is usable; no hook, and the user's own signing config applies.
    let committed: string | undefined;
    let notCommitted: string | undefined;
    if (created) {
      // Exactly the patch's validated paths, forced past ignore rules, never read as pathspec magic.
      const literal = [
        "--literal-pathspecs",
        "add",
        "-A",
        "-f",
        "--",
        ...result.files,
      ];
      const staged = await bgit(target, literal);
      const commit =
        staged.code === 0
          ? await bgit(target, [
              "commit",
              "--no-verify",
              "-q",
              "-m",
              `sandbox: changes from session ${sessionId}`,
            ])
          : staged;
      const left =
        commit.code === 0
          ? (
              await bgit(target, [
                "--literal-pathspecs",
                "status",
                "--porcelain",
                "-z",
                "--",
                ...result.files,
              ])
            ).stdout.toString("utf8")
          : "";
      if (commit.code === 0 && left === "")
        committed = (
          await bgit(target, ["rev-parse", "--short", "HEAD"])
        ).stdout
          .toString("utf8")
          .trim();
      else if (commit.code === 0)
        notCommitted = "some of the patch's files are not in the commit";
      else
        notCommitted =
          printable(commit.stderr).trim().split("\n")[0] || "git commit failed";
    }
    finished = true;
    // Archive the bytes that were applied. A newer checkpoint written while the
    // prompt was open stays where it is.
    mkdirSync(paths.applied, { recursive: true, mode: 0o700 });
    const stamp = checkpoint.meta.createdAt.replace(/[^0-9A-Za-z]/g, "");
    writeFileSync(join(paths.applied, `${stamp}.patch`), checkpoint.patch, {
      mode: 0o600,
    });
    writeFileSync(
      join(paths.applied, `${stamp}.json`),
      `${JSON.stringify(checkpoint.meta)}\n`,
      { mode: 0o600 },
    );
    if (checkpoint.meta.checkpointCommit)
      writeRemoteWorkspacePulled(ctx.stateDir, root, {
        session: checkpoint.meta.session,
        checkpointCommit: checkpoint.meta.checkpointCommit,
      });
    const latest = readRemoteWorkspaceCheckpoint(sourceState, root);
    if (latest?.patch.equals(checkpoint.patch) !== false) remove();
    else
      ctx.err(
        `A newer sandbox checkpoint was saved while this one was open; it is still stored for the next ${cmd}.`,
      );
    if (created) {
      const dir = shellArg(target);
      ctx.out(
        `Applied ${result.files.length} file(s) in ${target} on branch ${created.name}${threeWay ? " with a 3-way merge" : ""}. ${
          committed
            ? `Committed as ${committed}; your own checkout was not touched.`
            : `They are staged but not committed (${notCommitted}). Fix that (for example set user.name and user.email), then run git -C ${dir} commit; your own checkout was not touched.`
        }`,
      );
      ctx.out(
        `Next: git -C ${dir} log -1 to look at it, git merge ${shellArg(created.name)} to take it, or git worktree remove ${dir}, then git branch -D ${shellArg(created.name)} to throw it away.`,
      );
    } else
      ctx.out(
        threeWay
          ? `Applied ${result.files.length} file(s) to ${root} with a 3-way merge; git staged them. Nothing was committed.`
          : `Applied ${result.files.length} file(s) to ${root}. They are changed in the working tree only: nothing was staged or committed.`,
      );
    others();
  } finally {
    if (!finished) await abandon();
  }
}
