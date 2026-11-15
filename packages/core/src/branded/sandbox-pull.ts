// `<command> sandbox pull`: review the patch a remote-workspace sandbox
// session left and apply it to the working tree. The patch is untrusted: it is
// validated first, shown, confirmed, and applied with `git apply --3way`,
// which neither commits nor runs any hook. With the main slot empty, the oldest
// patch another session parked for the project is pulled the same way.
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
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { PiShipError } from "@piship/contracts";
import { runGit as git } from "../git-run.js";
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

/** Terminal control/** Terminal control characters in untrusted text would let a patch rewrite the screen. */
function printable(text: string): string {
  return text.replace(
    // biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    "?",
  );
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

export async function sandboxPull(
  ctx: BrandedContext,
  flags: readonly string[],
): Promise<void> {
  const yes = flags.includes("--yes");
  const discard = flags.includes("--discard");
  const showDiff = flags.includes("--diff");
  if (
    flags.some((f) => f !== "--yes" && f !== "--discard" && f !== "--diff") ||
    (discard && (yes || showDiff))
  )
    throw failure(
      "Usage: sandbox pull [--diff] [--yes] or sandbox pull --discard",
      `Run ${ctx.metadata.app.command} sandbox pull with --discard alone, or with --diff and --yes`,
    );
  const top = await git(process.cwd(), ["rev-parse", "--show-toplevel"]).catch(
    () => undefined,
  );
  if (top?.code !== 0)
    throw failure(
      "This directory is not inside a git work tree, and sandbox pull applies changes to the project the sandbox session was started for",
      `Run cd <your project> && ${ctx.metadata.app.command} sandbox pull from that project's root`,
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
      `Run ${cmd} inside that project, or ${cmd} --discard`,
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
      `The sandbox is gone; the patch is stored at ${storedPatch} for you to inspect or apply by hand. Run ${cmd} --discard to drop it`,
      "POLICY_DENIED",
    );
  const problem = pathProblem(root, result.files);
  if (problem) {
    const name = printable(problem.path);
    throw failure(
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
  }
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
  if (base && head && base !== head)
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
  else
    ctx.out(
      `The full diff is not shown; run ${cmd} --diff to review it before applying.`,
    );
  // What will happen, before the one prompt: plain apply touches only the work tree;
  // --3way merges against the index, stages what it writes, and may leave conflict markers.
  const apply = (extra: readonly string[]) =>
    git(
      root,
      ["apply", "--whitespace=nowarn", ...extra, ...result.excludeArgs, "-"],
      checkpoint.patch,
    );
  // Why git could not apply: a stale or edited tree is cured by committing; anything else is shown as git said it.
  const cannot = (stderr: string, what: string) => {
    const shown = printable(stderr).trim();
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
  const plainCheck = await apply(["--check"]);
  let threeWay = false;
  if (plainCheck.code === 0)
    ctx.out(
      `${result.files.length} file(s) apply cleanly to your working tree.`,
    );
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
          ? `Run ${cmd} in a terminal`
          : `Review the changes, then run ${cmd} --yes`,
      );
    if (
      !(await confirm(
        `Apply ${result.files.length} file(s) to ${root}? [y/N] `,
      ))
    ) {
      ctx.out("Nothing was applied; the changes are still stored.");
      return;
    }
  }
  // The work tree may have changed during the prompt. Plain apply when the patch still fits
  // (git checks, then writes: a failed write is undone from the snapshot, never retried as a
  // merge); --3way only when it does not fit.
  const again = pathProblem(root, result.files);
  if (again)
    throw failure(
      `${printable(again.path)} changed on this machine while you were deciding, so nothing was applied`,
      `Run ${cmd} again`,
    );
  const snapshot = takeSnapshot(root, result.files);
  const fits = (await apply(["--check"])).code === 0;
  threeWay = !fits;
  const applied = await apply(fits ? [] : ["--3way"]);
  if (applied.code !== 0) {
    // --3way conflicts leave markers in the file, an unmerged index entry, and the rest of
    // the patch applied and staged. Running pull again cannot work.
    const conflicted = fits
      ? []
      : (
          await git(root, ["diff", "--name-only", "--diff-filter=U", "-z"])
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
    const untouched = matchesSnapshot(root, snapshot);
    const restored = untouched || restoreSnapshot(root, snapshot);
    throw cannot(
      applied.stderr,
      untouched
        ? "The patch could not be applied and nothing was changed"
        : restored
          ? "The patch could not be written completely; the files it names were put back exactly as they were, so nothing was changed"
          : `The patch could not be written completely and some of ${[...snapshot.files.keys()].slice(0, 5).map(printable).join(", ")} could not be put back; check git status`,
    );
  }
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
  ctx.out(
    threeWay
      ? `Applied ${result.files.length} file(s) to ${root} with a 3-way merge; git staged them. Nothing was committed.`
      : `Applied ${result.files.length} file(s) to ${root}. They are changed in the working tree only: nothing was staged or committed.`,
  );
  others();
}
