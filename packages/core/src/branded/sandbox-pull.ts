// `<command> sandbox pull`: review the patch a remote-workspace sandbox
// session left and apply it to the working tree. The patch is untrusted: it is
// validated first, shown, confirmed, and applied with `git apply --3way`,
// which neither commits nor runs any hook. With the main slot empty, the oldest
// patch another session parked for the project is pulled the same way.
import {
  mkdirSync,
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
  listParkedRemoteWorkspaceCheckpoints,
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
  validateRemoteWorkspacePatch,
} from "../remote-workspace.js";
import type { BrandedContext } from "./context.js";

/** Terminal control characters in untrusted text would let a patch rewrite the screen. */
function printable(text: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "?");
}

function failure(message: string, userAction?: string): PiShipError {
  return new PiShipError("CONFIG_INVALID", message, {
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
      "sandbox pull must run inside the git work tree the sandbox session was started for",
    );
  const root = realpathSync(top.stdout.toString("utf8").trim());
  const paths = remoteWorkspacePaths(ctx.stateDir, root);
  const parked = listParkedRemoteWorkspaceCheckpoints(ctx.stateDir, root);
  const main = readRemoteWorkspaceCheckpoint(ctx.stateDir, root);
  const checkpoint = main ?? parked[0];
  // Where the patch being pulled lives: the main slot, or a parked session root.
  const sourceState = main ? ctx.stateDir : (parked[0]?.stateDir ?? "");
  if (!checkpoint) {
    ctx.out(
      `No sandbox changes are waiting for ${root}. A remote-workspace session saves them when it ends.`,
    );
    return;
  }
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
        `${more} more sandbox patch${more === 1 ? " is" : "es are"} waiting; run ${ctx.metadata.app.command} sandbox pull again.`,
      );
  };
  if (checkpoint.meta.projectRoot !== root)
    throw failure(
      `The stored sandbox changes belong to ${checkpoint.meta.projectRoot}, not ${root}`,
      "Run sandbox pull inside that project, or sandbox pull --discard",
    );
  const policy = checkpoint.meta.pull;
  const interactiveOnly = policy?.confirm === "required";
  if (yes && interactiveOnly)
    throw failure(
      "This distribution's policy requires an interactive review of sandbox changes, so --yes is not accepted",
      `Run ${ctx.metadata.app.command} sandbox pull in a terminal and answer the prompt`,
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
      `The sandbox patch is refused as a whole and nothing was applied${result.protectedOnly ? " (this distribution's policy refuses a patch that touches protected files)" : ""}: ${result.refused.slice(0, 5).join("; ")}${result.refused.length > 5 ? `; and ${result.refused.length - 5} more` : ""}`,
      "Inspect the sandbox session, then run sandbox pull --discard",
    );
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
  const stat = await git(
    root,
    ["apply", "--stat", ...result.excludeArgs, "-"],
    checkpoint.patch,
  );
  if (stat.code !== 0)
    throw failure(
      `The sandbox patch does not parse: ${printable(stat.stderr).trim()}`,
      "Run sandbox pull --discard",
    );
  ctx.out(printable(stat.stdout.toString("utf8")).trimEnd());
  if (showDiff) ctx.out(printable(checkpoint.patch.toString("utf8")));
  else
    ctx.out(
      "The full diff is not shown; run sandbox pull --diff to review it before applying.",
    );
  if (!yes) {
    if (!process.stdin.isTTY)
      throw failure(
        "sandbox pull needs confirmation and there is no terminal",
        interactiveOnly
          ? `Run ${ctx.metadata.app.command} sandbox pull in a terminal`
          : `Review the changes, then run ${ctx.metadata.app.command} sandbox pull --yes`,
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
  const applied = await git(
    root,
    ["apply", "--3way", "--whitespace=nowarn", ...result.excludeArgs, "-"],
    checkpoint.patch,
  );
  if (applied.code !== 0) {
    // --3way leaves conflicts in the tree: markers in the file, an unmerged index entry, and
    // the rest of the patch already applied and staged. Running it again cannot work.
    const conflicted = (
      await git(root, ["diff", "--name-only", "--diff-filter=U", "-z"])
    ).stdout
      .toString("utf8")
      .split("\0")
      .filter(Boolean);
    if (conflicted.length > 0)
      throw failure(
        `The patch applied with conflicts in ${conflicted.length} file(s): ${conflicted.slice(0, 5).map(printable).join(", ")}${conflicted.length > 5 ? ", ..." : ""}. Conflict markers are in the working tree, and the patch's other files are applied and staged.`,
        `Resolve the conflict markers and git add those files. Do not run sandbox pull again: the patch is already applied. The stored copy is kept; run ${ctx.metadata.app.command} sandbox pull --discard when you are done`,
      );
    throw failure(
      `git apply failed and nothing was applied: ${printable(applied.stderr).trim()}`,
      "The stored changes are kept; fix the working tree and run sandbox pull again, or --discard",
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
  const latest = readRemoteWorkspaceCheckpoint(sourceState, root);
  if (latest?.patch.equals(checkpoint.patch) !== false) remove();
  else
    ctx.err(
      "A newer sandbox checkpoint was saved while this one was open; it is still stored for the next sandbox pull.",
    );
  ctx.out(
    `Applied ${result.files.length} file(s) to ${root}. Nothing was committed.`,
  );
  others();
}
