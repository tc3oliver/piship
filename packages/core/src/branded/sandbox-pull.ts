// `<command> sandbox pull`: review the patch a remote-workspace sandbox
// session left and apply it to the working tree. The patch is untrusted: it is
// validated first, shown, confirmed, and applied with `git apply --3way`,
// which neither commits nor runs any hook.
import { execFile } from "node:child_process";
import { mkdirSync, realpathSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { PiShipError } from "@piship/contracts";
import {
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
  validateRemoteWorkspacePatch,
} from "../remote-workspace.js";
import type { BrandedContext } from "./context.js";

function git(
  cwd: string,
  args: readonly string[],
  input?: Buffer,
): Promise<{ stdout: Buffer; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      "git",
      [...args],
      { cwd, encoding: "buffer", maxBuffer: 256 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code =
          error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        if (code === -1) reject(error);
        else resolve({ stdout, stderr: stderr.toString("utf8"), code });
      },
    );
    child.stdin?.end(input);
  });
}

/** Terminal control characters in untrusted text would let a patch rewrite the screen. */
function printable(text: string): string {
  return [...text]
    .map((c) => {
      const code = c.charCodeAt(0);
      const control =
        (code < 0x20 && c !== "\n" && c !== "\t") ||
        (code >= 0x7f && code <= 0x9f);
      return control ? "?" : c;
    })
    .join("");
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
  if (flags.some((f) => f !== "--yes" && f !== "--discard") || (yes && discard))
    throw failure(
      "Usage: sandbox pull [--yes] or sandbox pull --discard",
      `Run ${ctx.metadata.app.command} sandbox pull with at most one of --yes and --discard`,
    );
  const top = await git(process.cwd(), ["rev-parse", "--show-toplevel"]).catch(
    () => undefined,
  );
  if (!top || top.code !== 0)
    throw failure(
      "sandbox pull must run inside the git work tree the sandbox session was started for",
    );
  const root = realpathSync(top.stdout.toString("utf8").trim());
  const paths = remoteWorkspacePaths(ctx.stateDir, root);
  const checkpoint = readRemoteWorkspaceCheckpoint(ctx.stateDir, root);
  if (!checkpoint) {
    ctx.out(
      `No sandbox changes are waiting for ${root}. A remote-workspace session saves them when it ends.`,
    );
    return;
  }
  if (checkpoint.meta.projectRoot !== root)
    throw failure(
      `The stored sandbox changes belong to ${checkpoint.meta.projectRoot}, not ${root}`,
      "Run sandbox pull inside that project, or sandbox pull --discard",
    );
  if (discard) {
    rmSync(paths.patch, { force: true });
    rmSync(paths.meta, { force: true });
    ctx.out("The stored sandbox changes were discarded.");
    return;
  }
  if (checkpoint.patch.length === 0) {
    ctx.out("The sandbox session made no changes.");
    return;
  }
  // shortcut: only `.git` is refused; the sandbox package's protected git
  // paths (hooks, config, ...) are not reachable from core. `.git` covers them.
  const result = validateRemoteWorkspacePatch(checkpoint.patch);
  if (!result.ok)
    throw failure(
      `The sandbox patch is refused as a whole and nothing was applied: ${result.refused.slice(0, 5).join("; ")}${result.refused.length > 5 ? `; and ${result.refused.length - 5} more` : ""}`,
      "Inspect the sandbox session, then run sandbox pull --discard",
    );
  const stat = await git(root, ["apply", "--stat", "-"], checkpoint.patch);
  if (stat.code !== 0)
    throw failure(
      `The sandbox patch does not parse: ${printable(stat.stderr).trim()}`,
      "Run sandbox pull --discard",
    );
  ctx.out(printable(stat.stdout.toString("utf8")).trimEnd());
  ctx.out(printable(checkpoint.patch.toString("utf8")));
  if (!yes) {
    if (!process.stdin.isTTY)
      throw failure(
        "sandbox pull needs confirmation and there is no terminal",
        `Review the changes, then run ${ctx.metadata.app.command} sandbox pull --yes`,
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
    ["apply", "--3way", "--whitespace=nowarn", "-"],
    checkpoint.patch,
  );
  if (applied.code !== 0)
    throw failure(
      `git apply failed: ${printable(applied.stderr).trim()}`,
      "The stored changes are kept; fix the working tree and run sandbox pull again, or --discard",
    );
  mkdirSync(paths.applied, { recursive: true, mode: 0o700 });
  const stamp = checkpoint.meta.createdAt.replace(/[^0-9A-Za-z]/g, "");
  renameSync(paths.patch, join(paths.applied, `${stamp}.patch`));
  renameSync(paths.meta, join(paths.applied, `${stamp}.json`));
  ctx.out(
    `Applied ${result.files.length} file(s) to ${root}. Nothing was committed.`,
  );
}
