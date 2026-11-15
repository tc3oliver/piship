// Seeds a remote workspace: the project's files, filtered by policy, go into
// the sandbox as one tar, which is extracted and committed as a baseline the
// session's changes are later diffed against.
import { execFile } from "node:child_process";
import { lstat, readFile, realpath } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { ActiveSandbox } from "@piship/sandbox";
import { packTar, type TarEntry } from "./tar.js";

export const SEED_TOTAL_CAP = 200 * 1024 * 1024;
export const SEED_FILE_CAP = 50 * 1024 * 1024;
const ARCHIVE = ".piship-seed.tar";
const EXTRACT_TIMEOUT_SECONDS = 300;

export type SeedSkipReason =
  | "policy"
  | "symlink"
  | "git"
  | "outside"
  | "not-file"
  | "reserved";

export interface SeedResult {
  /** The host's HEAD, or null before the first commit. */
  readonly baseHead: string | null;
  /** The baseline commit made in the sandbox. */
  readonly baselineCommit: string;
  /** Workspace-relative paths uploaded. */
  readonly uploaded: readonly string[];
  readonly skipped: readonly { path: string; reason: SeedSkipReason }[];
}

export type SeedSandbox = Pick<ActiveSandbox, "exec"> & {
  readonly files: NonNullable<ActiveSandbox["files"]>;
};

function git(root: string, args: string[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      args,
      { cwd: root, encoding: "buffer", maxBuffer: 256 * 1024 * 1024 },
      (error, stdout) => (error ? reject(error) : resolve(stdout)),
    );
  });
}

// The extract and baseline, as specified; each tool is checked first so a
// template without it fails with its name.
const SCRIPT = [
  'for t in tar git; do command -v $t >/dev/null 2>&1 || { echo "piship-missing-tool:$t"; exit 127; }; done',
  `tar -xf ${ARCHIVE} && rm -f ${ARCHIVE}`,
  "git init -q",
  "git add -A",
  "git -c user.name=piship -c user.email=piship@invalid -c commit.gpgsign=false commit -q --allow-empty -m piship-baseline",
  "git rev-parse HEAD",
].join(" && ");

export async function seedRemoteWorkspace(
  sandbox: SeedSandbox,
  projectRoot: string,
  decide: (absolutePath: string) => Promise<"allow" | "skip">,
  options: { signal?: AbortSignal } = {},
): Promise<SeedResult> {
  const root = await realpath(projectRoot);
  let listing: Buffer;
  try {
    listing = await git(root, ["ls-files", "-co", "--exclude-standard", "-z"]);
  } catch {
    throw new Error(
      "a remote workspace needs the project to be a git work tree, and git could not list its files",
    );
  }
  const baseHead = await git(root, ["rev-parse", "HEAD"])
    .then((out) => out.toString("utf8").trim() || null)
    .catch(() => null);

  const entries: TarEntry[] = [];
  const skipped: { path: string; reason: SeedSkipReason }[] = [];
  let total = 0;
  const seen = new Set<string>();
  for (const path of listing.toString("utf8").split("\0")) {
    if (!path || seen.has(path)) continue;
    seen.add(path);
    const skip = (reason: SeedSkipReason) => skipped.push({ path, reason });
    const segments = path.split("/");
    if (segments.some((s) => s.toLowerCase() === ".git")) {
      skip("git");
      continue;
    }
    if (path === ARCHIVE) {
      skip("reserved");
      continue;
    }
    if (
      path.startsWith("/") ||
      path.includes("\\") ||
      segments.some((s) => s === ".." || s === "." || s === "")
    ) {
      skip("outside");
      continue;
    }
    const absolute = join(root, ...segments);
    const info = await lstat(absolute).catch(() => undefined);
    if (!info) continue; // tracked but deleted
    if (info.isSymbolicLink()) {
      skip("symlink");
      continue;
    }
    if (!info.isFile()) {
      skip("not-file"); // a directory, such as a submodule
      continue;
    }
    // A symlinked directory on the way would lead outside the project.
    const real = await realpath(absolute).catch(() => undefined);
    if (
      real === undefined ||
      relative(root, real).split(sep).join("/") !== path
    ) {
      skip("outside");
      continue;
    }
    if ((await decide(absolute)) !== "allow") {
      skip("policy");
      continue;
    }
    if (info.size > SEED_FILE_CAP)
      throw new Error(
        `${path} is larger than the ${SEED_FILE_CAP / 1024 / 1024} MiB single-file cap of the remote workspace seed`,
      );
    total += info.size;
    if (total > SEED_TOTAL_CAP)
      throw new Error(
        `the project is larger than the ${SEED_TOTAL_CAP / 1024 / 1024} MiB cap of the remote workspace seed`,
      );
    const data = await readFile(absolute);
    entries.push({
      path,
      mode: process.platform !== "win32" && info.mode & 0o111 ? 0o755 : 0o644,
      data,
    });
  }

  await sandbox.files.write(
    join(root, ARCHIVE),
    packTar(entries),
    options.signal ? { signal: options.signal } : undefined,
  );
  let output = "";
  const result = await sandbox.exec(SCRIPT, root, {
    onData: (chunk) => {
      output += chunk.toString("utf8");
    },
    timeout: EXTRACT_TIMEOUT_SECONDS,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  const missing = /piship-missing-tool:(\w+)/.exec(output);
  if (missing)
    throw new Error(
      `the sandbox has no ${missing[1]}, which a remote workspace needs; use a template that includes tar and git`,
    );
  const commit = output.trim().split(/\s+/).at(-1) ?? "";
  if (result.exitCode !== 0 || !/^[0-9a-f]{40,64}$/.test(commit))
    throw new Error(
      `seeding the sandbox failed (exit ${result.exitCode}): ${output.trim().slice(-300)}`,
    );
  return {
    baseHead,
    baselineCommit: commit,
    uploaded: entries.map((entry) => entry.path),
    skipped,
  };
}
