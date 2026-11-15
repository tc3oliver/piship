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
export const ARCHIVE = ".piship-seed.tar";
/** Written before the extract, removed once the baseline is committed: it marks a seed of ours that did not finish. */
export const MARKER = ".piship-seed.started";
const EXTRACT_TIMEOUT_SECONDS = 300;
/** The upload of the whole project may be large: far longer than a file call. */
const UPLOAD_TIMEOUT_MS = 15 * 60 * 1000;

export type SeedSkipReason =
  | "policy"
  | "symlink"
  | "git"
  | "outside"
  | "not-file"
  | "reserved"
  | "too-large";

/** A seed failure a retry cannot cure: it is remembered and not repeated. */
export class SeedRefused extends Error {}

export interface SeedResult {
  /** The host's HEAD, or null before the first commit. */
  readonly baseHead: string | null;
  /**
   * The baseline commit made in the sandbox. It moves (one new commit) when a
   * policy-skipped file is uploaded later, so that file is not a change.
   */
  baselineCommit: string;
  /** Workspace-relative paths uploaded. */
  readonly uploaded: readonly string[];
  readonly skipped: readonly { path: string; reason: SeedSkipReason }[];
  /** What the seed left out and why, and how to add one such file later. */
  readonly lookup: SeedLookup;
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
  // Our own unfinished seed (the marker) is cleaned and redone.
  `if [ -e ${MARKER} ]; then find . -mindepth 1 -maxdepth 1 ! -name ${ARCHIVE} ! -name ${MARKER} -exec rm -rf -- {} +; fi`,
  // The baseline holds exactly the project: a workdir with anything else in
  // it (a home directory's dotfiles) is refused.
  `[ -z "$(ls -A | grep -v -e '^\\.piship-seed\\.tar$' -e '^\\.piship-seed\\.started$')" ] || { echo "piship-workdir-not-empty"; exit 1; }`,
  `: > ${MARKER}`,
  `tar -xf ${ARCHIVE} && rm -f ${ARCHIVE}`,
  "git init -q",
  `git add -A -- . ':(exclude)${MARKER}'`,
  "git -c user.name=piship -c user.email=piship@invalid -c commit.gpgsign=false commit -q --allow-empty -m piship-baseline",
  `rm -f ${MARKER}`,
  "git rev-parse HEAD",
].join(" && ");

const quote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;

/** What the seed left out and why, and how to add one such file later. */
export interface SeedLookup {
  /** The seed's reason for leaving a host path out of the sandbox. */
  skipped(hostPath: string): SeedSkipReason | undefined;
  /** Upload one policy-skipped file whose read was just approved, as part of the baseline. */
  adopt(hostPath: string, signal?: AbortSignal): Promise<void>;
}

/** Human text for a skip reason, finishing "<path> is not in the sandbox: it is ...". */
export function skipExplanation(reason: SeedSkipReason): string {
  switch (reason) {
    case "policy":
      return "withheld by policy when the sandbox was seeded";
    case "symlink":
      return "a symlink, which the sandbox copy leaves out; use the path it points to";
    case "too-large":
      return "over the per-file upload cap (sandbox.remote.seed.maxFileMiB); ask for a smaller file or raise the cap";
    case "git":
      return "inside .git, which the sandbox builds for itself";
    case "outside":
      return "reached through a path that leaves the project, so it was left out";
    case "not-file":
      return "a directory or submodule, which the sandbox copy leaves out";
    case "reserved":
      return "a name PiShip reserves for seeding the sandbox";
  }
}

const size = (bytes: number) =>
  bytes >= 1024 * 1024 ? `${bytes / 1024 / 1024} MiB` : `${bytes} bytes`;

export async function seedRemoteWorkspace(
  sandbox: SeedSandbox,
  projectRoot: string,
  decide: (absolutePath: string) => Promise<"allow" | "skip">,
  options: {
    signal?: AbortSignal;
    /** Smaller or larger caps than the documented defaults (the manifest sets them, in bytes here). */
    caps?: { totalCap: number; fileCap: number };
    /** One line before the upload, which can take a while. */
    progress?: (message: string) => void;
  } = {},
): Promise<SeedResult> {
  const root = await realpath(projectRoot);
  let listing: Buffer;
  try {
    listing = await git(root, ["ls-files", "-co", "--exclude-standard", "-z"]);
  } catch {
    throw new SeedRefused(
      "a remote workspace needs the project to be a git work tree, and git could not list its files; run git init in the project, then try again",
    );
  }
  const baseHead = await git(root, ["rev-parse", "HEAD"])
    .then((out) => out.toString("utf8").trim() || null)
    .catch(() => null);

  // A tracked file's mode is git's, on every platform: a Windows checkout has
  // no exec bit to read, and a later chmod would show up as a change.
  const indexModes = new Map<string, number>();
  const staged = await git(root, ["ls-files", "-s", "-z"]).catch(() =>
    Buffer.alloc(0),
  );
  for (const record of staged.toString("utf8").split("\0")) {
    const found = /^(\d{6}) [0-9a-f]+ \d\t(.*)$/s.exec(record);
    if (found?.[2])
      indexModes.set(found[2], found[1] === "100755" ? 0o755 : 0o644);
  }
  const modeOf = (path: string, info: { mode: number }) =>
    indexModes.get(path) ??
    (process.platform !== "win32" && info.mode & 0o111 ? 0o755 : 0o644);

  const totalCap = options.caps?.totalCap ?? SEED_TOTAL_CAP;
  const fileCap = options.caps?.fileCap ?? SEED_FILE_CAP;
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
    if (path === ARCHIVE || path === MARKER) {
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
    if (info.size > fileCap) {
      skip("too-large");
      continue;
    }
    total += info.size;
    if (total > totalCap)
      throw new SeedRefused(
        `the files uploaded to the sandbox (those git tracks or does not ignore, and policy allows) are over the ${size(totalCap)} total cap of the remote workspace seed; add the large directories to .gitignore, then try again`,
      );
    const data = await readFile(absolute);
    entries.push({
      path,
      mode: modeOf(path, info),
      data,
    });
  }

  const sizeOf = entries.reduce((n, e) => n + e.data.length, 0);
  options.progress?.(
    `Uploading ${entries.length} files (${(sizeOf / 1024 / 1024).toFixed(1)} MiB) to the sandbox`,
  );
  await sandbox.files.write(join(root, ARCHIVE), packTar(entries), {
    timeoutMs: UPLOAD_TIMEOUT_MS,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  let output = "";
  const result = await sandbox.exec(SCRIPT, root, {
    onData: (chunk) => {
      output += chunk.toString("utf8");
    },
    timeout: EXTRACT_TIMEOUT_SECONDS,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  if (output.includes("piship-workdir-not-empty"))
    throw new SeedRefused(
      "the sandbox's project directory is not empty, so the remote workspace cannot start from a clean baseline; set sandbox.workdir to a new directory",
    );
  const missing = /piship-missing-tool:(\w+)/.exec(output);
  if (missing)
    throw new SeedRefused(
      `the sandbox has no ${missing[1]}, which a remote workspace needs; use a template that includes tar and git`,
    );
  const commit = output.trim().split(/\s+/).at(-1) ?? "";
  if (result.exitCode !== 0 || !/^[0-9a-f]{40,64}$/.test(commit))
    throw new Error(
      `seeding the sandbox failed (exit ${result.exitCode}): ${output.trim().slice(-300)}`,
    );
  const reasons = new Map(skipped.map((item) => [item.path, item.reason]));
  const relativeOf = (hostPath: string) =>
    relative(root, hostPath).split(sep).join("/");
  let chain: Promise<unknown> = Promise.resolve();
  const lookup: SeedLookup = {
    skipped: (hostPath) => reasons.get(relativeOf(hostPath)),
    adopt: (hostPath, signal) => {
      const path = relativeOf(hostPath);
      const run = async () => {
        if (reasons.get(path) !== "policy") return;
        const absolute = join(root, ...path.split("/"));
        const info = await lstat(absolute);
        if (!info.isFile() || info.size > fileCap)
          throw new Error(
            `${path} cannot be copied to the sandbox (a non-regular file, or over the ${size(fileCap)} per-file cap); read it on the host instead`,
          );
        // The agent may already have made its own file there: keep it.
        if (
          !(await sandbox.files.stat(
            join(root, path),
            signal ? { signal } : {},
          ))
        ) {
          await sandbox.files.write(
            join(root, path),
            await readFile(absolute),
            {
              ...(signal ? { signal } : {}),
            },
          );
          // A temporary index builds the new baseline tree, so the work the
          // agent already staged is not folded into the baseline.
          const mode = modeOf(path, info);
          const output: string[] = [];
          const done = await sandbox.exec(
            [
              "set -e",
              'idx="$(git rev-parse --git-dir)/piship-baseline.idx"',
              'export GIT_INDEX_FILE="$idx"',
              'rm -f "$idx"',
              `git read-tree ${seeded.baselineCommit}`,
              ...(mode === 0o755 ? [`chmod 755 -- ${quote(path)}`] : []),
              `git add -f -- ${quote(path)}`,
              'tree="$(git write-tree)"',
              'rm -f "$idx"',
              'git -c user.name=piship -c user.email=piship@invalid -c commit.gpgsign=false commit-tree "$tree" -m piship-baseline',
            ].join("\n"),
            root,
            {
              onData: (chunk) => output.push(chunk.toString("utf8")),
              timeout: EXTRACT_TIMEOUT_SECONDS,
              ...(signal ? { signal } : {}),
            },
          );
          const commit = output.join("").trim().split(/\s+/).at(-1) ?? "";
          if (done.exitCode !== 0 || !/^[0-9a-f]{40,64}$/.test(commit))
            throw new Error(
              `copying ${path} into the sandbox failed (exit ${done.exitCode}); try the read again`,
            );
          seeded.baselineCommit = commit;
        }
        reasons.delete(path);
      };
      chain = chain.then(run, run);
      return chain as Promise<void>;
    },
  };
  const seeded: SeedResult = {
    baseHead,
    baselineCommit: commit,
    uploaded: entries.map((entry) => entry.path),
    skipped,
    lookup,
  };
  return seeded;
}
