// Seeds a remote workspace: the project's files, filtered by policy, go into
// the sandbox as tar.gz parts, which are extracted and committed as a baseline the
// session's changes are later diffed against.
import { execFile } from "node:child_process";
import { lstat, readFile, realpath } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { promisify } from "node:util";
import { gzip as gzipCallback } from "node:zlib";
import type { ActiveSandbox } from "@piship/sandbox";
import { printable } from "./printable.js";
import { packTar, type TarEntry } from "./tar.js";

export const SEED_TOTAL_CAP = 200 * 1024 * 1024;
export const SEED_FILE_CAP = 50 * 1024 * 1024;
export const ARCHIVE = ".piship-seed.tar";
/** Written before the extract, removed once the baseline is committed: it marks a seed of ours that did not finish. */
export const MARKER = ".piship-seed.started";
/** The uploaded paths, NUL separated: an overlay removes what is not on this list. */
export const KEEP = ".piship-seed.keep";
/** Sent inside the last part: the uploaded paths as JSON, which the finish moves into `.git`, out of the baseline and every patch. */
export const UPLOADED = ".piship-seed.uploaded";
/** Sent inside the last part of an overlay: what the snapshot's seed uploaded and this one does not, NUL separated. */
export const DROP = ".piship-seed.drop";
/** Where the snapshot keeps the list of uploaded paths, made before any agent acted. */
const LIST = ".git/piship-uploaded.json";
export const RESERVED = new Set([ARCHIVE, MARKER, KEEP, UPLOADED, DROP]);
const EXTRACT_TIMEOUT_SECONDS = 300;
/** The upload of the whole project may be large: far longer than a file call. */
const UPLOAD_TIMEOUT_MS = 15 * 60 * 1000;
/** Uncompressed bytes (files and tar headers) in one uploaded part; a larger file is a part of its own. */
const PART_BYTES = 32 * 1024 * 1024;
/** Files inspected or read at once. */
const CONCURRENCY = 32;
const gzip = promisify(gzipCallback);

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

/**
 * How the project reaches the sandbox. `fresh`: into an empty directory.
 * `overlay`: over the tree a snapshot of this host's own earlier seed holds
 * (the project, its `.git`, and the setup command's ignored output): the
 * files are extracted over it, what is not uploaded and not ignored is
 * removed, and the baseline is made anew. `reset`: clean an overlay that
 * failed, then seed as `fresh`.
 */
export type SeedMode = "fresh" | "overlay" | "reset";

// The extract and baseline, as specified: PREPARE runs with the first part,
// EXTRACT with each, FINISH with the last. Each tool is checked first so a
// template without it fails with its name.
const CLEAN = `find . -mindepth 1 -maxdepth 1 ! -name ${ARCHIVE} ! -name ${MARKER} -exec rm -rf -- {} +`;
const TOOLS =
  'for t in tar gzip git; do command -v $t >/dev/null 2>&1 || { echo "piship-missing-tool:$t"; exit 127; }; done';
const prepare = (mode: SeedMode) =>
  mode === "overlay"
    ? [TOOLS, `: > ${MARKER}`]
    : [
        TOOLS,
        // Our own unfinished seed (the marker) is cleaned and redone.
        mode === "reset" ? CLEAN : `if [ -e ${MARKER} ]; then ${CLEAN}; fi`,
        // The baseline holds exactly the project: a workdir with anything else in
        // it (a home directory's dotfiles) is refused.
        `[ -z "$(ls -A | grep -v -e '^\\.piship-seed\\.tar$' -e '^\\.piship-seed\\.started$')" ] || { echo "piship-workdir-not-empty"; exit 1; }`,
        `: > ${MARKER}`,
      ];
const EXTRACT = `tar -xzf ${ARCHIVE} && rm -f ${ARCHIVE}`;
// Two temporary indexes, one of the uploaded paths and one of every file git
// would add: the second minus the first is what is neither uploaded nor
// ignored, which the project no longer has.
const REMOVE_STALE = [
  // What the snapshot's seed uploaded and this one does not, whatever .gitignore says.
  `xargs -0 rm -f -- < ${DROP}`,
  `rm -f ${DROP}`,
  'idx="$(git rev-parse --git-dir)/piship-keep.idx"',
  'export GIT_INDEX_FILE="$idx"',
  'rm -f "$idx"',
  `git update-index --add -z --stdin < ${KEEP}`,
  'keep="$(git write-tree)"',
  'rm -f "$idx"',
  `git add -A -- . ':(exclude)${MARKER}' ':(exclude)${KEEP}' ':(exclude)${UPLOADED}'`,
  'all="$(git write-tree)"',
  'rm -f "$idx"',
  "unset GIT_INDEX_FILE",
  // GNU xargs runs rm once with no operands, which is a no-op with -f.
  'git diff-tree -r --name-only --diff-filter=A -z "$keep" "$all" | xargs -0 rm -f --',
];
const finish = (mode: SeedMode, autocrlf: boolean) => [
  ...(mode === "overlay" ? [...REMOVE_STALE, "rm -rf .git"] : []),
  "git init -q",
  // The host checks out CRLF and stores LF: the sandbox stores LF too, so a
  // tool there that writes LF changes only the lines it changed.
  ...(autocrlf ? ["git config core.autocrlf input"] : []),
  `mv ${UPLOADED} ${LIST}`,
  `git add -A -- . ':(exclude)${MARKER}' ':(exclude)${KEEP}'`,
  "git -c user.name=piship -c user.email=piship@invalid -c commit.gpgsign=false commit -q --allow-empty -m piship-baseline",
  `rm -f ${MARKER} ${KEEP}`,
  "git rev-parse HEAD",
];

/** A path the seed could have uploaded: anything else in a list from the sandbox is not trusted. */
function uploadable(path: unknown): path is string {
  if (typeof path !== "string" || path.includes("\0")) return false;
  const segments = path.split("/");
  return !(
    RESERVED.has(path) ||
    path.startsWith("/") ||
    path.includes("\\") ||
    segments.some(
      (s) => s === ".." || s === "." || s === "" || s.toLowerCase() === ".git",
    )
  );
}

/**
 * The paths the snapshot's seed uploaded, or undefined when the list is
 * missing or malformed: the overlay then cannot tell what is stale, and the
 * sandbox is reset instead of trusted in part.
 */
async function readUploadedList(
  sandbox: SeedSandbox,
  root: string,
  signal: AbortSignal | undefined,
): Promise<string[] | undefined> {
  try {
    const data = await sandbox.files.read(
      join(root, ...LIST.split("/")),
      signal ? { signal } : {},
    );
    const value = JSON.parse(data.toString("utf8")) as {
      version?: unknown;
      paths?: unknown;
    } | null;
    if (value?.version !== 1 || !Array.isArray(value.paths)) return undefined;
    return value.paths.every(uploadable)
      ? (value.paths as string[])
      : undefined;
  } catch {
    return undefined;
  }
}

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
    /** Where the project goes; default `fresh`. */
    mode?: SeedMode;
  } = {},
): Promise<SeedResult> {
  const root = await realpath(projectRoot);
  const mode = options.mode ?? "fresh";
  let listing: Buffer;
  try {
    listing = await git(root, ["ls-files", "-co", "--exclude-standard", "-z"]);
  } catch {
    throw new SeedRefused(
      "a remote workspace needs the project to be a git work tree, and git could not list its files; run git init in the project, then try again",
    );
  }
  const previous =
    mode === "overlay"
      ? await readUploadedList(sandbox, root, options.signal)
      : undefined;
  if (mode === "overlay" && !previous)
    throw new Error(
      "the cached sandbox does not say what it was seeded with, so it cannot be overlaid",
    );
  const autocrlf = await git(root, ["config", "--get", "core.autocrlf"])
    .then((out) => out.toString("utf8").trim().toLowerCase() === "true")
    .catch(() => false);
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
  const skipped: { path: string; reason: SeedSkipReason }[] = [];
  interface Candidate {
    path: string;
    absolute: string;
    mode: number;
    size: number;
  }
  // Decide one listed path: a file to upload, a reason to leave it out, or
  // nothing (tracked but deleted).
  const inspect = async (
    path: string,
  ): Promise<Candidate | SeedSkipReason | undefined> => {
    const segments = path.split("/");
    if (segments.some((s) => s.toLowerCase() === ".git")) return "git";
    if (RESERVED.has(path)) return "reserved";
    if (
      path.startsWith("/") ||
      path.includes("\\") ||
      segments.some((s) => s === ".." || s === "." || s === "")
    )
      return "outside";
    const absolute = join(root, ...segments);
    const info = await lstat(absolute).catch(() => undefined);
    if (!info) return undefined; // tracked but deleted
    if (info.isSymbolicLink()) return "symlink";
    if (!info.isFile()) return "not-file"; // a directory, such as a submodule
    // A symlinked directory on the way would lead outside the project.
    const real = await realpath(absolute).catch(() => undefined);
    if (
      real === undefined ||
      relative(root, real).split(sep).join("/") !== path
    )
      return "outside";
    if ((await decide(absolute)) !== "allow") return "policy";
    if (info.size > fileCap) return "too-large";
    return { path, absolute, mode: modeOf(path, info), size: info.size };
  };
  // Only metadata is held here; the bytes are read part by part below.
  const files: Candidate[] = [];
  let total = 0;
  const paths = [...new Set(listing.toString("utf8").split("\0"))].filter(
    Boolean,
  );
  for (let at = 0; at < paths.length; at += CONCURRENCY) {
    const batch = paths.slice(at, at + CONCURRENCY);
    const found = await Promise.all(batch.map(inspect));
    found.forEach((item, i) => {
      if (typeof item === "string")
        skipped.push({ path: batch[i] as string, reason: item });
      else if (item) files.push(item);
    });
    for (const item of found) {
      if (typeof item !== "object") continue;
      total += item.size;
      if (total > totalCap)
        throw new SeedRefused(
          `the files uploaded to the sandbox (those git tracks or does not ignore, and policy allows) are over the ${size(totalCap)} total cap of the remote workspace seed; add the large directories to .gitignore, then try again`,
        );
    }
  }

  // Several tar.gz parts of bounded size, uploaded and extracted one after
  // another, so memory is about one part and not the project.
  const parts: Candidate[][] = [[]];
  let partBytes = 0;
  for (const file of files) {
    const weight = file.size + 512; // the tar header counts
    const current = parts.at(-1) as Candidate[];
    if (current.length && partBytes + weight > PART_BYTES) {
      parts.push([]);
      partBytes = 0;
    }
    (parts.at(-1) as Candidate[]).push(file);
    partBytes += weight;
  }
  const mib = (bytes: number) => (bytes / 1024 / 1024).toFixed(1);
  const uploaded: string[] = [];
  let sent = 0;
  let commit = "";
  for (const [index, part] of parts.entries()) {
    const entries: TarEntry[] = [];
    for (let at = 0; at < part.length; at += CONCURRENCY) {
      const batch = await Promise.all(
        part.slice(at, at + CONCURRENCY).map(async (file) => {
          try {
            return {
              path: file.path,
              mode: file.mode,
              data: await readFile(file.absolute),
            };
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT")
              return undefined; // deleted since it was listed
            throw error;
          }
        }),
      );
      for (const entry of batch) if (entry) entries.push(entry);
    }
    const last = index === parts.length - 1;
    const partPaths = entries.map((entry) => entry.path);
    const now = [...uploaded, ...partPaths];
    if (last) {
      const keep = new Set(now);
      const drop = (previous ?? []).filter((path) => !keep.has(path));
      entries.push(
        {
          path: UPLOADED,
          mode: 0o600,
          data: Buffer.from(JSON.stringify({ version: 1, paths: now })),
        },
        ...(mode === "overlay"
          ? [
              {
                path: DROP,
                mode: 0o600,
                data: Buffer.from(drop.map((path) => `${path}\0`).join("")),
              },
            ]
          : []),
      );
    }
    let packed: Buffer;
    try {
      packed = packTar(entries);
    } catch (error) {
      // The same files pack the same way: a retry cannot cure it.
      throw new SeedRefused(
        `the project's files cannot be packed for the sandbox (${(error as Error).message})`,
      );
    }
    await sandbox.files.write(
      join(root, ARCHIVE),
      await gzip(packed, { level: 1 }),
      {
        timeoutMs: UPLOAD_TIMEOUT_MS,
        ...(options.signal ? { signal: options.signal } : {}),
      },
    );
    if (last && mode === "overlay")
      await sandbox.files.write(
        join(root, KEEP),
        Buffer.from(now.map((path) => `${path}\0`).join(""), "utf8"),
        options.signal ? { signal: options.signal } : {},
      );
    let output = "";
    const result = await sandbox.exec(
      [
        ...(index === 0 ? prepare(mode) : []),
        EXTRACT,
        ...(last ? finish(mode, autocrlf) : []),
      ].join(" && "),
      root,
      {
        onData: (chunk) => {
          output += chunk.toString("utf8");
        },
        timeout: EXTRACT_TIMEOUT_SECONDS,
        ...(options.signal ? { signal: options.signal } : {}),
      },
    );
    if (output.includes("piship-workdir-not-empty"))
      throw new SeedRefused(
        "the sandbox's project directory is not empty, so the remote workspace cannot start from a clean baseline; set sandbox.workdir to a new directory",
      );
    const missing = /piship-missing-tool:(\w+)/.exec(output);
    if (missing)
      throw new SeedRefused(
        `the sandbox has no ${missing[1]}, which a remote workspace needs; use a template that includes tar, gzip and git`,
      );
    commit = output.trim().split(/\s+/).at(-1) ?? "";
    if (result.exitCode !== 0 || (last && !/^[0-9a-f]{40,64}$/.test(commit)))
      throw new Error(
        `seeding the sandbox failed (exit ${result.exitCode}): ${printable(output.trim().slice(-300))}`,
      );
    uploaded.push(...partPaths);
    sent += part.reduce((n, file) => n + file.size, 0);
    options.progress?.(
      `Uploading to the sandbox: ${index + 1}/${parts.length} parts, ${mib(sent)} of ${mib(total)} MiB`,
    );
  }
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
    uploaded,
    skipped,
    lookup,
  };
  return seeded;
}
