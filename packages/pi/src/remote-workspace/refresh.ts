// Keeps a remote workspace in step with edits the user makes on this machine
// during the session: at the start of each turn, host files that changed since
// the seed (or the last refresh) are sent to the sandbox and folded into the
// baseline, so they never appear in the patch `sandbox pull` reviews.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { resolveGit } from "@piship/core";
import { RESERVED, type SeedResult, type SeedSandbox } from "./seed.js";

const EXEC_TIMEOUT_SECONDS = 120;
/** Paths per sandbox command, to stay under argument limits. */
const BATCH = 200;
/** A file modified this recently before a scan is re-checked by content: mtime granularity and a seed that ran while the user typed. */
const MTIME_SLACK_MS = 2000;
const OBJECT_ID = /^[0-9a-f]{40,64}$/;

const quote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;

/** The id git gives a blob, so host content compares with `git hash-object` in the sandbox. */
const blobId = (data: Buffer) =>
  createHash("sha1").update(`blob ${data.length}\0`).update(data).digest("hex");

function hostGit(root: string, args: string[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    execFile(
      resolveGit(),
      args,
      { cwd: root, encoding: "buffer", maxBuffer: 256 * 1024 * 1024 },
      (error, stdout) => (error ? reject(error) : resolve(stdout)),
    );
  });
}

export async function run(
  sandbox: SeedSandbox,
  root: string,
  script: string,
  timeout = EXEC_TIMEOUT_SECONDS,
  signal?: AbortSignal,
): Promise<{ exitCode: number | null; output: string }> {
  let output = "";
  const { exitCode } = await sandbox.exec(script, root, {
    onData: (chunk) => {
      output += chunk.toString("utf8");
    },
    timeout,
    ...(signal ? { signal } : {}),
  });
  return { exitCode, output };
}

/**
 * A new baseline commit: the old one with the given paths (or, undefined, the
 * whole working tree) taken from the sandbox's files. A temporary index keeps
 * what the agent staged out of it. `before` runs first, in the same shell.
 */
export async function foldBaseline(
  sandbox: SeedSandbox,
  root: string,
  baseline: string,
  paths: readonly string[] | undefined,
  before: readonly string[] = [],
): Promise<string> {
  const { exitCode, output } = await run(
    sandbox,
    root,
    [
      "set -e",
      'idx="$(git rev-parse --git-dir)/piship-baseline.idx"',
      'export GIT_INDEX_FILE="$idx"',
      'rm -f "$idx"',
      `git read-tree ${baseline}`,
      ...before,
      paths ? `git add -f -A -- ${paths.map(quote).join(" ")}` : "git add -A",
      'tree="$(git write-tree)"',
      'rm -f "$idx"',
      'git -c user.name=piship -c user.email=piship@invalid -c commit.gpgsign=false commit-tree "$tree" -m piship-baseline',
    ].join("\n"),
  );
  const commit = output.trim().split(/\s+/).at(-1) ?? "";
  if (exitCode !== 0 || !OBJECT_ID.test(commit))
    throw new Error(
      `the sandbox could not record its baseline (exit ${exitCode})`,
    );
  return commit;
}

interface Seen {
  size: number;
  mtimeMs: number;
}

export interface RefreshResult {
  /** Host files sent to the sandbox, and host deletions applied there. */
  readonly sent: readonly string[];
  /** Changed on both sides, once per file per session: the sandbox copy was kept. */
  readonly conflicts: readonly string[];
}

export class HostRefresh {
  readonly #sandbox: SeedSandbox;
  readonly #root: string;
  readonly #decide: (absolutePath: string) => Promise<"allow" | "skip">;
  readonly #fileCap: number;
  readonly #seeded: SeedResult;
  /** What the host looked like when each synced path was last compared. */
  readonly #seen = new Map<string, Seen>();
  /** Paths seen and left alone (policy, too large, symlink ...): re-judged only when they change. */
  readonly #left = new Map<string, Seen>();
  readonly #told = new Set<string>();
  #since: number;

  private constructor(
    sandbox: SeedSandbox,
    root: string,
    decide: (absolutePath: string) => Promise<"allow" | "skip">,
    fileCap: number,
    seeded: SeedResult,
    since: number,
  ) {
    this.#sandbox = sandbox;
    this.#root = root;
    this.#decide = decide;
    this.#fileCap = fileCap;
    this.#seeded = seeded;
    this.#since = since - MTIME_SLACK_MS;
  }

  /** Taken right after the seed; `startedAt` is when the seed began reading host files. */
  static async snapshot(
    sandbox: SeedSandbox,
    projectRoot: string,
    decide: (absolutePath: string) => Promise<"allow" | "skip">,
    fileCap: number,
    seeded: SeedResult,
    startedAt: number,
  ): Promise<HostRefresh> {
    const root = await realpath(projectRoot);
    const refresh = new HostRefresh(
      sandbox,
      root,
      decide,
      fileCap,
      seeded,
      startedAt,
    );
    for (const path of seeded.uploaded) {
      const seen = await refresh.#stat(path);
      if (seen) refresh.#seen.set(path, seen);
    }
    // What the seed left out is judged again only when the host changes it
    // (a file over the cap that was shrunk, say).
    for (const { path } of seeded.skipped) {
      const seen = await refresh.#stat(path);
      if (seen) refresh.#left.set(path, seen);
    }
    return refresh;
  }

  async #stat(path: string): Promise<Seen | undefined> {
    const info = await lstat(join(this.#root, ...path.split("/"))).catch(
      () => undefined,
    );
    return info && { size: info.size, mtimeMs: info.mtimeMs };
  }

  /** Why a host path is not sent, or the file's content when it is. */
  async #judge(path: string): Promise<Buffer | "leave" | "gone"> {
    const segments = path.split("/");
    if (
      segments.some((s) => s.toLowerCase() === ".git") ||
      RESERVED.has(path) ||
      path.startsWith("/") ||
      path.includes("\\") ||
      /[\t\n]/.test(path) ||
      segments.some((s) => s === ".." || s === "." || s === "")
    )
      return "leave";
    const absolute = join(this.#root, ...segments);
    const info = await lstat(absolute).catch(() => undefined);
    if (!info) return "gone";
    if (info.isSymbolicLink() || !info.isFile() || info.size > this.#fileCap)
      return "leave";
    const real = await realpath(absolute).catch(() => undefined);
    if (
      real === undefined ||
      relative(this.#root, real).split(sep).join("/") !== path
    )
      return "leave";
    if ((await this.#decide(absolute)) !== "allow") return "leave";
    return readFile(absolute).catch(() => "gone" as const);
  }

  /**
   * The baseline blob of each path in the sandbox, its working file hashed as
   * git would store it (`work`, compared with the baseline), and its raw bytes
   * (`raw`, compared with the host file); "-" is absent. The two hashes differ
   * when the sandbox converts line endings (core.autocrlf=input).
   */
  async #sandboxState(
    paths: readonly string[],
  ): Promise<Map<string, { base: string; work: string; raw: string }>> {
    const state = new Map<
      string,
      { base: string; work: string; raw: string }
    >();
    for (let i = 0; i < paths.length; i += BATCH) {
      const batch = paths.slice(i, i + BATCH);
      const { exitCode, output } = await run(
        this.#sandbox,
        this.#root,
        [
          `for p in ${batch.map(quote).join(" ")}; do`,
          `b=$(git rev-parse -q --verify "${this.#seeded.baselineCommit}:$p" 2>/dev/null || echo -)`,
          'if [ -f "$p" ] && [ ! -L "$p" ]; then w=$(git hash-object -- "$p" 2>/dev/null || echo -); r=$(git hash-object --no-filters -- "$p" 2>/dev/null || echo -); else w=-; r=-; fi',
          'printf "%s\\t%s\\t%s\\t%s\\n" "$b" "$w" "$r" "$p"',
          "done",
        ].join("\n"),
      );
      if (exitCode !== 0)
        throw new Error(`the sandbox did not answer (exit ${exitCode})`);
      for (const line of output.split("\n")) {
        const [base, work, raw, ...rest] = line.replace(/\r$/, "").split("\t");
        const path = rest.join("\t");
        if (base && work && raw && path) state.set(path, { base, work, raw });
      }
    }
    return state;
  }

  /** Send what changed on this machine since the last look. Throws on a sandbox failure; the next call retries. */
  async run(): Promise<RefreshResult> {
    const scanStart = Date.now();
    const listing = await hostGit(this.#root, [
      "ls-files",
      "-co",
      "--exclude-standard",
      "-z",
    ]);
    const listed = new Set(
      listing.toString("utf8").split("\0").filter(Boolean),
    );
    const candidates: string[] = [];
    for (const path of new Set([...listed, ...this.#seen.keys()])) {
      const seen = this.#seen.get(path) ?? this.#left.get(path);
      const now = await this.#stat(path);
      if (!seen) candidates.push(path);
      else if (
        !now ||
        now.size !== seen.size ||
        now.mtimeMs !== seen.mtimeMs ||
        now.mtimeMs >= this.#since
      )
        candidates.push(path);
    }

    const content = new Map<string, Buffer>();
    const deleted: string[] = [];
    const left: string[] = [];
    for (const path of candidates) {
      const judged = await this.#judge(path);
      if (judged === "gone") deleted.push(path);
      else if (judged === "leave") left.push(path);
      else content.set(path, judged);
    }

    const state = await this.#sandboxState([...content.keys(), ...deleted]);
    const upload: string[] = [];
    const remove: string[] = [];
    const settled: string[] = [];
    const conflicts: string[] = [];
    for (const [path, data] of content) {
      const there = state.get(path);
      if (!there) continue; // unanswered: retried next turn
      if (there.raw === blobId(data)) settled.push(path);
      else if (there.work === there.base) upload.push(path);
      else conflicts.push(path);
    }
    for (const path of deleted) {
      const there = state.get(path);
      if (!there) continue;
      if (there.work === "-") settled.push(path);
      else if (there.work === there.base) remove.push(path);
      else conflicts.push(path);
    }

    const written: string[] = [];
    try {
      for (const path of upload) {
        await this.#sandbox.files.write(
          join(this.#root, ...path.split("/")),
          content.get(path) ?? Buffer.alloc(0),
        );
        written.push(path);
      }
    } finally {
      // What was written is the new baseline even if a later write failed.
      if (written.length || remove.length) await this.#fold(written, remove);
    }

    // Only now is each path's host state remembered: a failure above retries it.
    for (const path of [...settled, ...upload, ...conflicts]) {
      const seen = await this.#stat(path);
      if (seen) this.#seen.set(path, seen);
      this.#left.delete(path);
    }
    for (const path of [...deleted, ...remove]) {
      this.#seen.delete(path);
      this.#left.delete(path);
    }
    for (const path of left) {
      const seen = await this.#stat(path);
      if (seen) this.#left.set(path, seen);
      this.#seen.delete(path);
    }
    this.#since = scanStart - MTIME_SLACK_MS;

    const fresh = conflicts.filter((path) => !this.#told.has(path));
    for (const path of fresh) this.#told.add(path);
    return { sent: [...written, ...remove], conflicts: fresh };
  }

  async #fold(written: readonly string[], removed: readonly string[]) {
    for (let i = 0; i < Math.max(written.length, removed.length); i += BATCH) {
      const add = written.slice(i, i + BATCH);
      const drop = removed.slice(i, i + BATCH);
      const modes: string[] = [];
      if (process.platform !== "win32")
        for (const path of add) {
          const info = await lstat(join(this.#root, ...path.split("/"))).catch(
            () => undefined,
          );
          if (info && info.mode & 0o111) modes.push(path);
        }
      this.#seeded.baselineCommit = await foldBaseline(
        this.#sandbox,
        this.#root,
        this.#seeded.baselineCommit,
        [...add, ...drop],
        [
          ...(drop.length ? [`rm -f -- ${drop.map(quote).join(" ")}`] : []),
          ...(modes.length
            ? [`chmod 755 -- ${modes.map(quote).join(" ")}`]
            : []),
        ],
      );
    }
  }
}
