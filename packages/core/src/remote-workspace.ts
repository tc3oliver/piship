// The host side of `sandbox.workspace: remote`: where the sandbox's patch is
// kept, and the validation of that patch. The patch comes from an untrusted
// sandbox, so it is parsed here and the WHOLE patch is refused when any entry
// could write outside the project's ordinary files.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { writeFileAtomic } from "@piship/credentials";
import { runGit } from "./git-run.js";

export const REMOTE_PATCH_MAX_BYTES = 64 * 1024 * 1024;

export interface RemoteWorkspacePaths {
  readonly projectKey: string;
  readonly dir: string;
  readonly patch: string;
  readonly meta: string;
  readonly applied: string;
}

export interface RemoteWorkspaceMeta {
  readonly version: 1;
  readonly session: string;
  readonly projectRoot: string;
  readonly baseHead: string | null;
  readonly createdAt: string;
  readonly files: number;
  /**
   * Workspace-relative paths (`/` separators) `sandbox pull` refuses besides
   * `.git`: the project's protected git files and directories. Written by the
   * host, never by the sandbox. Absent in a checkpoint written before it.
   */
  readonly protectedPaths?: readonly string[];
  /**
   * How `sandbox pull` treats this checkpoint; the distribution's policy,
   * written by the host. Absent means the usable defaults. A damaged value
   * reads as the stricter setting.
   */
  readonly pull?: {
    /** `skip` (default): apply the rest and skip protected files. `refuse`: refuse the whole patch. */
    readonly protectedFiles?: "skip" | "refuse";
    /** `optional` (default): `--yes` allowed. `required`: interactive review only. */
    readonly confirm?: "optional" | "required";
  };
}

/**
 * One spelling of a project root for the project key and for comparing roots:
 * the session (its cwd) and `sandbox pull` (git's top-level) reach the same
 * directory by different strings. On Windows the separators become `/` and the
 * drive letter lower case; elsewhere the path is unchanged.
 */
export function normalizeProjectRoot(
  path: string,
  platform: NodeJS.Platform = process.platform,
): string {
  if (platform !== "win32") return path;
  return path
    .replace(/\\/g, "/")
    .replace(/^([A-Za-z]):/, (_, drive: string) => `${drive.toLowerCase()}:`);
}

function realOrResolved(path: string): string {
  try {
    return normalizeProjectRoot(realpathSync.native(path));
  } catch {
    return normalizeProjectRoot(resolve(path));
  }
}

export function remoteWorkspacePaths(
  stateDir: string,
  projectRoot: string,
): RemoteWorkspacePaths {
  const projectKey = createHash("sha256")
    .update(realOrResolved(projectRoot))
    .digest("hex")
    .slice(0, 16);
  const dir = join(stateDir, "sandbox-workspace", projectKey);
  return {
    projectKey,
    dir,
    patch: join(dir, "latest.patch"),
    meta: join(dir, "latest.json"),
    applied: join(dir, "applied"),
  };
}

/** Store the checkpoint atomically: the patch first, then its description. */
export function writeRemoteWorkspaceCheckpoint(
  stateDir: string,
  projectRoot: string,
  patch: Buffer,
  info: {
    readonly session: string;
    readonly baseHead: string | null;
    readonly files: number;
    readonly createdAt?: string;
    readonly protectedPaths?: readonly string[];
    readonly pull?: RemoteWorkspaceMeta["pull"];
  },
): RemoteWorkspacePaths {
  const paths = remoteWorkspacePaths(stateDir, projectRoot);
  const meta: RemoteWorkspaceMeta = {
    version: 1,
    session: info.session,
    projectRoot: realOrResolved(projectRoot),
    baseHead: info.baseHead,
    createdAt: info.createdAt ?? new Date().toISOString(),
    files: info.files,
    ...(info.protectedPaths
      ? { protectedPaths: [...info.protectedPaths] }
      : {}),
    ...(info.pull ? { pull: info.pull } : {}),
  };
  writeFileAtomic(paths.patch, patch, { directoryMode: 0o700 });
  writeFileAtomic(paths.meta, `${JSON.stringify(meta)}\n`, {
    directoryMode: 0o700,
  });
  return paths;
}

/** The latest checkpoint of the project, or undefined when none is stored or it is damaged. */
export function readRemoteWorkspaceCheckpoint(
  stateDir: string,
  projectRoot: string,
): { readonly patch: Buffer; readonly meta: RemoteWorkspaceMeta } | undefined {
  const paths = remoteWorkspacePaths(stateDir, projectRoot);
  try {
    const meta = JSON.parse(
      readFileSync(paths.meta, "utf8"),
    ) as Partial<RemoteWorkspaceMeta> | null;
    if (
      meta?.version !== 1 ||
      typeof meta.session !== "string" ||
      typeof meta.projectRoot !== "string" ||
      (meta.baseHead !== null && typeof meta.baseHead !== "string") ||
      typeof meta.createdAt !== "string" ||
      typeof meta.files !== "number" ||
      (meta.protectedPaths !== undefined &&
        !(
          Array.isArray(meta.protectedPaths) &&
          meta.protectedPaths.every((path) => typeof path === "string")
        ))
    )
      return undefined;
    const pull = meta.pull as unknown;
    const field = (value: unknown, ok: readonly string[], strict: string) =>
      value === undefined
        ? undefined
        : ok.includes(value as string)
          ? value
          : strict;
    const normalized =
      pull === undefined
        ? undefined
        : typeof pull === "object" && pull !== null && !Array.isArray(pull)
          ? {
              protectedFiles: field(
                (pull as Record<string, unknown>).protectedFiles,
                ["skip", "refuse"],
                "refuse",
              ),
              confirm: field(
                (pull as Record<string, unknown>).confirm,
                ["optional", "required"],
                "required",
              ),
            }
          : { protectedFiles: "refuse", confirm: "required" };
    return {
      patch: readFileSync(paths.patch),
      meta: {
        ...(meta as RemoteWorkspaceMeta),
        ...(normalized ? { pull: normalized } : {}),
      } as RemoteWorkspaceMeta,
    };
  } catch {
    return undefined;
  }
}

/**
 * Checkpoints another session parked for the project because the main slot was
 * taken, oldest first. Each lives in `<stateDir>/sandbox-workspace-parked/<session>/`
 * with the same layout as the main slot, so `stateDir` below is that session
 * root. The directory names are untrusted: only direct subdirectories are read.
 */
export function listParkedRemoteWorkspaceCheckpoints(
  stateDir: string,
  projectRoot: string,
): {
  readonly stateDir: string;
  readonly patch: Buffer;
  readonly meta: RemoteWorkspaceMeta;
}[] {
  const parkedRoot = join(stateDir, "sandbox-workspace-parked");
  let names: string[];
  try {
    names = readdirSync(parkedRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
  } catch {
    return [];
  }
  const found = [];
  for (const name of names.sort()) {
    const sessionRoot = join(parkedRoot, name);
    const checkpoint = readRemoteWorkspaceCheckpoint(sessionRoot, projectRoot);
    if (checkpoint) found.push({ stateDir: sessionRoot, ...checkpoint });
  }
  const time = (createdAt: string) => Date.parse(createdAt) || 0;
  return found.sort((a, b) => time(a.meta.createdAt) - time(b.meta.createdAt));
}

export interface RemoteWorkspacePatchResult {
  readonly ok: boolean;
  /** Every path git will write or delete. */
  readonly files: string[];
  /** Why the patch is refused; empty when ok. */
  readonly refused: string[];
  /**
   * Protected or `.git` paths left out of an otherwise sound patch. Pass
   * `excludeArgs` to every `git apply` of this patch so git skips exactly them.
   */
  readonly skipped: string[];
  readonly excludeArgs: string[];
  /** Set when the only refusals are protected or `.git` paths and skipping was not allowed. */
  readonly protectedOnly?: boolean;
}

const ESCAPES: Record<string, number> = {
  a: 7,
  b: 8,
  f: 12,
  n: 10,
  r: 13,
  t: 9,
  v: 11,
  "\\": 92,
  '"': 34,
};

/** Decode git's C-quoted path (without the surrounding quotes) into bytes. */
function unquote(body: string): Buffer | undefined {
  const bytes: number[] = [];
  for (let i = 0; i < body.length; i++) {
    const char = body[i] as string;
    if (char === '"') return undefined;
    if (char !== "\\") {
      bytes.push(body.charCodeAt(i));
      continue;
    }
    const next = body[++i];
    if (next === undefined) return undefined;
    if (/[0-7]/.test(next)) {
      const octal = /^[0-3][0-7]{2}/.exec(body.slice(i, i + 3));
      if (!octal) return undefined;
      bytes.push(Number.parseInt(octal[0], 8));
      i += 2;
    } else if (next in ESCAPES) bytes.push(ESCAPES[next] as number);
    else return undefined;
  }
  return Buffer.from(bytes);
}

/** A path as `git apply --summary` prints it: C-quoted, or raw bytes (latin1 chars). */
function summaryPath(token: string): Buffer | undefined {
  if (token.startsWith('"'))
    return token.length > 1 && token.endsWith('"')
      ? unquote(token.slice(1, -1))
      : undefined;
  return Buffer.from(token, "latin1");
}

/** Case-insensitive file systems and Unicode compatibility folding (ſ is s) equate more than toLowerCase does. */
const fold = (text: string) => text.normalize("NFKC").toLowerCase();

function checkPath(
  raw: Buffer,
  protectedPaths: ReadonlySet<string>,
  refused: string[],
  soft: { count: number },
  skipPaths?: Set<string>,
): string | undefined {
  const path = raw.toString("utf8");
  const shown = JSON.stringify(path);
  const refuse = (why: string) => {
    refused.push(`${shown}: ${why}`);
    return undefined;
  };
  // A path that only touches .git or a protected path can be skipped alone.
  const refuseSoft = (why: string) => {
    soft.count++;
    skipPaths?.add(path);
    return refuse(why);
  };
  if (path === "") return refuse("empty path");
  for (const byte of raw)
    if (byte < 0x20 || byte === 0x7f)
      return refuse("control character in path");
  if (path.includes("\\")) return refuse("backslash in path");
  // git reads a +++ /dev/null without a deleted-file header as the path dev/null.
  if (path === "dev/null" || path.startsWith("dev/null/"))
    return refuse("a path under dev/null");
  if (path.startsWith("/") || /^[A-Za-z]:/.test(path))
    return refuse("absolute path");
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".")
      return refuse("empty or '.' path segment");
    if (segment === "..") return refuse("'..' path segment");
    // .git, plus the Windows aliases of it (trailing dots/spaces, 8.3 name).
    const folded = fold(segment);
    if (/^\.git[. ]*$/.test(folded) || /^git~\d+$/.test(folded))
      return refuseSoft("touches .git");
  }
  for (const segment of path.split("/"))
    if (/~\d+$/.test(segment))
      return refuse(
        "a ~N segment; on Windows it can name a different file by its 8.3 short name",
      );
  const folded = fold(path);
  for (const protectedPath of protectedPaths)
    if (folded === protectedPath || folded.startsWith(`${protectedPath}/`))
      return refuseSoft("touches a protected path");
  return path;
}

const ALLOWED_MODES = new Set(["100644", "100755"]);

/**
 * The line scan: what git's report omits. It checks the structure and every
 * mode (including the `index` line's, which the summary never shows) against
 * 100644 and 100755, and refuses any line git could read as a header outside
 * one: a hunk ends exactly where its `@@` counts say, and anything after
 * that is a header, a hunk header, or a refusal. Paths are not read here.
 */
function scanStructure(lines: readonly string[]): string[] {
  const refused: string[] = [];
  const checkMode = (mode: string) => {
    if (!ALLOWED_MODES.has(mode))
      refused.push(
        `file mode ${JSON.stringify(mode)} is not 100644 or 100755 (symbolic links, submodules and unusual modes are refused)`,
      );
  };
  const refuseLine = (why: string) => refused.push(`${why} in the patch`);
  // `header`: extended headers of a section; `between`: after +++ or a
  // finished hunk; `hunk`: consuming lines; `binary`: base85 data; `end`: a
  // section that takes no more lines.
  let state: "header" | "between" | "hunk" | "binary" | "end" = "end";
  let oldLeft = 0;
  let newLeft = 0;
  let awaitingPlus = false;
  let oldName: string | null | undefined;
  // The header lines of the current section decide where /dev/null may appear.
  let sawNew = false;
  let sawDeleted = false;
  // `--- a/x` or `+++ b/x` as the bare name (quotes kept), null for /dev/null.
  // Git deletes the --- name and writes the +++ name, yet numstat shows only one.
  const diffName = (text: string): string | null | undefined =>
    text === "/dev/null"
      ? null
      : /^("?)[ab]\/([\s\S]+)$/.exec(text)?.slice(1).join("");
  const BINARY_LINE = /^[A-Za-z][0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]*$/;
  for (const [index, line] of lines.entries()) {
    if (line === "" && index === lines.length - 1) continue;
    if (state === "hunk") {
      if (oldLeft > 0 || newLeft > 0) {
        const lead = line[0];
        if (lead === " " || line === "") {
          oldLeft--;
          newLeft--;
        } else if (lead === "-") oldLeft--;
        else if (lead === "+") newLeft--;
        else if (lead !== "\\") {
          refuseLine("an unexpected line inside a hunk");
          return refused;
        }
        if (oldLeft < 0 || newLeft < 0) {
          refuseLine("a hunk longer than its header declares");
          return refused;
        }
        continue;
      }
      // A "\ No newline" marker may follow the last counted line.
      if (line.startsWith("\\")) continue;
      state = "between";
    }
    if (line.startsWith("diff --git ")) {
      if (awaitingPlus) refuseLine("a --- line without +++");
      sawNew = false;
      sawDeleted = false;
      state = "header";
      awaitingPlus = false;
      continue;
    }
    if (state === "between") {
      const hunk = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
      if (!hunk) {
        refuseLine("a line that is not a hunk or a header");
        continue;
      }
      oldLeft = hunk[1] === undefined ? 1 : Number(hunk[1]);
      newLeft = hunk[2] === undefined ? 1 : Number(hunk[2]);
      state = "hunk";
      continue;
    }
    if (state === "binary") {
      if (
        line !== "" &&
        !/^(?:literal|delta) \d+$/.test(line) &&
        !BINARY_LINE.test(line)
      )
        refuseLine("an unexpected line in binary data");
      continue;
    }
    if (state === "end") {
      refuseLine("a line outside any diff section");
      continue;
    }
    if (awaitingPlus) {
      if (!line.startsWith("+++ ")) refuseLine("a --- line without +++");
      else {
        const newName = diffName(line.slice(4));
        if (
          oldName === undefined ||
          newName === undefined ||
          (oldName !== null && newName !== null && oldName !== newName)
        )
          refuseLine("--- and +++ lines that name different files");
        // Without the matching header git reads /dev/null as the path dev/null
        // and deletes or writes the other name unreported.
        else if (
          (oldName === null && !sawNew) ||
          (newName === null && !sawDeleted)
        )
          refuseLine("/dev/null without a new file or deleted file header");
      }
      awaitingPlus = false;
      state = "between";
      continue;
    }
    if (line.startsWith("--- ")) {
      oldName = diffName(line.slice(4));
      awaitingPlus = true;
      continue;
    }
    const mode =
      /^(?:old mode|new mode|deleted file mode|new file mode) ([\s\S]*)$/.exec(
        line,
      ) ?? /^index [0-9a-f]+\.\.[0-9a-f]+ ([\s\S]*)$/.exec(line);
    if (mode) {
      if (line.startsWith("new file mode")) sawNew = true;
      if (line.startsWith("deleted file mode")) sawDeleted = true;
      checkMode(mode[1] as string);
      continue;
    }
    // The producer runs git diff --no-renames, so a rename or copy is never honest.
    if (/^(?:rename|copy) (?:from|to|old|new) /.test(line)) {
      refuseLine("a rename or copy header");
      continue;
    }
    if (/^index [0-9a-f]+\.\.[0-9a-f]+$/.test(line)) continue;
    if (line === "GIT binary patch") {
      state = "binary";
      continue;
    }
    if (/^Binary files .* differ$/.test(line)) {
      state = "end";
      continue;
    }
    refuseLine(
      `an unrecognized header line ${JSON.stringify(line.slice(0, 40))}`,
    );
  }
  if (awaitingPlus) refuseLine("a --- line without +++");
  return refused;
}

/**
 * Validate the output of `git diff --binary`. Git's own parser is the
 * authority on which paths the patch touches: `git apply --numstat -z` lists
 * what it writes or deletes and `git apply --summary` the modes of what it
 * creates, deletes or re-modes, run without applying anything. Every path is checked, and the whole
 * patch is refused when one fails. `cwd` is where git runs (the project).
 */
export async function validateRemoteWorkspacePatch(
  patch: Buffer,
  protectedPaths: readonly string[] = [],
  options: { cwd?: string; maxBytes?: number; skipProtected?: boolean } = {},
): Promise<RemoteWorkspacePatchResult> {
  const first = await validatePatch(patch, protectedPaths, options, []);
  const { soft: _soft, skipPaths: _paths, ...plain } = first;
  if (first.ok || first.soft <= 0 || first.soft !== first.refused.length)
    return plain;
  if (options.skipProtected === false) return { ...plain, protectedOnly: true };
  // Only protected or .git paths were refused and the patch is otherwise
  // sound: have git leave exactly those out, then validate again with the same
  // excludes. The second pass is the full check, so a path the exclude missed
  // refuses the whole patch.
  const skipped = [...first.skipPaths];
  const excludeArgs = skipped.map(
    (path) => `--exclude=${path.replace(/[\\*?[]/g, "\\$&")}`,
  );
  const second = await validatePatch(
    patch,
    protectedPaths,
    options,
    excludeArgs,
  );
  const { soft: _s, skipPaths: _p, ...done } = second;
  return second.ok
    ? { ...done, skipped, excludeArgs }
    : { ...done, refused: first.refused };
}

async function validatePatch(
  patch: Buffer,
  protectedPaths: readonly string[],
  options: { cwd?: string; maxBytes?: number; skipProtected?: boolean },
  excludeArgs: readonly string[],
): Promise<
  RemoteWorkspacePatchResult & { soft: number; skipPaths: Set<string> }
> {
  const soft = { count: 0 };
  const skipPaths = new Set<string>();
  const maxBytes = options.maxBytes ?? REMOTE_PATCH_MAX_BYTES;
  const fail = (...reasons: string[]) => ({
    ok: false,
    files: [],
    refused: reasons,
    skipped: [],
    excludeArgs: [],
    soft: -1,
    skipPaths,
  });
  if (patch.length > maxBytes)
    return fail(`the patch is larger than ${maxBytes} bytes`);
  const lines = patch.toString("latin1").split("\n");
  if (patch.length === 0 || !lines[0]?.startsWith("diff --git "))
    return fail("the patch does not start with a git diff header");
  const refused = scanStructure(lines);
  if (refused.length > 0) return fail(...refused);

  const cwd = options.cwd ?? process.cwd();
  const [numstat, summary] = await Promise.all([
    runGit(cwd, ["apply", "--numstat", "-z", ...excludeArgs, "-"], patch),
    runGit(cwd, ["apply", "--summary", ...excludeArgs, "-"], patch),
  ]);
  if (numstat.code !== 0 || summary.code !== 0)
    return fail(
      `git cannot read the patch: ${(numstat.stderr || summary.stderr).trim().slice(0, 200)}`,
    );

  const protectedSet = new Set(
    protectedPaths.map((p) => fold(p.replace(/\/+$/, ""))),
  );
  const files = new Set<string>();
  const check = (token: string) => {
    const bytes = summaryPath(token);
    if (!bytes) refused.push("git reports a malformed path");
    else {
      const path = checkPath(bytes, protectedSet, refused, soft);
      if (path !== undefined) files.add(path);
    }
  };
  for (const record of numstat.stdout.toString("latin1").split("\0")) {
    if (record === "") continue;
    const fields = /^(?:-|\d+)\t(?:-|\d+)\t([\s\S]*)$/.exec(record);
    if (!fields) refused.push("git reports an unreadable change summary");
    // -z numstat paths are raw, never quoted.
    else if (fields[1] !== "") {
      const path = checkPath(
        Buffer.from(fields[1] as string, "latin1"),
        protectedSet,
        refused,
        soft,
        skipPaths,
      );
      if (path !== undefined) files.add(path);
    }
  }
  const mode = (value: string) => {
    if (!ALLOWED_MODES.has(value))
      refused.push(`git reports file mode ${JSON.stringify(value)}`);
  };
  for (const line of summary.stdout.toString("latin1").split("\n")) {
    if (line === "") continue;
    let m = /^ (?:create|delete) mode (\S+) (.+)$/.exec(line);
    if (m) {
      mode(m[1] as string);
      check(m[2] as string);
      continue;
    }
    m = /^ mode change (\S+) => (\S+) (.+)$/.exec(line);
    if (m) {
      mode(m[1] as string);
      mode(m[2] as string);
      check(m[3] as string);
      continue;
    }
    refused.push("git reports an unrecognized summary line");
  }
  return {
    ok: refused.length === 0,
    files: [...files],
    refused,
    skipped: [],
    excludeArgs: [],
    soft: soft.count,
    skipPaths,
  };
}
