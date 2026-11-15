// The host side of `sandbox.workspace: remote`: where the sandbox's patch is
// kept, and the validation of that patch. The patch comes from an untrusted
// sandbox, so it is parsed here and the WHOLE patch is refused when any entry
// could write outside the project's ordinary files.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { writeFileAtomic } from "@piship/credentials";

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
}

function realOrResolved(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
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
    return {
      patch: readFileSync(paths.patch),
      meta: meta as RemoteWorkspaceMeta,
    };
  } catch {
    return undefined;
  }
}

export interface RemoteWorkspacePatchResult {
  readonly ok: boolean;
  /** Every path git will write, delete, or read as a rename or copy source. */
  readonly files: string[];
  /** Why the patch is refused; empty when ok. */
  readonly refused: string[];
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

function checkPath(
  raw: Buffer,
  protectedPaths: ReadonlySet<string>,
  refused: string[],
): string | undefined {
  const path = raw.toString("utf8");
  const shown = JSON.stringify(path);
  const refuse = (why: string) => {
    refused.push(`${shown}: ${why}`);
    return undefined;
  };
  if (path === "") return refuse("empty path");
  for (const byte of raw)
    if (byte < 0x20 || byte === 0x7f)
      return refuse("control character in path");
  if (path.includes("\\")) return refuse("backslash in path");
  if (path.startsWith("/") || /^[A-Za-z]:/.test(path))
    return refuse("absolute path");
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".")
      return refuse("empty or '.' path segment");
    if (segment === "..") return refuse("'..' path segment");
    // .git, plus the Windows aliases of it (trailing dots/spaces, 8.3 name).
    if (/^\.git[. ]*$/i.test(segment) || /^git~\d+$/i.test(segment))
      return refuse("touches .git");
  }
  const folded = path.toLowerCase();
  for (const protectedPath of protectedPaths)
    if (folded === protectedPath || folded.startsWith(`${protectedPath}/`))
      return refuse("touches a protected path");
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
      awaitingPlus = false;
      state = "between";
      continue;
    }
    if (line.startsWith("--- ")) {
      awaitingPlus = true;
      continue;
    }
    const mode =
      /^(?:old mode|new mode|deleted file mode|new file mode) ([\s\S]*)$/.exec(
        line,
      ) ?? /^index [0-9a-f]+\.\.[0-9a-f]+ ([\s\S]*)$/.exec(line);
    if (mode) {
      checkMode(mode[1] as string);
      continue;
    }
    if (
      /^index [0-9a-f]+\.\.[0-9a-f]+$/.test(line) ||
      /^(?:dis)?similarity index \d+%$/.test(line) ||
      /^(?:rename|copy) (?:from|to|old|new) [\s\S]*$/.test(line)
    )
      continue;
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

function runGit(
  cwd: string,
  args: string[],
  input: Buffer,
): Promise<{ stdout: Buffer; stderr: string; code: number }> {
  return new Promise((resolveRun, reject) => {
    const child = execFile(
      "git",
      args,
      { cwd, encoding: "buffer", maxBuffer: 256 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code =
          error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        if (code === -1) reject(error);
        else resolveRun({ stdout, stderr: stderr.toString("utf8"), code });
      },
    );
    child.stdin?.end(input);
  });
}

/**
 * Validate the output of `git diff --binary`. Git's own parser is the
 * authority on which paths the patch touches: `git apply --numstat -z` lists
 * what it writes and `git apply --summary` the modes and the rename and copy
 * sources, run without applying anything. Every path is checked, and the whole
 * patch is refused when one fails. `cwd` is where git runs (the project).
 */
export async function validateRemoteWorkspacePatch(
  patch: Buffer,
  protectedPaths: readonly string[] = [],
  options: { cwd?: string; maxBytes?: number } = {},
): Promise<RemoteWorkspacePatchResult> {
  const maxBytes = options.maxBytes ?? REMOTE_PATCH_MAX_BYTES;
  const fail = (...reasons: string[]) => ({
    ok: false,
    files: [],
    refused: reasons,
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
    runGit(cwd, ["apply", "--numstat", "-z", "-"], patch),
    runGit(cwd, ["apply", "--summary", "-"], patch),
  ]);
  if (numstat.code !== 0 || summary.code !== 0)
    return fail(
      `git cannot read the patch: ${(numstat.stderr || summary.stderr).trim().slice(0, 200)}`,
    );

  const protectedSet = new Set(
    protectedPaths.map((p) => p.replace(/\/+$/, "").toLowerCase()),
  );
  const files = new Set<string>();
  const check = (token: string) => {
    const bytes = summaryPath(token);
    if (!bytes) refused.push("git reports a malformed path");
    else {
      const path = checkPath(bytes, protectedSet, refused);
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
    m = /^ (?:rename|copy) (.+) \(\d+%\)$/.exec(line);
    if (m) {
      // "a => b" is ambiguous when a name holds " => ": check every split.
      const pair = m[1] as string;
      const parts = pair.split(" => ");
      for (let i = 1; i < parts.length; i++) {
        check(parts.slice(0, i).join(" => "));
        check(parts.slice(i).join(" => "));
      }
      continue;
    }
    refused.push("git reports an unrecognized summary line");
  }
  return { ok: refused.length === 0, files: [...files], refused };
}
