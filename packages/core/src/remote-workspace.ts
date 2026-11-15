// The host side of `sandbox.workspace: remote`: where the sandbox's patch is
// kept, and the validation of that patch. The patch comes from an untrusted
// sandbox, so it is parsed here and the WHOLE patch is refused when any entry
// could write outside the project's ordinary files.
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

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

function ensurePrivateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function writeAtomic(path: string, data: Buffer | string): void {
  const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(temporary, data, { flag: "wx", mode: 0o600 });
  renameSync(temporary, path);
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
  ensurePrivateDirectory(join(stateDir, "sandbox-workspace"));
  ensurePrivateDirectory(paths.dir);
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
  writeAtomic(paths.patch, patch);
  writeAtomic(paths.meta, `${JSON.stringify(meta)}\n`);
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
  /** Every path the patch touches (both sides of a rename or copy). */
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

/** A git path token: quoted (decoded) or raw up to a tab. Lines are latin1, so chars are bytes. */
function pathBytes(token: string): Buffer | undefined {
  if (token.startsWith('"')) {
    if (token.length < 2 || !token.endsWith('"')) return undefined;
    return unquote(token.slice(1, -1));
  }
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
  const segments = path.split("/");
  for (const segment of segments) {
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

/** `a/p` or `b/p` prefix removed; undefined when absent. */
function stripSide(bytes: Buffer): Buffer | undefined {
  return bytes.length > 2 &&
    (bytes[0] === 0x61 || bytes[0] === 0x62) &&
    bytes[1] === 0x2f
    ? bytes.subarray(2)
    : undefined;
}

/**
 * Validate the output of `git diff --binary`. Parses every `diff --git`
 * header and the extended headers; `---`/`+++` are checked too but never
 * trusted alone. The whole patch is parsed strictly: hunks end where their
 * counts say, and any line git would read as something else is refused.
 */
export function validateRemoteWorkspacePatch(
  patch: Buffer,
  protectedPaths: readonly string[] = [],
  maxBytes = REMOTE_PATCH_MAX_BYTES,
): RemoteWorkspacePatchResult {
  const refused: string[] = [];
  const files = new Set<string>();
  if (patch.length > maxBytes)
    return {
      ok: false,
      files: [],
      refused: [`the patch is larger than ${maxBytes} bytes`],
    };
  const protectedSet = new Set(
    protectedPaths.map((p) => p.replace(/\/+$/, "").toLowerCase()),
  );
  const add = (raw: Buffer | undefined) => {
    if (!raw) {
      refused.push("a path in the patch is malformed");
      return;
    }
    const path = checkPath(raw, protectedSet, refused);
    if (path !== undefined) files.add(path);
  };
  const addSided = (token: string) => {
    if (token === "/dev/null") return;
    const bytes = pathBytes(token);
    const stripped = bytes && stripSide(bytes);
    if (!stripped) refused.push("a path in the patch has no a/ or b/ prefix");
    else add(stripped);
  };

  const lines = patch.toString("latin1").split("\n");
  if (patch.length === 0 || lines[0]?.startsWith("diff --git ") !== true)
    return {
      ok: false,
      files: [],
      refused: ["the patch does not start with a git diff header"],
    };

  let renamed = false;
  let headerLine = "";
  const finishSection = () => {
    if (headerLine === "" || renamed) return;
    // No rename lines: both sides name the same path, so split the header
    // where `a/P b/P` is symmetric.
    const rest = headerLine.slice("diff --git ".length);
    if (rest.startsWith('"') || rest.includes('"')) {
      // Quoted forms: a/ token then b/ token; each may be quoted or raw.
      const match = /^("(?:[^"\\]|\\.)*"|\S+) ("(?:[^"\\]|\\.)*"|.+)$/s.exec(
        rest,
      );
      if (!match) {
        refused.push("a diff header is malformed");
        return;
      }
      addSided(match[1] as string);
      addSided(match[2] as string);
      return;
    }
    const half = (rest.length - 1) / 2;
    if (Number.isInteger(half) && rest[half] === " ") {
      const left = rest.slice(0, half);
      const right = rest.slice(half + 1);
      if (
        left.startsWith("a/") &&
        right.startsWith("b/") &&
        left.slice(2) === right.slice(2)
      ) {
        addSided(left);
        addSided(right);
        return;
      }
    }
    refused.push("a diff header is malformed");
  };
  const checkMode = (mode: string) => {
    if (mode !== "100644" && mode !== "100755")
      refused.push(
        `file mode ${JSON.stringify(mode)} is not 100644 or 100755 (symbolic links, submodules and unusual modes are refused)`,
      );
  };

  // Strict, like git's own parser: a hunk ends exactly where its @@ counts
  // say, and anything after that is a header, a hunk header, or a refusal.
  // `header`: extended headers of a section; `between`: after ---/+++ or a
  // finished hunk; `hunk`: consuming lines; `binary`: base85 data; `end`: a
  // section that takes no more lines.
  let state: "header" | "between" | "hunk" | "binary" | "end" = "end";
  let oldLeft = 0;
  let newLeft = 0;
  let awaitingPlus = false;
  const BINARY_LINE = /^[A-Za-z][0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]*$/;
  const refuseLine = (why: string) => refused.push(`${why} in the patch`);

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
          return { ok: false, files: [...files], refused };
        }
        if (oldLeft < 0 || newLeft < 0) {
          refuseLine("a hunk longer than its header declares");
          return { ok: false, files: [...files], refused };
        }
        continue;
      }
      // A "\ No newline" marker may follow the last counted line.
      if (line.startsWith("\\")) continue;
      state = "between";
    }
    if (line.startsWith("diff --git ")) {
      if (awaitingPlus) refuseLine("a --- line without +++");
      finishSection();
      state = "header";
      renamed = false;
      awaitingPlus = false;
      headerLine = line;
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
        line === "" ||
        /^(?:literal|delta) \d+$/.test(line) ||
        BINARY_LINE.test(line)
      )
        continue;
      refuseLine("an unexpected line in binary data");
      continue;
    }
    if (state === "end") {
      refuseLine("a line outside any diff section");
      continue;
    }
    // state === "header"
    if (awaitingPlus) {
      const plus = /^\+\+\+ ([^\t]*)/.exec(line);
      if (!plus) refuseLine("a --- line without +++");
      else addSided(plus[1] as string);
      awaitingPlus = false;
      state = "between";
      continue;
    }
    const minus = /^--- ([^\t]*)/.exec(line);
    if (minus) {
      addSided(minus[1] as string);
      awaitingPlus = true;
      continue;
    }
    const mode =
      /^(?:old mode|new mode|deleted file mode|new file mode) ([\s\S]*)$/.exec(
        line,
      );
    if (mode) {
      checkMode(mode[1] as string);
      continue;
    }
    const index_ = /^index [0-9a-f]+\.\.[0-9a-f]+(?: ([\s\S]*))?$/.exec(line);
    if (index_) {
      if (index_[1] !== undefined) checkMode(index_[1]);
      continue;
    }
    if (/^(?:dis)?similarity index \d+%$/.test(line)) continue;
    const move = /^(?:rename|copy) (?:from|to|old|new) (.*)$/.exec(line);
    if (move) {
      renamed = true;
      add(pathBytes(move[1] as string));
      continue;
    }
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
  finishSection();
  return { ok: refused.length === 0, files: [...files], refused };
}

/**
 * A second opinion from git itself: the paths of `git apply --numstat -z` and
 * the modes and rename pairs of `git apply --summary`, both run on the same
 * patch without applying it, checked with the same rules. It catches a patch
 * whose structure this parser and git read differently.
 */
export function crossCheckRemoteWorkspacePatch(
  numstat: Buffer,
  summary: string,
  protectedPaths: readonly string[] = [],
): string[] {
  const refused: string[] = [];
  const protectedSet = new Set(
    protectedPaths.map((p) => p.replace(/\/+$/, "").toLowerCase()),
  );
  const check = (token: string) => {
    const bytes = pathBytes(token);
    if (!bytes) refused.push("git reports a malformed path");
    else checkPath(bytes, protectedSet, refused);
  };
  for (const record of numstat.toString("latin1").split("\0")) {
    if (record === "") continue;
    const fields = /^(?:-|\d+)\t(?:-|\d+)\t([\s\S]*)$/.exec(record);
    if (!fields) refused.push("git reports an unreadable change summary");
    else if (fields[1] !== "") check(fields[1] as string);
  }
  const mode = (value: string) => {
    if (value !== "100644" && value !== "100755")
      refused.push(`git reports file mode ${JSON.stringify(value)}`);
  };
  for (const line of summary.split("\n")) {
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
    m = /^ (?:rename|copy) (.+) => (.+?) \(\d+%\)$/.exec(line);
    if (m) {
      check(m[1] as string);
      check(m[2] as string);
      continue;
    }
    refused.push("git reports an unrecognized summary line");
  }
  return refused;
}
