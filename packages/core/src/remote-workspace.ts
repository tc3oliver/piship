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
 * trusted alone. Hunk bodies and binary data are not inspected: a line of
 * either never starts with `diff --git `.
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

  let inHeader = false;
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
  const refuseMode = (mode: string) => {
    if (mode === "120000")
      refused.push("contains a symbolic link (mode 120000)");
    else if (mode === "160000")
      refused.push("contains a submodule (mode 160000)");
  };

  for (const line of lines) {
    if (line.startsWith("diff --git ")) {
      finishSection();
      inHeader = true;
      renamed = false;
      headerLine = line;
      continue;
    }
    if (!inHeader) continue;
    if (line.startsWith("@@ ") || line.startsWith("GIT binary patch")) {
      inHeader = false;
      continue;
    }
    if (line.startsWith("Binary files ")) {
      inHeader = false;
      continue;
    }
    const mode =
      /^(?:old|new|new file|deleted file) mode (\d+)$/.exec(line) ??
      /^index [0-9a-f]+\.\.[0-9a-f]+ (\d+)$/.exec(line);
    if (mode) refuseMode(mode[1] as string);
    const move = /^(?:rename|copy) (?:from|to) (.*)$/.exec(line);
    if (move) {
      renamed = true;
      add(pathBytes(move[1] as string));
    }
    const side = /^(?:---|\+\+\+) ([^\t]*)/.exec(line);
    if (side) addSided(side[1] as string);
  }
  finishSection();
  return { ok: refused.length === 0, files: [...files], refused };
}
