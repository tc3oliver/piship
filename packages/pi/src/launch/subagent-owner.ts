// Who may start a subagent child. pi-code's `subagent` tool spawns the branded
// command with `PI_CODE_SUBAGENT=1`, a marker anyone can set. A running
// session therefore publishes a record of itself in the distribution's state
// directory (a random token, its process, its session, its workspace) and
// puts the token in its own environment, which pi-code's spawn passes on
// (`{ ...process.env, PI_CODE_SUBAGENT: "1" }`). A child refuses to start
// unless the token names a record whose process still runs, and it works only
// inside that session's workspace. A person who can read the state directory
// has the user's own files already; what this closes is a launch that no
// session of this distribution started, and a child outside its parent's
// workspace.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  win32,
} from "node:path";
import { PiShipError, processAlive, processHostToken } from "@piship/contracts";
import {
  recordedIdentity,
  recordedProcessGone,
  recordedStart,
} from "@piship/core";
import { inTemp, readOwnedFile } from "./subagent-child.js";

/**
 * The token travels in the environment. Its name is one the credential
 * filters know (`TOKEN`): the managed launch removes it from a process, and
 * the sandbox never gives it to a command, so a model's `echo` does not see
 * it. The child reads it before that cleanup runs and removes it itself.
 */
export const SUBAGENT_TOKEN_ENV = "PISHIP_SUBAGENT_TOKEN";
export const SUBAGENT_OWNER_DIRECTORY = "subagent-owners";
const SCHEMA = "piship-subagent-owner/v1";
const TOKEN = /^[0-9a-f]{64}$/;
const MAX_RECORD_BYTES = 64 * 1024;
/** An unreadable record another launch may still be writing. */
const PARTIAL_MS = 60_000;
// pi-code's `isolation: worktree` gives a child a git worktree of its own
// directly under the OS temp directory (extensions/subagent/worktree.ts).
const WORKTREE = /^pi-agent-worktree-[A-Za-z0-9_-]+-[0-9a-f]{8}$/;

/** What a child learns from the session that started it. */
export interface SubagentParent {
  /** The parent's session id, as its audit log records it ("" if ungoverned). */
  readonly session: string;
  /** The real path of the parent's working directory. */
  readonly workspace: string;
}

interface OwnerRecord extends SubagentParent {
  readonly schema: typeof SCHEMA;
  readonly nonce: string;
  readonly pid: number;
  readonly host: string;
  /** The process's start identity (Linux) and start time, against a reused ID. */
  readonly identity: string | null;
  readonly started: number | null;
}

const refuse = (message: string, userAction: string) =>
  new PiShipError("CONFIG_INVALID", message, { userAction });
const unauthenticated = () =>
  refuse(
    "This subagent launch was not started by a running session of this distribution",
    "Subagent children are started by a session's subagent tool; start the command normally instead",
  );

const fileName = (nonce: string) =>
  `${createHash("sha256").update(nonce).digest("hex")}.json`;
const ours = (uid: number) =>
  process.getuid === undefined || uid === process.getuid();

function parse(text: string): OwnerRecord | undefined {
  try {
    const value = JSON.parse(text) as OwnerRecord;
    if (
      value.schema === SCHEMA &&
      TOKEN.test(value.nonce) &&
      Number.isSafeInteger(value.pid) &&
      value.pid > 0 &&
      typeof value.host === "string" &&
      typeof value.session === "string" &&
      typeof value.workspace === "string"
    )
      return value;
  } catch {
    // unreadable
  }
  return undefined;
}

/** Whether the process a record names still runs, and is the one that wrote it. */
function ownerRuns(record: OwnerRecord): boolean {
  if (record.host !== processHostToken() || !processAlive(record.pid))
    return false;
  // A reused process ID: the start identity (Linux) or start time (elsewhere)
  // of the process that has it now is not the writer's. Undefined (it cannot
  // be told) keeps the record, as a running process is never judged gone by
  // a failed lookup.
  return (
    recordedProcessGone({
      pid: record.pid,
      identity: record.identity ?? null,
      host: record.host,
      started: record.started ?? null,
    }) !== true
  );
}

/** The record directory, created private (0700) and checked to be ours. */
function privateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || !ours(stat.uid))
    throw refuse(
      "The subagent owner directory cannot be used",
      "Remove it from the distribution's state directory and start the command again",
    );
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    chmodSync(path, 0o700);
}

const published = new Set<string>();
/** One exit handler for every record this process holds. */
function removeAtExit(path: string): void {
  if (published.size === 0)
    process.once("exit", () => {
      for (const record of published) rmSync(record, { force: true });
    });
  published.add(path);
}

/**
 * Called when a session starts: publishes the owner record and exports its
 * token, so the children this session's subagent tool starts can prove who
 * started them. The record is removed when the process exits; one a crash
 * left behind names a process that is gone and is removed by the next start.
 */
export function publishSubagentOwner(
  stateDir: string,
  parent: SubagentParent,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const directory = join(stateDir, SUBAGENT_OWNER_DIRECTORY);
  privateDirectory(directory);
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    try {
      const record = parse(readFileSync(path, "utf8"));
      const stale = record
        ? record.host === processHostToken() && !ownerRuns(record)
        : Date.now() - statSync(path).mtimeMs > PARTIAL_MS;
      if (stale) rmSync(path, { force: true });
    } catch {
      // gone already
    }
  }
  const nonce = randomBytes(32).toString("hex");
  const path = join(directory, fileName(nonce));
  const record: OwnerRecord = {
    schema: SCHEMA,
    nonce,
    pid: process.pid,
    host: processHostToken(),
    identity: recordedIdentity(),
    started: recordedStart(),
    ...parent,
  };
  const fd = openSync(path, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(record));
  } finally {
    closeSync(fd);
  }
  env[SUBAGENT_TOKEN_ENV] = nonce;
  removeAtExit(path);
}

/**
 * The session that started this child, or a refusal. The token is taken out
 * of the environment first, so nothing the child runs inherits it. The record
 * is opened without following a link and checked and read through the one
 * descriptor.
 */
export function authenticateSubagentChild(
  stateDir: string,
  env: NodeJS.ProcessEnv = process.env,
): SubagentParent {
  const nonce = env[SUBAGENT_TOKEN_ENV];
  delete env[SUBAGENT_TOKEN_ENV];
  if (!nonce || !TOKEN.test(nonce)) throw unauthenticated();
  const directory = join(stateDir, SUBAGENT_OWNER_DIRECTORY);
  let record: OwnerRecord | undefined;
  try {
    const folder = lstatSync(directory);
    if (
      !folder.isDirectory() ||
      !ours(folder.uid) ||
      (process.platform !== "win32" && (folder.mode & 0o077) !== 0)
    )
      throw unauthenticated();
    record = parse(
      readOwnedFile(join(directory, fileName(nonce)), MAX_RECORD_BYTES, {
        closed: true,
      }),
    );
  } catch {
    throw unauthenticated();
  }
  if (
    !record ||
    !timingSafeEqual(Buffer.from(record.nonce), Buffer.from(nonce)) ||
    !ownerRuns(record)
  )
    throw unauthenticated();
  return { session: record.session, workspace: record.workspace };
}

/** What a small file git wrote says (bounded, owned by us, never a FIFO). */
const gitFile = (path: string) => readOwnedFile(path, 4096).trim();

/** The target of a `.git` file (`gitdir: <path>`), as a real path. */
function gitdirOf(dotGit: string): string | undefined {
  try {
    const line = gitFile(dotGit)
      .split("\n")
      .map((item) => item.trim())
      .find((item) => item.startsWith("gitdir:"));
    const target = line?.slice("gitdir:".length).trim();
    return target
      ? realpathSync.native(resolve(dirname(dotGit), target))
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The common git directory of the repository `start` is in (walking up), or
 * undefined when it is in none or cannot be read: the `.git` directory
 * itself, or for a linked worktree the directory its `commondir` names.
 */
function commonGitDirectory(start: string): string | undefined {
  for (let directory = start; ; directory = dirname(directory)) {
    try {
      const dotGit = join(directory, ".git");
      const entry = lstatSync(dotGit, { throwIfNoEntry: false });
      if (entry?.isDirectory()) return realpathSync.native(dotGit);
      if (entry?.isFile()) {
        const gitdir = gitdirOf(dotGit);
        if (!gitdir) return undefined;
        const common = gitFile(join(gitdir, "commondir"));
        return realpathSync.native(resolve(gitdir, common));
      }
    } catch {
      return undefined;
    }
    if (dirname(directory) === directory) return undefined;
  }
}

/**
 * Whether `directory` is a linked worktree of the repository the workspace
 * is in, as `git worktree add` leaves one: its `.git` file names a directory
 * directly below the repository's `worktrees/`, and that directory names the
 * worktree's `.git` file back (as an absolute path, or relative to itself
 * where git is set to write relative paths). A directory merely named and
 * shaped like one does not pass; a workspace outside any repository has none;
 * anything unreadable is a refusal.
 */
function isWorktreeOfWorkspace(directory: string, workspace: string): boolean {
  try {
    const common = commonGitDirectory(workspace);
    if (!common) return false;
    const dotGit = join(directory, ".git");
    const gitdir = gitdirOf(dotGit);
    if (!gitdir) return false;
    const below = relative(join(common, "worktrees"), gitdir).split(/[\\/]/);
    if (
      below.length !== 1 ||
      !below[0] ||
      below[0] === ".." ||
      isAbsolute(below[0])
    )
      return false;
    const back = realpathSync.native(
      resolve(gitdir, gitFile(join(gitdir, "gitdir"))),
    );
    return back === realpathSync.native(dotGit);
  } catch {
    return false;
  }
}

/** Whether the current user owns `path` (false if it cannot be looked at). */
function ownedByUs(path: string): boolean {
  try {
    return ours(lstatSync(path).uid);
  } catch {
    return false;
  }
}

/**
 * A child works in its parent's workspace: `cwd` is that directory or one
 * below it. The one other place pi-code puts a child is the git worktree its
 * `isolation: worktree` agents get under the temp directory; that, and only
 * that, is accepted outside the root.
 */
export function assertChildWorkspace(
  workspace: string,
  cwd: string = process.cwd(),
  platform: NodeJS.Platform = process.platform,
): void {
  const path = platform === "win32" ? win32 : posix;
  let real: string;
  try {
    real = realpathSync.native(cwd);
  } catch {
    throw refuse(
      "The subagent child's working directory cannot be used",
      "Start the child in its parent's workspace",
    );
  }
  const from = path.relative(workspace, real);
  if (
    from === "" ||
    (from.split(/[\\/]/)[0] !== ".." && !path.isAbsolute(from))
  )
    return;
  if (
    inTemp(real, WORKTREE, platform) &&
    ownedByUs(real) &&
    isWorktreeOfWorkspace(real, workspace)
  )
    return;
  throw refuse(
    `The subagent child's working directory ${real} is outside its parent's workspace ${workspace}`,
    "Omit cwd in the subagent call, or start the session in that directory",
  );
}
