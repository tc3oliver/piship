// Who may start a subagent child. pi-code's `subagent` tool spawns the branded
// command with `PI_CODE_SUBAGENT=1`, a marker anyone can set. A running
// session therefore publishes a record of itself in the distribution's state
// directory (a random nonce, its process, its session, its workspace) and
// puts the nonce in its own environment, which pi-code's spawn passes on
// (`{ ...process.env, PI_CODE_SUBAGENT: "1" }`). A child refuses to start
// unless the nonce names a record whose process still runs, and it works only
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
import { join, posix, win32 } from "node:path";
import { PiShipError, processAlive, processHostToken } from "@piship/contracts";
import { inTemp } from "./subagent-child.js";

/**
 * The nonce travels in the environment. The managed launch removes `PI_*`
 * and credential-looking variables from a process, so the name is neither;
 * the child reads it before that cleanup runs and removes it itself.
 */
export const SUBAGENT_NONCE_ENV = "PISHIP_SUBAGENT_NONCE";
export const SUBAGENT_OWNER_DIRECTORY = "subagent-owners";
const SCHEMA = "piship-subagent-owner/v1";
const NONCE = /^[0-9a-f]{64}$/;
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
      NONCE.test(value.nonce) &&
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

/**
 * Called when a session starts: publishes the owner record and exports its
 * nonce, so the children this session's subagent tool starts can prove who
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
  const host = processHostToken();
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    try {
      const record = parse(readFileSync(path, "utf8"));
      const stale = record
        ? record.host === host && !processAlive(record.pid)
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
    host,
    ...parent,
  };
  const fd = openSync(path, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(record));
  } finally {
    closeSync(fd);
  }
  env[SUBAGENT_NONCE_ENV] = nonce;
  process.once("exit", () => rmSync(path, { force: true }));
}

/**
 * The session that started this child, or a refusal. The nonce is taken out
 * of the environment first, so nothing the child runs inherits it.
 */
export function authenticateSubagentChild(
  stateDir: string,
  env: NodeJS.ProcessEnv = process.env,
): SubagentParent {
  const nonce = env[SUBAGENT_NONCE_ENV];
  delete env[SUBAGENT_NONCE_ENV];
  if (!nonce || !NONCE.test(nonce)) throw unauthenticated();
  const directory = join(stateDir, SUBAGENT_OWNER_DIRECTORY);
  let record: OwnerRecord | undefined;
  try {
    const folder = lstatSync(directory);
    const path = join(directory, fileName(nonce));
    const file = lstatSync(path);
    const posixChecks = process.platform !== "win32";
    if (
      !folder.isDirectory() ||
      !file.isFile() ||
      !ours(folder.uid) ||
      !ours(file.uid) ||
      (posixChecks && ((folder.mode | file.mode) & 0o077) !== 0) ||
      file.size > 64 * 1024
    )
      throw unauthenticated();
    record = parse(readFileSync(path, "utf8"));
  } catch {
    throw unauthenticated();
  }
  if (
    !record ||
    !timingSafeEqual(Buffer.from(record.nonce), Buffer.from(nonce)) ||
    record.host !== processHostToken() ||
    !processAlive(record.pid)
  )
    throw unauthenticated();
  return { session: record.session, workspace: record.workspace };
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
  if (inTemp(real, WORKTREE, platform)) {
    try {
      const stat = lstatSync(join(real, ".git"));
      if (stat.isFile() && ours(lstatSync(real).uid)) return;
    } catch {
      // not a worktree
    }
  }
  throw refuse(
    "The subagent child's working directory is outside its parent's workspace",
    "A subagent runs in the workspace of the session that started it, or in the git worktree of an isolated agent",
  );
}
