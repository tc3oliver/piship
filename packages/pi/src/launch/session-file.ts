// Which persisted Pi session a launch resumes, whether it is safe to resume,
// and which process owns it.
//
// Pi 0.87.1's `SessionManager.continueRecent()` loads the most recent session
// of the project whatever it holds: it skips a line that does not parse (so a
// corrupt entry silently drops out of the conversation), appends a newline to
// a truncated last record, reads a file of any size to its end, and lets two
// processes append to the same file. PiShip therefore picks the file itself,
// the way Pi does, inspects it before Pi reads it, and takes an owner record
// for it; only then does Pi open it (`SessionManager.open`).
import { randomUUID } from "node:crypto";
import {
  closeSync,
  fstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { hostname } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { PiShipError, processAlive } from "@piship/contracts";
import { processIdentity, processIdentityMatches } from "@piship/core";

/**
 * The largest session file a launch resumes on its own: 64 MiB. Pi holds
 * every entry of the file in memory, and compaction never shrinks it.
 */
export const MAX_RESUME_BYTES = 64 * 1024 * 1024;
/** Pi reads at most this much of a file to find its header (discovery). */
const HEADER_SCAN_BYTES = 1024 * 1024;
const READ_CHUNK = 1024 * 1024;

type Entry = Record<string, unknown>;

function isEntry(value: unknown): value is Entry {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The first record of the file, as Pi's bounded header scan finds it. */
function readHeader(path: string): Entry | undefined {
  let text: string;
  let complete: boolean;
  const fd = openSync(path, "r");
  try {
    const buffer = Buffer.alloc(HEADER_SCAN_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = readSync(fd, buffer, length, buffer.length - length, null);
      if (read === 0) break;
      length += read;
    }
    complete = length <= HEADER_SCAN_BYTES;
    text = buffer
      .subarray(0, Math.min(length, HEADER_SCAN_BYTES))
      .toString("utf8");
  } finally {
    closeSync(fd);
  }
  const lines = text.split("\n");
  // Past the scan limit the last line is cut; Pi does not read beyond it.
  if (!complete) lines.pop();
  for (const line of lines) {
    if (!line.trim()) continue;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      continue;
    }
    if (!value) continue;
    return isEntry(value) &&
      value.type === "session" &&
      typeof value.id === "string"
      ? value
      : undefined;
  }
  return undefined;
}

/**
 * The session `SessionManager.continueRecent(cwd, sessionDir)` would resume:
 * the most recently modified `.jsonl` file whose header names this project.
 */
export function mostRecentSession(
  sessionDir: string,
  cwd: string,
): string | undefined {
  const project = resolve(cwd);
  let files: { path: string; mtime: number }[];
  try {
    files = readdirSync(sessionDir)
      .filter((name) => name.endsWith(".jsonl"))
      .map((name) => join(sessionDir, name))
      .map((path) => ({ path, mtime: statSync(path).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
  } catch {
    return undefined;
  }
  for (const { path } of files) {
    let header: Entry | undefined;
    try {
      header = readHeader(path);
    } catch {
      continue;
    }
    const recorded = header?.cwd;
    if (
      typeof recorded === "string" &&
      recorded !== "" &&
      resolve(recorded) === project
    )
      return path;
  }
  return undefined;
}

/** What makes an entry of this type unusable, if anything. */
function shapeProblem(entry: Entry): string | undefined {
  const text = (field: string) => typeof entry[field] === "string";
  switch (entry.type) {
    case "message":
      return isEntry(entry.message) && typeof entry.message.role === "string"
        ? undefined
        : "has no message";
    case "compaction":
      if (!text("summary")) return "has no summary";
      return entry.firstKeptEntryId === undefined || text("firstKeptEntryId")
        ? undefined
        : "has an invalid first kept entry";
    case "branch_summary":
      return text("fromId") && text("summary")
        ? undefined
        : "has no summary or origin";
    case "context_edit":
      return text("targetId") &&
        (entry.replacement === null ||
          (isEntry(entry.replacement) && "content" in entry.replacement))
        ? undefined
        : "has no target or replacement";
    case "label":
      return text("targetId") ? undefined : "has no target";
    case "model_change":
      return text("provider") && text("modelId") ? undefined : "has no model";
    case "thinking_level_change":
      return text("thinkingLevel") ? undefined : "has no thinking level";
    case "custom":
    case "custom_message":
      return text("customType") ? undefined : "has no custom type";
    default:
      return undefined;
  }
}

/** The other entries an entry refers to, beside its parent. */
function references(entry: Entry): [string, string][] {
  const found: [string, string][] = [];
  if (
    entry.type === "compaction" &&
    typeof entry.firstKeptEntryId === "string" &&
    entry.firstKeptEntryId !== entry.id
  )
    found.push(["first kept entry", entry.firstKeptEntryId]);
  if (
    (entry.type === "context_edit" || entry.type === "label") &&
    typeof entry.targetId === "string"
  )
    found.push(["target", entry.targetId]);
  if (
    entry.type === "branch_summary" &&
    typeof entry.fromId === "string" &&
    entry.fromId !== "root"
  )
    found.push(["origin", entry.fromId]);
  return found;
}

/** Checks the structure of a session one physical line at a time. */
class SessionStructure {
  private header = false;
  private version = 1;
  private readonly entries = new Map<
    string,
    { parent: string | null; line: number }
  >();
  private readonly refs: {
    line: number;
    label: string;
    field: string;
    target: string;
  }[] = [];

  line(text: string, line: number): string | undefined {
    if (!text.trim()) return undefined;
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      return `line ${line} is not valid JSON`;
    }
    if (!isEntry(value)) return `line ${line} is not a session entry`;
    if (value.type === "session") {
      if (this.header) return `line ${line} is a second session header`;
      if (typeof value.id !== "string")
        return `the session header on line ${line} has no session ID`;
      this.header = true;
      this.version = typeof value.version === "number" ? value.version : 1;
      return undefined;
    }
    if (!this.header) return `line ${line} comes before the session header`;
    if (typeof value.type !== "string") return `line ${line} has no entry type`;
    // Version 1 entries have no IDs yet; Pi assigns them when it migrates.
    if (this.version < 2) return undefined;
    const { id, parentId } = value;
    if (typeof id !== "string" || !id) return `line ${line} has no entry ID`;
    const label = `the ${value.type} entry ${id} on line ${line}`;
    if (parentId !== null && typeof parentId !== "string")
      return `${label} has no valid parent reference`;
    const earlier = this.entries.get(id);
    if (earlier)
      return `${label} repeats the ID of the entry on line ${earlier.line}`;
    const shape = shapeProblem(value);
    if (shape) return `${label} ${shape}`;
    this.entries.set(id, { parent: parentId, line });
    for (const [field, target] of references(value))
      this.refs.push({ line, label, field, target });
    return undefined;
  }

  finish(): string | undefined {
    if (!this.header) return "the file has no session header";
    for (const [id, { parent, line }] of this.entries)
      if (parent !== null && !this.entries.has(parent))
        return `the entry ${id} on line ${line} names parent ${parent}, which is not in the file`;
    // Every parent exists, so each walk ends at a root or at a cycle.
    const state = new Map<string, "walking" | "done">();
    for (const start of this.entries.keys()) {
      const path: string[] = [];
      let id: string | null = start;
      while (id !== null && !state.has(id)) {
        state.set(id, "walking");
        path.push(id);
        id = this.entries.get(id)?.parent ?? null;
      }
      if (id !== null && state.get(id) === "walking")
        return `the entry ${id} on line ${this.entries.get(id)?.line} is its own ancestor: the parent references form a cycle`;
      for (const walked of path) state.set(walked, "done");
    }
    for (const { label, field, target } of this.refs)
      if (!this.entries.has(target))
        return `${label} names ${field} ${target}, which is not in the file`;
    return undefined;
  }
}

export type SessionProblem =
  | { readonly kind: "oversized"; readonly size: number }
  | { readonly kind: "corrupt"; readonly reason: string };

/**
 * Why the session file at `path` must not be resumed automatically, or
 * undefined. It is read in bounded chunks and never written: a file over
 * `limit` is not read at all.
 */
export function inspectSession(
  path: string,
  limit = MAX_RESUME_BYTES,
): SessionProblem | undefined {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size > limit) return { kind: "oversized", size };
    const structure = new SessionStructure();
    const decoder = new StringDecoder("utf8");
    const buffer = Buffer.allocUnsafe(Math.min(READ_CHUNK, Math.max(size, 1)));
    let remaining = size;
    let pending = "";
    let line = 0;
    while (remaining > 0) {
      const read = readSync(
        fd,
        buffer,
        0,
        Math.min(buffer.length, remaining),
        null,
      );
      if (read === 0) break;
      remaining -= read;
      pending += decoder.write(buffer.subarray(0, read));
      let start = 0;
      let newline = pending.indexOf("\n", start);
      while (newline !== -1) {
        line += 1;
        const reason = structure.line(pending.slice(start, newline), line);
        if (reason) return { kind: "corrupt", reason };
        start = newline + 1;
        newline = pending.indexOf("\n", start);
      }
      pending = pending.slice(start);
    }
    pending += decoder.end();
    if (pending.trim()) {
      line += 1;
      try {
        JSON.parse(pending);
      } catch {
        return {
          kind: "corrupt",
          reason: `the last record (line ${line}) is incomplete: the file ends in the middle of a write`,
        };
      }
      // A complete last record without its newline: Pi adds the newline.
      const reason = structure.line(pending, line);
      if (reason) return { kind: "corrupt", reason };
    }
    const reason = structure.finish();
    return reason ? { kind: "corrupt", reason } : undefined;
  } finally {
    closeSync(fd);
  }
}

const OWNER_SCHEMA = "piship-session-owner/v1";
/** Beside the session files; Pi only reads `*.jsonl` there. */
export const OWNER_DIRECTORY = ".piship-owners";
/**
 * An owner record whose process cannot be verified (another host, or no
 * start identity on this platform) counts as live until it has not been
 * refreshed for this long. Wrongly live only starts a new session; wrongly
 * stale would let two processes write one file.
 */
const UNVERIFIED_OWNER_MS = 24 * 60 * 60_000;
/** A record another process is still writing is not stale yet. */
const PARTIAL_OWNER_MS = 60_000;
const OWNER_HEARTBEAT_MS = 60_000;
const INSTANCE = /^[0-9a-f-]{36}$/;

interface OwnerRecord {
  readonly schema: typeof OWNER_SCHEMA;
  readonly session: string;
  readonly pid: number;
  readonly identity: string | null;
  readonly host: string;
  readonly instance: string;
}

function selfIdentity(): string | null {
  return processIdentity(process.pid) ?? null;
}

function recentlyModified(path: string, withinMs: number): boolean {
  try {
    return Date.now() - statSync(path).mtimeMs < withinMs;
  } catch {
    return false;
  }
}

function parseOwner(path: string, session: string): OwnerRecord | undefined {
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as OwnerRecord;
    if (
      value.schema !== OWNER_SCHEMA ||
      value.session !== session ||
      !Number.isSafeInteger(value.pid) ||
      value.pid < 1 ||
      typeof value.host !== "string" ||
      typeof value.instance !== "string" ||
      !INSTANCE.test(value.instance) ||
      (value.identity !== null && typeof value.identity !== "string")
    )
      return undefined;
    return value;
  } catch {
    return undefined;
  }
}

function ownerAlive(record: OwnerRecord, path: string): boolean {
  if (record.host === hostname()) {
    if (!processAlive(record.pid)) return false;
    // A process with the ID exists; the start identity tells whether it is
    // the owner or a later process that was given the same ID.
    const same = processIdentityMatches(record.identity, record.pid);
    if (same !== undefined) return same;
  }
  return recentlyModified(path, UNVERIFIED_OWNER_MS);
}

/**
 * The process ID of another live owner of the session file, `0` for an owner
 * record still being written, or undefined when there is none. Records of
 * owners that are gone are removed on the way.
 */
export function liveOwner(
  sessionFile: string,
  exceptInstance?: string,
): number | undefined {
  const directory = join(dirname(sessionFile), OWNER_DIRECTORY);
  const session = basename(sessionFile);
  let names: string[];
  try {
    names = readdirSync(directory);
  } catch {
    return undefined;
  }
  let live: number | undefined;
  for (const name of names) {
    if (!name.startsWith(`${session}.`) || !name.endsWith(".json")) continue;
    const instance = name.slice(session.length + 1, -".json".length);
    if (!INSTANCE.test(instance) || instance === exceptInstance) continue;
    const path = join(directory, name);
    const record = parseOwner(path, session);
    const alive = record
      ? ownerAlive(record, path)
      : recentlyModified(path, PARTIAL_OWNER_MS);
    if (alive) live ??= record?.pid ?? 0;
    else rmSync(path, { force: true });
  }
  return live;
}

/**
 * The owner record this process holds for the session file it writes. A
 * record names the process instance (PID, start identity, host, and a random
 * instance ID), so after a crash the next launch takes the session over even
 * when another process was given the same PID. Two launches that race for
 * one file may both find the other and both start a new session; neither
 * ever appends to a file the other writes.
 */
export class SessionOwnership {
  private readonly instance = randomUUID();
  private held: { file: string; path: string; bytes: string } | undefined;
  private beat: NodeJS.Timeout | undefined;
  private readonly onExit = () => this.release();

  get file(): string | undefined {
    return this.held?.file;
  }

  /** Whether another live process owns the session file. */
  heldByOther(sessionFile: string): boolean {
    return liveOwner(resolve(sessionFile), this.instance) !== undefined;
  }

  /**
   * Takes the session file over from the one held before, which is released
   * either way. False when another live process owns it.
   */
  claim(sessionFile: string): boolean {
    const file = resolve(sessionFile);
    if (this.held?.file === file) return true;
    this.release();
    const directory = join(dirname(file), OWNER_DIRECTORY);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const session = basename(file);
    const record: OwnerRecord = {
      schema: OWNER_SCHEMA,
      session,
      pid: process.pid,
      identity: selfIdentity(),
      host: hostname(),
      instance: this.instance,
    };
    const path = join(directory, `${session}.${this.instance}.json`);
    const bytes = `${JSON.stringify(record)}\n`;
    writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
    // Written before looking, so of two racing launches at least one sees
    // the other.
    if (liveOwner(file, this.instance) !== undefined) {
      rmSync(path, { force: true });
      return false;
    }
    this.held = { file, path, bytes };
    this.beat = setInterval(() => {
      const now = new Date();
      try {
        if (this.held && readFileSync(this.held.path, "utf8") === bytes)
          utimesSync(this.held.path, now, now);
      } catch {
        // Retried on the next beat.
      }
    }, OWNER_HEARTBEAT_MS);
    this.beat.unref?.();
    process.on("exit", this.onExit);
    return true;
  }

  /** Gives the held session file up; a crash leaves it to the next launch. */
  release(): void {
    const held = this.held;
    if (!held) return;
    this.held = undefined;
    clearInterval(this.beat);
    this.beat = undefined;
    process.removeListener("exit", this.onExit);
    try {
      if (readFileSync(held.path, "utf8") === held.bytes)
        rmSync(held.path, { force: true });
    } catch {
      // Already gone; a stale record is removed by the next launch.
    }
  }
}

export interface OpenedSession {
  readonly sessionManager: SessionManager;
  readonly ownership: SessionOwnership;
  /** Shown before the session starts, when it is not the one resumed. */
  readonly notice?: string;
}

function mebibytes(size: number): string {
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}

/**
 * File text inside a diagnostic: control characters are shown escaped and the
 * length is bounded, so a crafted entry ID can neither drive the terminal nor
 * flood the message.
 */
function printable(text: string, limit = 240): string {
  const clean = text.replace(
    // biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point
    /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  return clean.length > limit ? `${clean.slice(0, limit)}...` : clean;
}

/** The error code of a failed file operation, shown escaped. */
function errorCode(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === "string" ? printable(code, 32) : "unknown error";
}

/**
 * Why a `/resume` into `target` is refused, worded for the user, or undefined
 * when it may go ahead: another live process owns the file, or it is over the
 * size limit or damaged, which Pi's own load would not report.
 */
export function resumeRefusal(
  ownership: SessionOwnership,
  target: string,
  command: string,
): string | undefined {
  if (ownership.heldByOther(target))
    return `That session is open in another ${command} process. Continue it there, or start a new session here.`;
  let problem: SessionProblem | undefined;
  try {
    problem = inspectSession(target);
  } catch (error) {
    // A check that did not finish (EMFILE, EIO, a file that is gone) proves
    // nothing about the file, so it is not resumed.
    return `That session is not resumed: PiShip could not check it (${errorCode(error)}). The file was not loaded or changed. Make sure the file is readable and the system is not out of open files, then resume it again, or start a new session here.`;
  }
  if (!problem) return undefined;
  const why =
    problem.kind === "oversized"
      ? `it is ${mebibytes(problem.size)}, over the ${mebibytes(MAX_RESUME_BYTES)} limit for resuming a session automatically`
      : `it is damaged and Pi would continue without the damaged part (${printable(problem.reason)})`;
  return `That session is not resumed: ${why}. The file was not loaded or changed. Start a new session here instead.`;
}

/**
 * Opens the session a launch continues: the project's most recent one when
 * no other live process owns it and it is safe to load, a new one when
 * `newSession` is set or another process owns the most recent. A corrupt or
 * oversized most recent session stops the launch with the file unchanged,
 * except for a `disposable` one (the acceptance sessions of `--smoke`, which
 * hold no user work and cannot be given `--new-session` by `piship test`,
 * `dev --smoke`, or `doctor`): it starts a new session and says so, and the
 * file is kept.
 */
export function openSession(
  cwd: string,
  sessionDir: string,
  options: {
    readonly newSession: boolean;
    readonly command: string;
    readonly disposable?: boolean;
  },
): OpenedSession {
  const ownership = new SessionOwnership();
  const fresh = () => {
    const sessionManager = SessionManager.create(cwd, sessionDir);
    const file = sessionManager.getSessionFile();
    if (file) ownership.claim(file);
    return sessionManager;
  };
  const recent = options.newSession
    ? undefined
    : mostRecentSession(sessionDir, cwd);
  if (!recent) return { sessionManager: fresh(), ownership };
  if (!ownership.claim(recent))
    return {
      sessionManager: fresh(),
      ownership,
      notice: `The most recent session of this project is open in another ${options.command} process, so this one starts a new session. The other session is not changed: ${recent}`,
    };
  try {
    const problem = inspectSession(recent);
    if (problem && options.disposable)
      return {
        sessionManager: fresh(),
        ownership,
        notice: `The most recent acceptance session is ${problem.kind === "oversized" ? `${mebibytes(problem.size)}, over the ${mebibytes(MAX_RESUME_BYTES)} limit` : `damaged (${printable(problem.reason)})`}, so this run starts a new one. The file is kept unchanged: ${recent}`,
      };
    if (problem) {
      const action = `Run ${options.command} --new-session to start a new session. The file is kept unchanged for recovery; it was not loaded, repaired, or deleted.`;
      throw problem.kind === "oversized"
        ? new PiShipError(
            "CONFIG_UNAVAILABLE",
            `The most recent session of this project is ${mebibytes(problem.size)}, over the ${mebibytes(MAX_RESUME_BYTES)} limit for resuming a session automatically: ${recent}`,
            { userAction: action, component: "session" },
          )
        : new PiShipError(
            "CONFIG_UNAVAILABLE",
            `The most recent session of this project is damaged and is not resumed, because Pi would continue without the damaged part: ${printable(problem.reason)}: ${recent}`,
            { userAction: action, component: "session" },
          );
    }
    return {
      sessionManager: SessionManager.open(recent, sessionDir, cwd),
      ownership,
    };
  } catch (error) {
    ownership.release();
    throw error;
  }
}
