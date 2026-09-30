// Which persisted Pi session a launch resumes, and whether it is safe to
// resume.
//
// Pi 0.87.1's `SessionManager.continueRecent()` loads the most recent session
// of the project whatever it holds: it skips a line that does not parse (so a
// corrupt entry silently drops out of the conversation), appends a newline to
// a truncated last record, and reads a file of any size to its end. PiShip
// therefore picks the file itself, the way Pi does, and inspects it before
// Pi reads it; only then does Pi open it (`SessionManager.open`).
import {
  closeSync,
  fstatSync,
  openSync,
  readdirSync,
  readSync,
  statSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";

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

export interface OpenedSession {
  readonly sessionManager: SessionManager;
}

function mebibytes(size: number): string {
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}

/**
 * Opens the session a launch continues: the project's most recent one when
 * it is safe to load, a new one when `newSession` is set or there is none. A
 * corrupt or oversized most recent session stops the launch with the file
 * unchanged.
 */
export function openSession(
  cwd: string,
  sessionDir: string,
  options: { readonly newSession: boolean; readonly command: string },
): OpenedSession {
  const fresh = () => SessionManager.create(cwd, sessionDir);
  const recent = options.newSession
    ? undefined
    : mostRecentSession(sessionDir, cwd);
  if (!recent) return { sessionManager: fresh() };
  const problem = inspectSession(recent);
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
          `The most recent session of this project is damaged and is not resumed, because Pi would continue without the damaged part: ${problem.reason}: ${recent}`,
          { userAction: action, component: "session" },
        );
  }
  return {
    sessionManager: SessionManager.open(recent, sessionDir, cwd),
  };
}
