// The session a launch resumes: corrupt and oversized session files are
// refused before Pi reads them (#62, #65). The files are written by Pi's own
// SessionManager.
import {
  closeSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  inspectSession,
  MAX_RESUME_BYTES,
  mostRecentSession,
  openSession,
} from "./session-file.js";

let temp: string;
let project: string;
let sessionDir: string;
beforeEach(() => {
  temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-session-file-")));
  project = join(temp, "project");
  sessionDir = join(temp, "sessions", "user");
  mkdirSync(project);
  mkdirSync(sessionDir, { recursive: true });
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

function assistant(text: string) {
  return {
    role: "assistant" as const,
    content: [{ type: "text" as const, text }],
    api: "piship-test",
    provider: "piship",
    model: "none",
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason: "stop" as const,
    timestamp: Date.now(),
  };
}

/**
 * A persisted session written by Pi: messages, a model and a thinking-level
 * change, a context edit, a label, and a compaction.
 */
function persistedSession(cwd = project, dir = sessionDir, turns = 2) {
  const manager = SessionManager.create(cwd, dir);
  const ids: string[] = [];
  for (let turn = 0; turn < turns; turn += 1) {
    ids.push(
      manager.appendMessage({
        role: "user",
        content: `question ${turn}`,
        timestamp: Date.now(),
      }),
    );
    ids.push(manager.appendMessage(assistant(`answer ${turn}`)));
  }
  manager.appendModelChange("piship", "none");
  manager.appendThinkingLevelChange("low");
  manager.appendContextEdit(ids[0] as string, { content: "edited question" });
  manager.appendLabelChange(ids[1] as string, "kept");
  manager.appendCompaction("summary so far", ids[2] as string, 100);
  manager.appendMessage({
    role: "user",
    content: "after compaction",
    timestamp: Date.now(),
  });
  manager.appendMessage(assistant("still here"));
  const file = manager.getSessionFile() as string;
  return { file, id: manager.getSessionId(), lines: lines(file) };
}

function lines(file: string): Record<string, unknown>[] {
  return readFileSync(file, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function rewrite(file: string, entries: readonly unknown[], tail = "\n") {
  writeFileSync(
    file,
    `${entries.map((entry) => (typeof entry === "string" ? entry : JSON.stringify(entry))).join("\n")}${tail}`,
  );
}

function indexOfType(entries: Record<string, unknown>[], type: string) {
  return entries.findIndex((entry) => entry.type === type);
}

function open(newSession = false) {
  return openSession(project, sessionDir, { newSession, command: "mypi" });
}

/** Opening the session fails with the diagnostic, and the file is unchanged. */
function expectRefused(file: string, pattern: RegExp) {
  const before = readFileSync(file);
  const mtime = statSync(file).mtimeMs;
  let error: unknown;
  try {
    open();
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(PiShipError);
  const refused = error as PiShipError;
  expect(refused.message).toMatch(pattern);
  expect(refused.message).toContain(file);
  expect(refused.userAction).toContain("mypi --new-session");
  expect(refused.userAction).toContain("kept unchanged");
  expect(readFileSync(file).equals(before)).toBe(true);
  expect(statSync(file).mtimeMs).toBe(mtime);
  return refused;
}

describe("resuming a persisted session", () => {
  it("resumes a valid session written by Pi unchanged", () => {
    const { file, id } = persistedSession();
    const before = readFileSync(file);
    expect(inspectSession(file)).toBeUndefined();
    const opened = open();
    expect(opened.notice).toBeUndefined();
    expect(opened.sessionManager.getSessionFile()).toBe(file);
    expect(opened.sessionManager.getSessionId()).toBe(id);
    const reference = SessionManager.continueRecent(project, sessionDir);
    expect(opened.sessionManager.getLeafId()).toBe(reference.getLeafId());
    expect(opened.sessionManager.buildSessionContext()).toEqual(
      reference.buildSessionContext(),
    );
    expect(readFileSync(file).equals(before)).toBe(true);
  });

  it("starts a new session when the project has none", () => {
    persistedSession(join(temp, "other-project"));
    const opened = open();
    expect(opened.sessionManager.getSessionFile()).not.toBe(undefined);
    expect(opened.sessionManager.getEntries()).toEqual([]);
  });

  it("migrates a version 1 session as Pi does", () => {
    const file = join(sessionDir, "2020-01-01T00-00-00-000Z_legacy.jsonl");
    rewrite(file, [
      {
        type: "session",
        id: "legacy",
        timestamp: "2020-01-01T00:00:00.000Z",
        cwd: project,
      },
      {
        type: "message",
        timestamp: "2020-01-01T00:00:01.000Z",
        message: { role: "user", content: "old question", timestamp: 1 },
      },
      {
        type: "message",
        timestamp: "2020-01-01T00:00:02.000Z",
        message: { ...assistant("old answer"), timestamp: 2 },
      },
    ]);
    expect(inspectSession(file)).toBeUndefined();
    const opened = open();
    expect(opened.sessionManager.getSessionId()).toBe("legacy");
    const migrated = lines(file);
    expect(migrated[0]).toMatchObject({ type: "session", version: 3 });
    expect(migrated[2]?.parentId).toBe(migrated[1]?.id);
    expect(
      JSON.stringify(opened.sessionManager.buildSessionContext().messages),
    ).toContain("old answer");
  });

  it("migrates a version 2 session as Pi does", () => {
    const file = join(sessionDir, "2021-01-01T00-00-00-000Z_v2.jsonl");
    rewrite(file, [
      {
        type: "session",
        version: 2,
        id: "v2",
        timestamp: "2021-01-01T00:00:00.000Z",
        cwd: project,
      },
      {
        type: "message",
        id: "a1",
        parentId: null,
        timestamp: "2021-01-01T00:00:01.000Z",
        message: { role: "hookMessage", content: "hook", timestamp: 1 },
      },
    ]);
    expect(inspectSession(file)).toBeUndefined();
    open();
    expect(lines(file)[1]).toMatchObject({ message: { role: "custom" } });
  });
});

describe("a corrupt session is not resumed (#62)", () => {
  it("refuses a malformed message in the middle", () => {
    const { file, lines: entries } = persistedSession();
    const broken = [...entries] as unknown[];
    broken[2] = JSON.stringify(entries[2]).slice(0, 40);
    rewrite(file, broken);
    expect(inspectSession(file)).toEqual({
      kind: "corrupt",
      reason: "line 3 is not valid JSON",
    });
    expectRefused(file, /damaged.*line 3 is not valid JSON/);
  });

  it("refuses a truncated last record, which Pi would complete", () => {
    const { file, lines: entries } = persistedSession();
    const last = JSON.stringify(entries.at(-1));
    rewrite(file, [...entries.slice(0, -1), last.slice(0, 30)], "");
    const refused = expectRefused(
      file,
      /last record \(line \d+\) is incomplete/,
    );
    expect(refused.code).toBe("CONFIG_UNAVAILABLE");
  });

  it("resumes a complete last record that only lacks its newline", () => {
    const { file, lines: entries } = persistedSession();
    rewrite(file, entries, "");
    expect(inspectSession(file)).toBeUndefined();
  });

  it("refuses an entry whose parent is missing", () => {
    const { file, lines: entries } = persistedSession();
    const removed = entries[2] as { id: string };
    rewrite(file, [...entries.slice(0, 2), ...entries.slice(3)]);
    expectRefused(
      file,
      new RegExp(`names parent ${removed.id}, which is not in the file`),
    );
  });

  it("refuses a duplicate entry ID", () => {
    const { file, lines: entries } = persistedSession();
    const duplicate = { ...entries[3], id: entries[2]?.id };
    rewrite(file, [...entries.slice(0, 3), duplicate, ...entries.slice(4)]);
    expectRefused(file, /line 4 repeats the ID of the entry on line 3/);
  });

  it("refuses parent references that form a cycle", () => {
    const { file, lines: entries } = persistedSession();
    const first = { ...entries[1], parentId: entries.at(-1)?.id };
    rewrite(file, [entries[0], first, ...entries.slice(2)]);
    expectRefused(file, /parent references form a cycle/);
  });

  it("refuses a compaction that names a missing first kept entry", () => {
    const { file, lines: entries } = persistedSession();
    const at = indexOfType(entries, "compaction");
    const broken = [...entries];
    broken[at] = { ...entries[at], firstKeptEntryId: "deadbeef" };
    rewrite(file, broken);
    expectRefused(
      file,
      /compaction entry .* names first kept entry deadbeef, which is not in the file/,
    );
  });

  it("refuses a compaction without its summary", () => {
    const { file, lines: entries } = persistedSession();
    const at = indexOfType(entries, "compaction");
    const broken = [...entries];
    const { summary: _summary, ...rest } = entries[at] as Record<
      string,
      unknown
    >;
    broken[at] = rest;
    rewrite(file, broken);
    expectRefused(file, /compaction entry .* has no summary/);
  });

  it("refuses a context edit that names a missing target", () => {
    const { file, lines: entries } = persistedSession();
    const at = indexOfType(entries, "context_edit");
    const broken = [...entries];
    broken[at] = { ...entries[at], targetId: "deadbeef" };
    rewrite(file, broken);
    expectRefused(
      file,
      /context_edit entry .* names target deadbeef, which is not in the file/,
    );
  });

  it("refuses a context edit without its replacement", () => {
    const { file, lines: entries } = persistedSession();
    const at = indexOfType(entries, "context_edit");
    const broken = [...entries];
    broken[at] = { ...entries[at], replacement: "text" };
    rewrite(file, broken);
    expectRefused(file, /context_edit entry .* has no target or replacement/);
  });

  it("refuses a second session header", () => {
    const { file, lines: entries } = persistedSession();
    rewrite(file, [...entries, entries[0]]);
    expectRefused(file, /is a second session header/);
  });

  it("refuses a line that is not a session entry", () => {
    const { file, lines: entries } = persistedSession();
    rewrite(file, [entries[0], "[1,2]", ...entries.slice(1)]);
    expectRefused(file, /line 2 is not a session entry/);
  });

  it("starts a new session with --new-session and keeps the damaged one", () => {
    const { file, id, lines: entries } = persistedSession();
    rewrite(file, [...entries.slice(0, 2), "{not json", ...entries.slice(2)]);
    const before = readFileSync(file);
    const opened = open(true);
    expect(opened.sessionManager.getSessionId()).not.toBe(id);
    expect(opened.sessionManager.getSessionFile()).not.toBe(file);
    opened.sessionManager.appendMessage({
      role: "user",
      content: "fresh start",
      timestamp: Date.now(),
    });
    opened.sessionManager.appendMessage(assistant("hello"));
    expect(readFileSync(file).equals(before)).toBe(true);
    // The next plain launch continues the new session.
    const next = open();
    expect(next.sessionManager.getSessionId()).toBe(
      opened.sessionManager.getSessionId(),
    );
  });
});

describe("a very large session is not resumed automatically (#65)", () => {
  it("resumes a large compacted history below the limit and refuses it above", () => {
    const { file, id } = persistedSession(project, sessionDir, 400);
    const size = statSync(file).size;
    expect(size).toBeGreaterThan(100_000);
    expect(inspectSession(file, size)).toBeUndefined();
    expect(inspectSession(file, size - 1)).toEqual({
      kind: "oversized",
      size,
    });
    const opened = open();
    expect(opened.sessionManager.getSessionId()).toBe(id);
  });

  it("refuses a session over the default limit without reading it", () => {
    const { file, lines: entries } = persistedSession();
    rewrite(file, [entries[0]]);
    // A sparse tail of zero bytes: read, it would be a corrupt session
    // rather than an oversized one.
    const fd = openSync(file, "r+");
    try {
      ftruncateSync(fd, MAX_RESUME_BYTES + 1);
    } finally {
      closeSync(fd);
    }
    expect(inspectSession(file)).toEqual({
      kind: "oversized",
      size: MAX_RESUME_BYTES + 1,
    });
    expectRefused(file, /is 64\.0 MiB, over the 64\.0 MiB limit/);
  });

  it("starts a new session with --new-session without loading the large one", () => {
    const { file, id, lines: entries } = persistedSession();
    rewrite(file, [entries[0]]);
    const fd = openSync(file, "r+");
    try {
      ftruncateSync(fd, MAX_RESUME_BYTES + 1);
    } finally {
      closeSync(fd);
    }
    const opened = open(true);
    expect(opened.sessionManager.getSessionId()).not.toBe(id);
    expect(statSync(file).size).toBe(MAX_RESUME_BYTES + 1);
  });
});

describe("finding the most recent session", () => {
  it("chooses the file continueRecent chooses", () => {
    const other = persistedSession(join(temp, "other-project"));
    const mine = persistedSession();
    // Newer files that are not this project's session: another project's
    // and a file with no header.
    const later = persistedSession(join(temp, "later-project"));
    writeFileSync(join(sessionDir, "zz-garbage.jsonl"), "not a session\n");
    expect(mostRecentSession(sessionDir, project)).toBe(mine.file);
    expect(
      SessionManager.continueRecent(project, sessionDir).getSessionFile(),
    ).toBe(mine.file);
    expect(mostRecentSession(sessionDir, join(temp, "other-project"))).toBe(
      other.file,
    );
    expect(mostRecentSession(sessionDir, join(temp, "later-project"))).toBe(
      later.file,
    );
    expect(mostRecentSession(join(temp, "missing"), project)).toBeUndefined();
  });
});
