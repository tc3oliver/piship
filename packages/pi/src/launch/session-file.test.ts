// The session a launch resumes: corrupt and oversized session files are
// refused before Pi reads them (#62, #65), and a session file has one owner
// process at a time (#57). The files are written by Pi's own SessionManager;
// the owner tests run the built module in real child processes.
import { type ChildProcess, spawn } from "node:child_process";
import {
  closeSync,
  existsSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  deadPid,
  livePid,
  stopLiveProcesses,
} from "../../../../tests/helpers/processes.js";
import {
  inspectSession,
  MAX_RESUME_BYTES,
  mostRecentSession,
  OWNER_DIRECTORY,
  openSession,
  resumeRefusal,
  SessionOwnership,
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
  stopLiveProcesses();
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
  // The owner record taken for the inspection is given back.
  expect(readdirSync(join(sessionDir, OWNER_DIRECTORY))).toEqual([]);
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
    opened.ownership.release();
  });

  it("starts a new session when the project has none", () => {
    persistedSession(join(temp, "other-project"));
    const opened = open();
    expect(opened.sessionManager.getSessionFile()).not.toBe(undefined);
    expect(opened.sessionManager.getEntries()).toEqual([]);
    opened.ownership.release();
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
    opened.ownership.release();
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
    const opened = open();
    expect(lines(file)[1]).toMatchObject({ message: { role: "custom" } });
    opened.ownership.release();
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
    opened.ownership.release();
    expect(readFileSync(file).equals(before)).toBe(true);
    // The next plain launch continues the new session.
    const next = open();
    expect(next.sessionManager.getSessionId()).toBe(
      opened.sessionManager.getSessionId(),
    );
    next.ownership.release();
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
    opened.ownership.release();
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
    opened.ownership.release();
  });
});

describe("a damaged acceptance session is replaced, not refused", () => {
  const disposable = () =>
    openSession(project, sessionDir, {
      newSession: false,
      command: "mypi",
      disposable: true,
    });

  it("starts a new session with a notice for a damaged or oversized one and keeps the file", () => {
    const { file, id, lines: entries } = persistedSession();
    rewrite(file, [...entries.slice(0, 3), "{not json"]);
    const damaged = readFileSync(file);
    const first = disposable();
    expect(first.sessionManager.getSessionId()).not.toBe(id);
    expect(first.notice).toMatch(
      /acceptance session is damaged \(line 4 is not valid JSON\), so this run starts a new one/,
    );
    expect(readFileSync(file).equals(damaged)).toBe(true);
    first.ownership.release();
    rewrite(file, [entries[0]]);
    const fd = openSync(file, "r+");
    try {
      ftruncateSync(fd, MAX_RESUME_BYTES + 1);
    } finally {
      closeSync(fd);
    }
    const second = disposable();
    expect(second.sessionManager.getSessionId()).not.toBe(id);
    expect(second.notice).toMatch(/64\.0 MiB, over the 64\.0 MiB limit/);
    expect(statSync(file).size).toBe(MAX_RESUME_BYTES + 1);
    second.ownership.release();
  });

  it("still resumes a healthy one without a notice", () => {
    const { id } = persistedSession();
    const opened = disposable();
    expect(opened.sessionManager.getSessionId()).toBe(id);
    expect(opened.notice).toBeUndefined();
    opened.ownership.release();
  });
});

describe("a /resume checks its target like a launch does (#57, #62, #65)", () => {
  it("lets a valid session that nobody owns be resumed", () => {
    const { file } = persistedSession();
    const ownership = new SessionOwnership();
    expect(resumeRefusal(ownership, file, "mypi")).toBeUndefined();
    expect(ownerRecords()).toEqual([]);
  });

  it("refuses a session another live process owns", () => {
    const { file } = persistedSession();
    const other = new SessionOwnership();
    expect(other.claim(file)).toBe(true);
    expect(resumeRefusal(new SessionOwnership(), file, "mypi")).toMatch(
      /open in another mypi process/,
    );
    other.release();
  });

  it("refuses a damaged session and an oversized one, and leaves the file alone", () => {
    const { file, lines: entries } = persistedSession();
    const ownership = new SessionOwnership();
    rewrite(file, [...entries.slice(0, 3), "{not json"]);
    const damaged = readFileSync(file);
    expect(resumeRefusal(ownership, file, "mypi")).toMatch(
      /not resumed: it is damaged.*line 4 is not valid JSON/,
    );
    expect(readFileSync(file).equals(damaged)).toBe(true);
    rewrite(file, [entries[0]]);
    const fd = openSync(file, "r+");
    try {
      ftruncateSync(fd, MAX_RESUME_BYTES + 1);
    } finally {
      closeSync(fd);
    }
    expect(resumeRefusal(ownership, file, "mypi")).toMatch(
      /not resumed: it is 64\.0 MiB, over the 64\.0 MiB limit/,
    );
    expect(statSync(file).size).toBe(MAX_RESUME_BYTES + 1);
  });

  it("leaves a file that cannot be read to Pi", () => {
    expect(
      resumeRefusal(
        new SessionOwnership(),
        join(sessionDir, "gone.jsonl"),
        "mypi",
      ),
    ).toBeUndefined();
  });

  it("shows an entry ID from the file escaped and bounded, never raw", () => {
    const { file, lines: entries } = persistedSession();
    const id = `x\u001b]0;owned\u0007${"y".repeat(5000)}`;
    rewrite(file, [
      ...entries.slice(0, 2),
      { ...entries[2], id },
      { ...entries[3], id },
      ...entries.slice(4),
    ]);
    const message = resumeRefusal(new SessionOwnership(), file, "mypi") ?? "";
    expect(message).toContain("the message entry x\\u001b]0;owned\\u0007yyy");
    expect(
      [...message].some((char) => {
        const code = char.charCodeAt(0);
        return code < 32 || (code >= 127 && code < 160);
      }),
    ).toBe(false);
    expect(message).toContain("\\u001b");
    expect(message.length).toBeLessThan(600);
    expectRefused(file, /message entry x\\u001b\]0;owned/);
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

const DIST = pathToFileURL(
  resolve(import.meta.dirname, "../../dist/launch/session-file.js"),
).href;

/**
 * A launch in a child process: opens the session like PiShip does, reports
 * it, then appends one turn for each line it reads and exits on `exit`.
 */
const CHILD = `
import { createInterface } from "node:readline";
import { openSession } from ${JSON.stringify(DIST)};
const [cwd, dir] = process.argv.slice(2);
const opened = openSession(cwd, dir, { newSession: false, command: "mypi" });
const manager = opened.sessionManager;
console.log(JSON.stringify({
  file: manager.getSessionFile(),
  id: manager.getSessionId(),
  notice: opened.notice ?? null,
}));
const usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
for await (const line of createInterface({ input: process.stdin })) {
  if (line === "exit") break;
  manager.appendMessage({ role: "user", content: line, timestamp: Date.now() });
  manager.appendMessage({ role: "assistant", content: [{ type: "text", text: line }],
    api: "piship-test", provider: "piship", model: "none", usage,
    stopReason: "stop", timestamp: Date.now() });
  console.log("appended");
}
opened.ownership.release();
// The open standard input would keep the process running.
process.exit(0);
`;

interface Launch {
  readonly child: ChildProcess;
  readonly next: () => Promise<string>;
  readonly exited: Promise<number | null>;
}

const launches: ChildProcess[] = [];
afterEach(() => {
  for (const child of launches.splice(0)) child.kill("SIGKILL");
});

function launch(cwd = project, dir = sessionDir): Launch {
  const script = join(temp, "launch.mjs");
  writeFileSync(script, CHILD);
  const child = spawn(process.execPath, [script, cwd, dir], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  launches.push(child);
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += chunk;
  });
  const queue: string[] = [];
  const waiting: ((line: string) => void)[] = [];
  createInterface({ input: child.stdout as NodeJS.ReadableStream }).on(
    "line",
    (line) => {
      const resolveLine = waiting.shift();
      if (resolveLine) resolveLine(line);
      else queue.push(line);
    },
  );
  const exited = new Promise<number | null>((done) =>
    child.on("exit", (code) => done(code)),
  );
  const next = () =>
    queue.length
      ? Promise.resolve(queue.shift() as string)
      : Promise.race([
          new Promise<string>((done) => waiting.push(done)),
          exited.then((code) => {
            throw new Error(`launch exited with ${code}: ${stderr}`);
          }),
          new Promise<string>((_, fail) =>
            setTimeout(
              () => fail(new Error(`launch did not answer: ${stderr}`)),
              30_000,
            ).unref(),
          ),
        ]);
  return { child, next, exited };
}

async function started(launched: Launch) {
  return JSON.parse(await launched.next()) as {
    file: string;
    id: string;
    notice: string | null;
  };
}

async function turn(launched: Launch, text: string) {
  launched.child.stdin?.write(`${text}\n`);
  expect(await launched.next()).toBe("appended");
}

function ownerRecords(): string[] {
  const directory = join(sessionDir, OWNER_DIRECTORY);
  return existsSync(directory) ? readdirSync(directory) : [];
}

/** Every entry's parent is the entry before it: one branch, no fork. */
function expectLinear(file: string) {
  const entries = lines(file).slice(1);
  entries.forEach((entry, index) => {
    expect(entry.parentId).toBe(index === 0 ? null : entries[index - 1]?.id);
  });
}

describe("one owner per session file (#57)", () => {
  it("gives a second concurrent launch a new session instead of the owned one", async () => {
    const { file, id } = persistedSession(project, sessionDir, 1);
    const simple = [...lines(file)];
    // Keep the fixture linear: drop everything after the first turn.
    rewrite(file, simple.slice(0, 3));
    const a = launch();
    const first = await started(a);
    expect(first).toMatchObject({ file, id, notice: null });
    const b = launch();
    const second = await started(b);
    expect(second.file).not.toBe(file);
    expect(second.id).not.toBe(id);
    expect(second.notice).toContain("open in another mypi process");
    expect(second.notice).toContain(file);
    await turn(a, "from A 1");
    await turn(b, "from B 1");
    await turn(a, "from A 2");
    await turn(b, "from B 2");
    a.child.stdin?.write("exit\n");
    b.child.stdin?.write("exit\n");
    expect(await a.exited).toBe(0);
    expect(await b.exited).toBe(0);
    const owned = readFileSync(file, "utf8");
    expect(owned).toContain("from A 2");
    expect(owned).not.toContain("from B");
    expectLinear(file);
    const other = readFileSync(second.file, "utf8");
    expect(other).toContain("from B 2");
    expect(other).not.toContain("from A");
    expectLinear(second.file);
    // A clean exit gives both files back.
    expect(ownerRecords()).toEqual([]);
  }, 60_000);

  it("takes the session over after its owner crashed", async () => {
    const { file, id } = persistedSession();
    const a = launch();
    expect(await started(a)).toMatchObject({ file, id });
    expect(ownerRecords()).toHaveLength(1);
    a.child.kill("SIGKILL");
    await a.exited;
    expect(ownerRecords()).toHaveLength(1);
    const b = launch();
    expect(await started(b)).toMatchObject({ file, id, notice: null });
    await turn(b, "after the crash");
    b.child.stdin?.write("exit\n");
    expect(await b.exited).toBe(0);
    expect(readFileSync(file, "utf8")).toContain("after the crash");
    expect(ownerRecords()).toEqual([]);
  }, 60_000);

  it("takes over a record whose PID now belongs to another process", () => {
    const { file, id } = persistedSession();
    const directory = join(sessionDir, OWNER_DIRECTORY);
    mkdirSync(directory);
    const session = file.slice(sessionDir.length + 1);
    const stale = (pid: number, instance: string) =>
      writeFileSync(
        join(directory, `${session}.${instance}.json`),
        JSON.stringify({
          schema: "piship-session-owner/v1",
          session,
          pid,
          identity: "a process that started earlier",
          host: hostname(),
          instance,
        }),
      );
    // A live process that is not the recorded owner, and an exited one.
    stale(livePid(), "00000000-0000-4000-8000-000000000001");
    stale(deadPid(), "00000000-0000-4000-8000-000000000002");
    const opened = open();
    expect(opened.notice).toBeUndefined();
    expect(opened.sessionManager.getSessionId()).toBe(id);
    expect(ownerRecords()).toHaveLength(1);
    opened.ownership.release();
    expect(ownerRecords()).toEqual([]);
  }, 30_000);

  it("lets launches in different projects run at once", async () => {
    const mine = persistedSession();
    const otherProject = join(temp, "other-project");
    mkdirSync(otherProject);
    const theirs = persistedSession(otherProject);
    const a = launch();
    const b = launch(otherProject);
    expect(await started(a)).toMatchObject({ file: mine.file, notice: null });
    expect(await started(b)).toMatchObject({ file: theirs.file, notice: null });
    a.child.stdin?.write("exit\n");
    b.child.stdin?.write("exit\n");
    expect(await a.exited).toBe(0);
    expect(await b.exited).toBe(0);
  }, 60_000);

  it("keeps acceptance sessions apart from user sessions", async () => {
    const acceptance = join(temp, "sessions", "acceptance");
    const user = persistedSession();
    const smoke = persistedSession(project, acceptance);
    const a = launch();
    expect(await started(a)).toMatchObject({ file: user.file });
    const opened = openSession(project, acceptance, {
      newSession: false,
      command: "mypi",
    });
    expect(opened.notice).toBeUndefined();
    expect(opened.sessionManager.getSessionFile()).toBe(smoke.file);
    opened.ownership.release();
    a.child.stdin?.write("exit\n");
    expect(await a.exited).toBe(0);
  }, 60_000);

  it("refuses to claim a file another live owner holds, and follows a switch", () => {
    const { file } = persistedSession();
    const first = new SessionOwnership();
    const second = new SessionOwnership();
    expect(first.claim(file)).toBe(true);
    expect(second.heldByOther(file)).toBe(true);
    expect(first.heldByOther(file)).toBe(false);
    expect(second.claim(file)).toBe(false);
    expect(second.file).toBeUndefined();
    // `/new` in the first process moves its record to the new file.
    const next = join(sessionDir, "next.jsonl");
    expect(first.claim(next)).toBe(true);
    expect(first.file).toBe(next);
    expect(second.claim(file)).toBe(true);
    first.release();
    second.release();
    expect(ownerRecords()).toEqual([]);
  });

  it("keeps a record that is still being written", () => {
    const { file } = persistedSession();
    const directory = join(sessionDir, OWNER_DIRECTORY);
    mkdirSync(directory);
    const session = file.slice(sessionDir.length + 1);
    writeFileSync(
      join(directory, `${session}.00000000-0000-4000-8000-000000000003.json`),
      '{"schema":',
    );
    const opened = open();
    expect(opened.sessionManager.getSessionFile()).not.toBe(file);
    expect(opened.notice).toContain("open in another mypi process");
    opened.ownership.release();
  });
});
