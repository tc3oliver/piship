// An on-disk record of the background tasks one PiShip process runs, so a
// later `doctor` can name tasks a killed process left behind. A SIGKILL runs
// no cleanup; on Linux bubblewrap's --die-with-parent still ends contained
// tasks, but macOS and uncontained tasks keep running. A task is removed
// from the record once its process is gone, and the file with the last one.
// It holds task ids, each task's process ID and start, and the owner's
// identity only, never a command.
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { processHostToken } from "@piship/contracts";
import {
  processIdentity,
  recordedIdentity,
  recordedProcessGone,
  recordedStart,
} from "@piship/core";

const SCHEMA = "piship-task-record/v2";
/** A leftover temporary file older than this is from a crashed write. */
const STALE_TEMPORARY_MS = 60_000;

export interface OrphanedTask {
  readonly id: string;
  /** The PiShip process that started it, no longer running. */
  readonly owner: number;
  /** Its own process (group leader), proven still running as the one started. */
  readonly pid?: number;
}

/** A task's process, judged as `recordedProcessGone` judges an owner. */
interface TaskProcess {
  pid: number;
  identity: string | null;
  started: number;
}

interface TaskRecord {
  schema: typeof SCHEMA;
  pid: number;
  identity: string | null;
  host: string;
  started: number;
  tasks: string[];
  /** By task id; optional, so a record without it stays the same schema. */
  processes?: Record<string, TaskProcess>;
}

const directory = (stateDir: string) => join(stateDir, "data", "tasks");

/** The record of this process's running tasks. */
export class TaskRecorder {
  readonly #path: string;
  readonly #record: TaskRecord = {
    schema: SCHEMA,
    pid: process.pid,
    identity: recordedIdentity(),
    host: processHostToken(),
    started: recordedStart(),
    tasks: [],
    processes: {},
  };

  constructor(stateDir: string) {
    // The start time in the name: a later process with the same ID writes
    // its own file and never replaces an orphan's.
    this.#path = join(
      directory(stateDir),
      `${process.pid}-${this.#record.started}.json`,
    );
  }

  add(id: string): void {
    this.#record.tasks.push(id);
    this.#write();
  }

  /** The task runs as `pid`; its start tells it from a later process with that ID. */
  spawned(id: string, pid: number): void {
    if (!this.#record.tasks.includes(id)) return;
    this.#record.processes = {
      ...this.#record.processes,
      [id]: {
        pid,
        // Cheap on Linux only; elsewhere the spawn time stands in, as for the owner.
        identity:
          process.platform === "linux" ? (processIdentity(pid) ?? null) : null,
        started: Date.now(),
      },
    };
    this.#write();
  }

  remove(id: string): void {
    this.#record.tasks = this.#record.tasks.filter((task) => task !== id);
    delete this.#record.processes?.[id];
    this.#write();
  }

  #write(): void {
    try {
      if (!this.#record.tasks.length) {
        rmSync(this.#path, { force: true });
        return;
      }
      mkdirSync(join(this.#path, ".."), { recursive: true, mode: 0o700 });
      const temporary = `${this.#path}.tmp`;
      writeFileSync(temporary, JSON.stringify(this.#record), { mode: 0o600 });
      renameSync(temporary, this.#path);
    } catch {
      // The record only helps doctor; a task never fails because of it.
    }
  }
}

function otherSchema(text: string): boolean {
  try {
    const schema = (JSON.parse(text) as { schema?: unknown } | null)?.schema;
    return typeof schema === "string" && schema !== SCHEMA;
  } catch {
    return false;
  }
}

function parse(text: string): TaskRecord | undefined {
  try {
    const record = JSON.parse(text) as TaskRecord;
    return record?.schema === SCHEMA &&
      Number.isSafeInteger(record.pid) &&
      record.pid > 0 &&
      typeof record.host === "string" &&
      Number.isSafeInteger(record.started) &&
      Array.isArray(record.tasks) &&
      record.tasks.every((task) => typeof task === "string")
      ? record
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Tasks recorded by PiShip processes that are proven gone (a process that
 * reused the ID has another start identity). Each such record is reported
 * once and removed; a live owner's, or one whose owner cannot be judged, is
 * left alone. A malformed record and a stale temporary file are removed.
 * Windows records nothing: a Job Object ends the tasks with their owner.
 */
export function takeOrphanedTasks(stateDir: string): OrphanedTask[] {
  const found: OrphanedTask[] = [];
  const root = directory(stateDir);
  let names: string[];
  try {
    names = readdirSync(root);
  } catch {
    return found;
  }
  for (const name of names) {
    const path = join(root, name);
    try {
      if (name.endsWith(".tmp")) {
        if (Date.now() - statSync(path).mtimeMs > STALE_TEMPORARY_MS)
          rmSync(path, { force: true });
        continue;
      }
      if (!name.endsWith(".json")) continue;
      const text = readFileSync(path, "utf8");
      const record = parse(text);
      if (!record) {
        // Another schema version may be a newer PiShip's live record.
        if (!otherSchema(text)) rmSync(path, { force: true });
        continue;
      }
      if (
        recordedProcessGone({
          pid: record.pid,
          identity: record.identity,
          host: record.host,
          started: record.started,
        }) !== true
      )
        continue;
      for (const id of record.tasks) {
        const task = record.processes?.[id];
        const gone =
          task && Number.isSafeInteger(task.pid) && task.pid > 0
            ? recordedProcessGone({
                pid: task.pid,
                identity:
                  typeof task.identity === "string" ? task.identity : null,
                host: record.host,
                started: Number.isSafeInteger(task.started)
                  ? task.started
                  : null,
              })
            : undefined;
        // A task proven ended needs nothing; one that cannot be judged is still reported.
        if (gone === true) continue;
        found.push({
          id,
          owner: record.pid,
          ...(gone === false && task ? { pid: task.pid } : {}),
        });
      }
      rmSync(path, { force: true });
    } catch {
      // An unreadable record is left for the next doctor.
    }
  }
  return found;
}
