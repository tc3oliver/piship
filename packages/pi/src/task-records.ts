// An on-disk record of the background tasks one PiShip process runs, so a
// later `doctor` can name tasks a killed process left behind. A SIGKILL runs
// no cleanup; on Linux bubblewrap's --die-with-parent still ends contained
// tasks, but macOS and uncontained tasks keep running. The record is
// removed when the last task ends or the session closes, and never holds more
// than the id and a redacted command preview.
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { processAlive, processHostToken, redact } from "@piship/contracts";

const SCHEMA = "piship-task-record/v1";
const PREVIEW_CHARS = 120;

export interface OrphanedTask {
  readonly id: string;
  readonly command: string;
  /** The PiShip process that started it, no longer running. */
  readonly owner: number;
}

interface TaskRecord {
  schema: typeof SCHEMA;
  pid: number;
  host: string;
  tasks: { id: string; command: string }[];
}

const directory = (stateDir: string) => join(stateDir, "data", "tasks");

/** The record of this process's running tasks. */
export class TaskRecorder {
  readonly #path: string;
  readonly #record: TaskRecord = {
    schema: SCHEMA,
    pid: process.pid,
    host: processHostToken(),
    tasks: [],
  };

  constructor(stateDir: string) {
    this.#path = join(directory(stateDir), `${process.pid}.json`);
  }

  add(id: string, command: string): void {
    this.#record.tasks.push({
      id,
      command: redact(command).slice(0, PREVIEW_CHARS),
    });
    this.#write();
  }

  remove(id: string): void {
    this.#record.tasks = this.#record.tasks.filter((task) => task.id !== id);
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

/**
 * Tasks recorded by PiShip processes that no longer exist. Each such record
 * is reported once and removed; a record of another host, or of a live
 * process, is left alone. Windows records nothing: a Job Object ends the
 * tasks with their owner.
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
  for (const name of names.filter((item) => item.endsWith(".json"))) {
    const path = join(root, name);
    try {
      const record = JSON.parse(readFileSync(path, "utf8")) as TaskRecord;
      if (
        record.schema !== SCHEMA ||
        record.host !== processHostToken() ||
        processAlive(record.pid)
      )
        continue;
      for (const task of record.tasks)
        found.push({ id: task.id, command: task.command, owner: record.pid });
      rmSync(path, { force: true });
    } catch {
      // An unreadable record is left for the next doctor.
    }
  }
  return found;
}
