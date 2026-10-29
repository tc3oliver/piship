import { spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { processHostToken } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import { TaskRecorder, takeOrphanedTasks } from "./task-records.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
const state = () => {
  const dir = mkdtempSync(join(tmpdir(), "piship-task-records-"));
  dirs.push(dir);
  return dir;
};
const root = (dir: string) => join(dir, "data", "tasks");
const files = (dir: string) => readdirSync(root(dir));
/** Writes a record by hand, as another process would have left it. */
function plant(dir: string, name: string, record: object | string) {
  mkdirSync(root(dir), { recursive: true });
  writeFileSync(
    join(root(dir), name),
    typeof record === "string" ? record : JSON.stringify(record),
  );
}
const record = (pid: number, extra: object = {}) => ({
  schema: "piship-task-record/v2",
  pid,
  identity: null,
  host: processHostToken(),
  started: 1,
  tasks: ["dead"],
  ...extra,
});

describe("task records", () => {
  it("keeps a record while tasks run, and removes it when the last ends", () => {
    const dir = state();
    const recorder = new TaskRecorder(dir);
    recorder.add("a");
    recorder.add("b");
    expect(files(dir)).toHaveLength(1);
    recorder.remove("a");
    expect(files(dir)).toHaveLength(1);
    recorder.remove("b");
    expect(files(dir)).toHaveLength(0);
  });

  it("holds ids and the owner, never a command", () => {
    const dir = state();
    new TaskRecorder(dir).add("a");
    expect(takeOrphanedTasks(dir)).toEqual([]);
    const [name] = files(dir);
    const saved = JSON.parse(
      readFileSync(join(root(dir), name as string), "utf8"),
    );
    expect(saved.tasks).toEqual(["a"]);
    expect(saved.pid).toBe(process.pid);
    expect(saved).not.toHaveProperty("command");
  });

  it("leaves a record of another schema version alone", () => {
    const dir = state();
    plant(dir, "2147483646-1.json", {
      ...record(2147483646),
      schema: "piship-task-record/v99",
    });
    plant(dir, "2147483646-2.json", "not json");
    expect(takeOrphanedTasks(dir)).toEqual([]);
    expect(files(dir)).toEqual(["2147483646-1.json"]);
  });

  it("reports a dead owner's tasks once, and leaves a live owner's alone", () => {
    const dir = state();
    new TaskRecorder(dir).add("live");
    plant(dir, "2147483646-1.json", record(2147483646));
    expect(takeOrphanedTasks(dir)).toEqual([{ id: "dead", owner: 2147483646 }]);
    expect(takeOrphanedTasks(dir)).toEqual([]);
    expect(files(dir)).toHaveLength(1);
  });

  // Needs a `sleep` binary, which Windows does not have.
  it.runIf(process.platform !== "win32")(
    "reports tasks whose owner ID now belongs to an unrelated live process",
    async () => {
      const dir = state();
      const other = spawn("sleep", ["30"], { stdio: "ignore" });
      try {
        // Started long before this process: the ID was reused.
        plant(
          dir,
          `${other.pid}-1.json`,
          record(other.pid as number, {
            identity: "other-boot:1",
          }),
        );
        expect(takeOrphanedTasks(dir)).toEqual([
          { id: "dead", owner: other.pid },
        ]);
      } finally {
        other.kill();
      }
    },
  );

  it("does not overwrite an orphan when a new process gets its ID", () => {
    const dir = state();
    plant(dir, `${process.pid}-1.json`, record(process.pid));
    new TaskRecorder(dir).add("mine");
    expect(files(dir)).toHaveLength(2);
    expect(takeOrphanedTasks(dir)).toEqual([
      { id: "dead", owner: process.pid },
    ]);
    expect(files(dir)).toHaveLength(1);
  });

  it("removes malformed records and stale temporary files", () => {
    const dir = state();
    plant(dir, "a.json", "not json");
    plant(dir, "b.json", record(0));
    plant(dir, "c.json", record(-5));
    plant(dir, "d.json", { ...record(1), tasks: [1] });
    plant(dir, "old.json.tmp", "{");
    plant(dir, "new.json.tmp", "{");
    const old = new Date(Date.now() - 10 * 60_000);
    utimesSync(join(root(dir), "old.json.tmp"), old, old);
    expect(takeOrphanedTasks(dir)).toEqual([]);
    expect(files(dir).sort()).toEqual(["new.json.tmp"]);
    expect(existsSync(join(root(dir), "b.json"))).toBe(false);
  });
});
