import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
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
const files = (dir: string) => readdirSync(join(dir, "data", "tasks"));

describe("task records", () => {
  it("keeps a record while tasks run, and removes it when the last ends", () => {
    const dir = state();
    const recorder = new TaskRecorder(dir);
    recorder.add("a", "sleep 1");
    recorder.add("b", "sleep 2");
    expect(files(dir)).toHaveLength(1);
    recorder.remove("a");
    expect(files(dir)).toHaveLength(1);
    recorder.remove("b");
    expect(files(dir)).toHaveLength(0);
  });

  it("redacts the command it records", () => {
    const dir = state();
    new TaskRecorder(dir).add(
      "a",
      "curl -H 'Authorization: Bearer abcdefghijkl'",
    );
    expect(takeOrphanedTasks(dir)).toEqual([]);
    const text = JSON.stringify(readdirSync(join(dir, "data", "tasks")));
    expect(text).toContain(String(process.pid));
  });

  it("reports the tasks of a dead owner once, and leaves a live owner's alone", () => {
    const dir = state();
    new TaskRecorder(dir).add("live", "sleep 1");
    const root = join(dir, "data", "tasks");
    mkdirSync(root, { recursive: true });
    writeFileSync(
      join(root, "2147483646.json"),
      JSON.stringify({
        schema: "piship-task-record/v1",
        pid: 2147483646,
        host: processHostToken(),
        tasks: [{ id: "dead", command: "sleep 9" }],
      }),
    );
    expect(takeOrphanedTasks(dir)).toEqual([
      { id: "dead", command: "sleep 9", owner: 2147483646 },
    ]);
    expect(takeOrphanedTasks(dir)).toEqual([]);
    expect(files(dir)).toHaveLength(1);
  });
});
