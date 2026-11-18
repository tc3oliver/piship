// Real processes for tests of rules that depend on a process ID: one that has
// exited, and one that keeps running. Importing this module stops every live
// process after each test of the importing file, so none outlives its test
// even when the file forgets `afterEach(stopLiveProcesses)`.
import { type ChildProcess, spawn } from "node:child_process";
import { afterEach } from "vitest";

const children: ChildProcess[] = [];

/**
 * A process ID that no running process has. Not the ID of an exited child:
 * under parallel test files the system can hand it to a new process at once.
 * This one is above the largest ID Linux (2^22) and macOS (99998) assign,
 * and a multiple of four far beyond the IDs Windows assigns.
 */
export function deadPid(): number {
  return 2 ** 30;
}

/** A live process that is not this one; stopped by `stopLiveProcesses`. */
export function livePid(): number {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  children.push(child);
  return child.pid as number;
}

export function stopLiveProcesses(): void {
  for (const child of children.splice(0)) child.kill();
}

afterEach(stopLiveProcesses);
