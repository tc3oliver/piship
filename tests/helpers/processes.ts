// Real processes for tests of rules that depend on a process ID: one that has
// exited, and one that keeps running. Call `stopLiveProcesses` after each
// test (`afterEach(stopLiveProcesses)`) so no live process outlives it.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";

const children: ChildProcess[] = [];

/** A process ID that no running process has. */
export function deadPid(): number {
  return spawnSync(process.execPath, ["-e", ""]).pid as number;
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
