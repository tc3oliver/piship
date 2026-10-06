// A child process run beside this thread's own work, from a synchronous
// function. The process is started by a worker thread, which waits for it with
// `spawnSync`, and this thread waits for the worker with `Atomics.wait` when it
// is ready for the result: no event loop is needed, and the caller gets the
// outcome as a return value.
import { startWorker } from "./parallel-files.js";

/** Slots of the shared state: finished, exit status. */
const DONE = 0;
const STATUS = 1;
const LENGTH = 2;
/** Set by the worker as its first act, so a worker that cannot run is noticed. */
const STARTED = 3;
const START_LIMIT_MS = 60_000;
/** The tail of the process's error output a failure reports. */
const OUTPUT_BYTES = 64 * 1024;
/** A hung process must not hang a build for ever. */
const WAIT_LIMIT_MS = 60 * 60_000;

const WORKER = `
const { workerData } = require("node:worker_threads");
const state = new Int32Array(workerData.state);
const output = new Uint8Array(workerData.output);
Atomics.add(state, ${STARTED}, 1);
let text = "";
let status = -1;
try {
  const { spawnSync } = require("node:child_process");
  const result = spawnSync(workerData.command, workerData.args, {
    cwd: workerData.cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  status = result.status === null ? -1 : result.status;
  text = String(result.stderr || (result.error && result.error.message) || result.stdout || "");
} catch (error) {
  text = String(error && error.message ? error.message : error);
} finally {
  const bytes = new TextEncoder().encode(text);
  const tail = bytes.subarray(Math.max(0, bytes.length - output.length));
  output.set(tail);
  Atomics.store(state, ${STATUS}, status);
  Atomics.store(state, ${LENGTH}, tail.length);
  Atomics.store(state, ${DONE}, 1);
  Atomics.notify(state, ${DONE});
}
`;

export interface BackgroundProcess {
  /** Wait for the process to end. The exit status is 0 on success, and its error output. */
  readonly wait: () => { readonly status: number; readonly output: string };
}

/** Start `command` with `args` in `cwd`, and return at once. */
export function startBackgroundProcess(
  command: string,
  args: readonly string[],
  cwd: string,
): BackgroundProcess {
  const stateBuffer = new SharedArrayBuffer(8 * 4);
  const outputBuffer = new SharedArrayBuffer(OUTPUT_BYTES);
  const state = new Int32Array(stateBuffer);
  const worker = startWorker(WORKER, {
    command,
    args,
    cwd,
    state: stateBuffer,
    output: outputBuffer,
  });
  let result: { status: number; output: string } | undefined;
  return {
    wait() {
      if (result) return result;
      const startedBy = Date.now() + START_LIMIT_MS;
      const deadline = Date.now() + WAIT_LIMIT_MS;
      while (Atomics.load(state, DONE) === 0) {
        if (Atomics.load(state, STARTED) === 0 && Date.now() > startedBy)
          throw new Error(`The thread that runs ${command} did not start`);
        if (Date.now() > deadline)
          throw new Error(`${command} did not finish within an hour`);
        Atomics.wait(state, DONE, 0, 1000);
      }
      void worker.terminate();
      result = {
        status: Atomics.load(state, STATUS),
        output: new TextDecoder().decode(
          new Uint8Array(outputBuffer).slice(0, Atomics.load(state, LENGTH)),
        ),
      };
      return result;
    },
  };
}
