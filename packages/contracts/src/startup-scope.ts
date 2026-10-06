// Path resolution while a session is being set up. Building the sandbox
// profile, the project's git protection and the policy engine resolves the
// same directories again and again (a hundred and more `realpath` calls on a
// start, two thirds of them for a path already resolved), and on Windows a
// resolution is one of the slowest file system calls there is. Within
// `duringStartup` the answer for a path is remembered; outside it, a session
// that is running resolves each path afresh at each call, as it always did,
// since a symlink changed under a running session must change what its
// policy decides.

let memo: Map<string, unknown> | undefined;

/**
 * Runs `work` with the startup memo on: `startupMemo` calls made while it
 * runs (also after an `await`) share one memo, which is dropped when it ends.
 * A nested call joins the outer one.
 */
export async function duringStartup<T>(work: () => Promise<T>): Promise<T> {
  if (memo) return work();
  memo = new Map();
  try {
    return await work();
  } finally {
    memo = undefined;
  }
}

/** Whether `duringStartup` is running. */
export function inStartup(): boolean {
  return memo !== undefined;
}

/**
 * The value `compute` gives, computed once per `kind` and `key` while
 * `duringStartup` runs and every time otherwise. A `compute` that throws is
 * not remembered.
 */
export function startupMemo<T>(kind: string, key: string, compute: () => T): T {
  if (!memo) return compute();
  const id = `${kind}\0${key}`;
  if (memo.has(id)) return memo.get(id) as T;
  const value = compute();
  memo.set(id, value);
  return value;
}
