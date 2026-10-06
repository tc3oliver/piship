// Node runs file system calls on a pool of four threads by default. Install
// and update are bound by how many file operations are in flight (on Windows
// each create or close waits on a scanner), so there the pool is made larger.
// libuv reads the size when the pool first runs, so this only works before the
// first asynchronous file system call, which is why install and update call it
// as their first step.

/** The pool size install and update ask for on Windows. */
export const INSTALL_THREADPOOL_SIZE = 16;

/**
 * On Windows, set `UV_THREADPOOL_SIZE` for this process unless the user
 * already chose a value. Returns whether it was set. A no-op elsewhere.
 */
export function raiseThreadpool(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== "win32" || env.UV_THREADPOOL_SIZE !== undefined)
    return false;
  env.UV_THREADPOOL_SIZE = String(INSTALL_THREADPOOL_SIZE);
  return true;
}
