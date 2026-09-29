// Pi ends an interactive session (Ctrl+D, `/quit`, SIGTERM, SIGHUP) in
// `InteractiveMode.shutdown()`: it awaits `runtimeHost.dispose()` and then
// calls `process.exit(0)`. Nothing PiShip runs after `InteractiveMode.run()`
// is reached, so the end of the governance session has to happen inside that
// `dispose()`. `compatibility.test.ts` pins the await-then-exit order.

/** The exit function whose code a failed teardown must not lose. */
interface ExitingProcess {
  exit: (code?: number) => never;
}

/**
 * Make `runtime.dispose()` run `run` once, and return the same once-only
 * function for the caller's own `finally`. A failure is reported, and the
 * process exit code becomes 1 even though Pi will pass 0: replacing `exit` is
 * the only way to change a code Pi has already decided, and the process is
 * ending anyway.
 */
export function endInsideDispose(
  runtime: { dispose(): Promise<void> },
  run: (sessionFailed: boolean) => Promise<void>,
  report: (error: unknown) => void,
  proc: ExitingProcess = process,
): (sessionFailed: boolean) => Promise<void> {
  let ending: Promise<void> | undefined;
  const end = (sessionFailed: boolean): Promise<void> => {
    ending ??= run(sessionFailed);
    return ending;
  };
  runtime.dispose = async () => {
    try {
      await end(false);
    } catch (error) {
      report(error);
      const exit = proc.exit.bind(proc);
      proc.exit = ((code?: number) => exit(code ? code : 1)) as never;
    }
  };
  return end;
}
