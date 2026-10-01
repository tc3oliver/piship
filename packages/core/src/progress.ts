// Low-noise progress for long lifecycle work (build, update, rollback): one
// line on stderr as each long step starts, and only for a person watching.

/**
 * A progress callback that writes `<step>...` with `write`, or `undefined`
 * when nobody is watching: stderr is not a terminal (a script, CI, or JSON
 * output). `PISHIP_PROGRESS=1` turns it on anyway (piship sets it when it
 * forwards to the installed release from a terminal), `PISHIP_PROGRESS=0`
 * turns it off.
 */
export function progressReporter(
  write: (message: string) => void,
  stream: { readonly isTTY?: boolean } = process.stderr,
  env: Readonly<Record<string, string | undefined>> = process.env,
): ((step: string) => void) | undefined {
  const setting = env.PISHIP_PROGRESS;
  if (setting === "0" || (setting !== "1" && !stream.isTTY)) return undefined;
  return (step) => write(`${step}...`);
}
