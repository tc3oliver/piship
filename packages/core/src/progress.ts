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

/**
 * Show `step` through `progress`, or, with nobody watching, as one plain
 * stderr line anyway: for a wait on the network that can last minutes and
 * otherwise looks like a hang. stdout stays clean for JSON output;
 * `PISHIP_PROGRESS=0` silences it.
 */
export function announceWait(
  step: string,
  progress: ((step: string) => void) | undefined,
  env: Readonly<Record<string, string | undefined>> = process.env,
): void {
  if (progress) progress(step);
  else if (env.PISHIP_PROGRESS !== "0") process.stderr.write(`${step}...\n`);
}
