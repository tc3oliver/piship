// Timing behind PISHIP_DEBUG_TIMING=1, in one place: a stage prints as
// `label: N ms`; a stage timer, used where stages overlap, prints them longest
// first when it reports; the startup marks of a launch print in the order they
// were reached. Each ends with one JSON line on stderr (`piship-timing/v1`),
// so a profile can be read by a person or by a script.
import { writeSync } from "node:fs";

export const TIMING_SCHEMA = "piship-timing/v1";

export function timingEnabled(): boolean {
  return process.env.PISHIP_DEBUG_TIMING === "1";
}

/** A phase marker: each call reports the time since the previous one. */
export function stopwatch(): (label: string) => void {
  let last = process.hrtime.bigint();
  return (label) => {
    debugTiming(label, last);
    last = process.hrtime.bigint();
  };
}

export function debugTiming(label: string, started: bigint): void {
  if (timingEnabled())
    process.stderr.write(
      `${label}: ${(Number(process.hrtime.bigint() - started) / 1e6).toFixed(1)} ms\n`,
    );
}

interface Stage {
  readonly name: string;
  readonly startMs: number;
  ms?: number;
}

export interface StageTimer {
  /** Starts a stage; the returned function ends it. */
  readonly start: (name: string) => () => void;
  /** Runs `work` as a stage, ended whether it returns, throws, or rejects. */
  readonly run: <T>(name: string, work: () => T | Promise<T>) => Promise<T>;
  /**
   * Prints the stages longest first, then the JSON summary. A stage still
   * open (its work threw past `start`) is reported up to now, marked
   * `unfinished`. Stages that overlap are each counted in full, so their sum
   * can exceed `totalMs`.
   */
  readonly report: (command: string) => void;
}

const round = (ms: number): number => Math.round(ms * 10) / 10;

export function createStageTimer(): StageTimer {
  const origin = performance.now();
  const stages: Stage[] = [];
  const start = (name: string): (() => void) => {
    const stage: Stage = { name, startMs: performance.now() - origin };
    stages.push(stage);
    return () => {
      stage.ms ??= performance.now() - origin - stage.startMs;
    };
  };
  return {
    start,
    async run(name, work) {
      const end = start(name);
      try {
        return await work();
      } finally {
        end();
      }
    },
    report(command) {
      if (!timingEnabled()) return;
      const totalMs = performance.now() - origin;
      const listed = stages
        .map((stage) => ({
          name: stage.name,
          startMs: round(stage.startMs),
          ms: round(stage.ms ?? totalMs - stage.startMs),
          ...(stage.ms === undefined ? { unfinished: true as const } : {}),
        }))
        .sort((a, b) => b.ms - a.ms || a.startMs - b.startMs);
      for (const stage of listed)
        process.stderr.write(
          `${command} ${stage.name}: ${stage.ms.toFixed(1)} ms\n`,
        );
      process.stderr.write(
        `${JSON.stringify({ schema: TIMING_SCHEMA, command, totalMs: round(totalMs), stages: listed })}\n`,
      );
    },
  };
}

// Startup marks. A launch crosses several module copies (the installed
// launcher, the payload launcher, and a bundled runtime that holds its own
// copy of this one), so the marks live in one shared store on `globalThis`;
// the launchers write to the same store before any payload code has loaded
// (`LAUNCHER_TIMING_SNIPPET` in @piship/core). Times are milliseconds since
// the process started (`performance.now()`, whose origin is the process
// start). With the variable unset every function returns at its first line
// and nothing is allocated.
const STORE = Symbol.for("piship.startup-timing");
/** Whether this process reports startup timing. */
export const startupTimingEnabled = timingEnabled();

interface StartupStore {
  readonly marks: { name: string; ms: number }[];
  readonly counters: Record<string, number>;
  readonly notes: Record<string, string>;
  reporting?: boolean;
}

function startupStore(): StartupStore {
  const holder = globalThis as unknown as Record<
    symbol,
    StartupStore | undefined
  >;
  const shared = holder[STORE] ?? { marks: [], counters: {}, notes: {} };
  holder[STORE] = shared;
  if (!shared.reporting) {
    shared.reporting = true;
    process.on("exit", () => reportStartup(shared));
  }
  return shared;
}

/** Record that a named phase of startup was reached. */
export function startupMark(name: string): void {
  if (!startupTimingEnabled) return;
  startupStore().marks.push({ name, ms: performance.now() });
}

/** Count an event that costs real time at startup, such as a process spawn. */
export function startupCount(name: string): void {
  if (!startupTimingEnabled) return;
  const counters = startupStore().counters;
  counters[name] = (counters[name] ?? 0) + 1;
}

/** Record a fact that identifies what ran, such as a launcher build. */
export function startupNote(name: string, value: string): void {
  if (!startupTimingEnabled) return;
  startupStore().notes[name] = value;
}

/**
 * The marks as a `piship-timing/v1` summary with command `launch`: each
 * stage is the phase that ended at its mark, so the stages add up to the
 * total, and the marks themselves (milliseconds since the process started),
 * counters and notes ride along. The readable lines come first, in the order
 * the marks were reached; written synchronously at exit, after Pi's terminal
 * UI has restored the screen. `writeSync` also works while Pi is calling
 * `process.exit`.
 */
function reportStartup(shared: StartupStore): void {
  const marks = [
    ...shared.marks,
    { name: "process_exit", ms: performance.now() },
  ].map(({ name, ms }) => ({ name, ms: round(ms) }));
  let previous = 0;
  const stages = marks.map(({ name, ms }) => {
    const stage = { name, startMs: previous, ms: round(ms - previous) };
    previous = ms;
    return stage;
  });
  const lines = stages.map(
    (stage) => `launch ${stage.name}: ${stage.ms.toFixed(1)} ms`,
  );
  lines.push(
    JSON.stringify({
      schema: TIMING_SCHEMA,
      command: "launch",
      totalMs: previous,
      stages,
      marks,
      counters: shared.counters,
      notes: {
        platform: `${process.platform}-${process.arch}`,
        node: process.versions.node,
        ...shared.notes,
      },
    }),
  );
  try {
    writeSync(2, `${lines.join("\n")}\n`);
  } catch {
    // stderr is closed: the report is best effort.
  }
}
