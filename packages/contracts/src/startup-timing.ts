// Startup phase timing, on only with PISHIP_DEBUG_TIMING=1. A launch crosses
// several module copies (the installed launcher, the payload launcher, and a
// bundled runtime that holds its own copy of this one), so the marks live in
// one shared store on `globalThis`; the launcher writes to the same store
// before any payload code has loaded. Times are milliseconds since the
// process started (`performance.now()`, whose origin is the process start).
// With the variable unset every function returns at its first line and
// nothing is allocated.
import { writeSync } from "node:fs";

const STORE = Symbol.for("piship.startup-timing");
/** Whether this process reports startup timing. */
export const startupTimingEnabled = process.env.PISHIP_DEBUG_TIMING === "1";
const enabled = startupTimingEnabled;

interface Store {
  readonly marks: { name: string; ms: number }[];
  readonly counters: Record<string, number>;
  readonly notes: Record<string, string>;
  reporting?: boolean;
}

function store(): Store {
  const holder = globalThis as unknown as Record<symbol, Store | undefined>;
  const shared = holder[STORE] ?? { marks: [], counters: {}, notes: {} };
  holder[STORE] = shared;
  if (!shared.reporting) {
    shared.reporting = true;
    process.on("exit", () => report(shared));
  }
  return shared;
}

/** Record that a named phase of startup was reached. */
export function startupMark(name: string): void {
  if (!enabled) return;
  store().marks.push({ name, ms: performance.now() });
}

/** Count an event that costs real time at startup, such as a process spawn. */
export function startupCount(name: string): void {
  if (!enabled) return;
  const counters = store().counters;
  counters[name] = (counters[name] ?? 0) + 1;
}

/** Record a fact that identifies what ran, such as a launcher build. */
export function startupNote(name: string, value: string): void {
  if (!enabled) return;
  store().notes[name] = value;
}

const round = (ms: number) => Math.round(ms * 10) / 10;

/**
 * One JSON line, then a readable summary, on stderr. Written synchronously
 * at exit, after Pi's terminal UI has restored the screen. `writeSync` also
 * works while Pi is calling `process.exit`.
 */
function report(shared: Store): void {
  const marks = [
    ...shared.marks,
    { name: "process_exit", ms: performance.now() },
  ].map(({ name, ms }) => ({ name, ms: round(ms) }));
  const json = {
    schema: "piship-startup-timing/v1",
    platform: `${process.platform}-${process.arch}`,
    node: process.versions.node,
    notes: shared.notes,
    counters: shared.counters,
    marks,
  };
  const lines = [`PISHIP_TIMING_JSON ${JSON.stringify(json)}`];
  let previous = 0;
  for (const { name, ms } of marks) {
    lines.push(
      `PISHIP_TIMING ${name.padEnd(28)} ${ms.toFixed(1).padStart(8)} ms  (+${round(ms - previous).toFixed(1)})`,
    );
    previous = ms;
  }
  for (const [name, value] of Object.entries(shared.notes))
    lines.push(`PISHIP_TIMING ${name} = ${value}`);
  for (const [name, count] of Object.entries(shared.counters))
    lines.push(`PISHIP_TIMING ${name} = ${count}`);
  try {
    writeSync(2, `${lines.join("\n")}\n`);
  } catch {
    // stderr is closed: the report is best effort.
  }
}
