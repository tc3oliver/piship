// Stage timing behind PISHIP_DEBUG_TIMING=1. A stage prints as `label: N ms`.
// A stage timer, used where stages overlap, prints them longest first when it
// reports and ends with one JSON line on stderr (`piship-timing/v1`), so a
// profile can be read by a person or by a script.

export const TIMING_SCHEMA = "piship-timing/v1";

export function timingEnabled(): boolean {
  return process.env.PISHIP_DEBUG_TIMING === "1";
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
