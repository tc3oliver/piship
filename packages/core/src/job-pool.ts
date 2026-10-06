// A small pool for file system work that is bound by per-operation latency
// (create, write, close, and on Windows the scanner's work at each close).
// Waiting for a free slot gives the caller backpressure, so buffered data stays
// bounded.

/** Runs jobs with at most `limit` in flight; the first failure stops the rest. */
export class JobPool {
  private readonly running = new Set<Promise<void>>();
  private failed: { readonly error: unknown } | undefined;

  constructor(private readonly limit: number) {}

  /** Start `job` once a slot is free; throws the first failure of an earlier job. */
  async run(job: () => Promise<void>): Promise<void> {
    while (this.running.size >= this.limit && this.failed === undefined)
      await Promise.race(this.running);
    if (this.failed !== undefined) throw this.failed.error;
    const done: Promise<void> = job()
      .catch((error: unknown) => {
        this.failed ??= { error };
      })
      .then(() => {
        this.running.delete(done);
      });
    this.running.add(done);
  }

  /** Wait for every started job, then throw the first failure, if any. */
  async finish(): Promise<void> {
    await this.drain();
    if (this.failed !== undefined) throw this.failed.error;
  }

  /** Wait for every started job without throwing, so cleanup cannot race a writer. */
  async drain(): Promise<void> {
    while (this.running.size > 0) await Promise.race(this.running);
  }
}
