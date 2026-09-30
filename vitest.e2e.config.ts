import { availableParallelism } from "node:os";
import { defineConfig } from "vitest/config";
import { BaseSequencer, type TestSpecification } from "vitest/node";
import { byKey, e2eSeconds, e2eShard } from "./tests/helpers/e2e-shards.js";
import base from "./vitest.config.js";

/**
 * Starts the longest files first, so none is left to run alone at the end,
 * and with `--shard` splits the files by measured duration and fixtures
 * (tests/helpers/e2e-shards.ts) instead of by count.
 */
class E2ESequencer extends BaseSequencer {
  override async shard(specs: TestSpecification[]) {
    const { index, count } = this.ctx.config.shard ?? { index: 1, count: 1 };
    const mine = new Set(
      e2eShard(
        specs.map((spec) => spec.moduleId),
        index,
        count,
      ),
    );
    return specs.filter((spec) => mine.has(spec.moduleId));
  }

  override async sort(specs: TestSpecification[]) {
    return [...specs].sort(
      (a, b) =>
        e2eSeconds(b.moduleId) - e2eSeconds(a.moduleId) ||
        byKey(a.moduleId, b.moduleId),
    );
  }
}

// `npm run test:e2e`: every E2E file works in its own temporary homes, so
// files run in parallel, but no more at once than the machine has cores.
// Each file spawns builds and installs that are CPU-bound; oversubscribing a
// 3-core runner made every file's wall time depend on its neighbours.
export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: ["tests/e2e/**/*.test.ts"],
    fileParallelism: true,
    maxWorkers: availableParallelism(),
    sequence: { sequencer: E2ESequencer },
    globalSetup: ["tests/helpers/e2e-global-setup.ts"],
    // Teardown stops fixture servers and deletes install homes of several
    // hundred MB; on a slow runner that alone can pass the 10 s default.
    hookTimeout: 60_000,
  },
});
