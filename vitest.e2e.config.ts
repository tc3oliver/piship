import { availableParallelism } from "node:os";
import { defineConfig } from "vitest/config";
import base from "./vitest.config.js";

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
    globalSetup: ["tests/helpers/e2e-global-setup.ts"],
  },
});
