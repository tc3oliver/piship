import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@piship/schema": fileURLToPath(
        new URL("./packages/schema/src/index.ts", import.meta.url),
      ),
    },
  },
  test: {
    env: {
      PISHIP_BUILD_INPUT: fileURLToPath(new URL("./", import.meta.url)),
    },
    include: ["packages/**/*.test.ts", "tests/**/*.test.ts"],
    testTimeout: 15_000,
    globalSetup: ["tests/helpers/global-setup.ts"],
    // Unit tests run one file at a time; `npm run test:e2e` turns file
    // parallelism on, since every E2E file works in its own temporary homes.
    fileParallelism: false,
  },
});
