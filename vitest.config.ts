import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    env: {
      PISHIP_BUILD_INPUT: fileURLToPath(
        new URL("./packages/core/dist/build-input/", import.meta.url),
      ),
    },
    include: ["packages/**/*.test.ts", "tests/**/*.test.ts"],
    testTimeout: 15_000,
    fileParallelism: false,
  },
});
