import { availableParallelism } from "node:os";
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { testStoreHome } from "./tests/helpers/test-store.js";

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
      // Installs in a test fill a store of this run, not the user's.
      PISHIP_STORE_HOME: testStoreHome,
      // `piship init` bundles fd and rg when GitHub answers, and the `lock`
      // that follows then downloads them from GitHub. A test never uses the
      // network, so `init` leaves them out (the probe itself is tested
      // against local servers, and the test of the bundled template asks for
      // them explicitly).
      PISHIP_INIT_PROBE: "unreachable",
    },
    include: ["packages/**/*.test.ts", "tests/**/*.test.ts"],
    testTimeout: 15_000,
    globalSetup: ["tests/helpers/global-setup.ts"],
    // Files run in parallel. Each file runs in a process of its own (the
    // default `forks` pool), so the environment variables and working
    // directory a test changes stay in its file. Every file works in
    // temporary directories of its own and binds only ephemeral loopback
    // ports, and none uses the real secret store (platform-store.test.ts does
    // only under PISHIP_LIVE_SECRET_STORE, which CI sets for a run of that
    // file alone). At most four files at once, and no more than the machine
    // has cores: the CI runners have three or four, and with more the install
    // and archive tests slow toward the test timeout.
    fileParallelism: true,
    maxWorkers: Math.min(availableParallelism(), 4),
  },
});
