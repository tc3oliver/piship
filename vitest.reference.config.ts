import { defineConfig } from "vitest/config";
import base from "./vitest.config.js";

// `npm run test:reference`: tests that run against the live enterprise
// reference stack (Keycloak, LiteLLM, PostgreSQL, the broker) started with
// Docker Compose. They need Docker, so `npm test` excludes them and the
// reference workflow runs them. One file at a time: each starts its own
// stack, and the stacks are slow to start.
export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: [
      "tests/enterprise-reference/**/*.test.ts",
      "examples/enterprise-reference/tests/**/*.test.ts",
    ],
    fileParallelism: false,
    globalSetup: [],
    testTimeout: 120_000,
    hookTimeout: 300_000,
  },
});
