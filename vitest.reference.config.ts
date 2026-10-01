import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { configDefaults, defineConfig } from "vitest/config";
import base from "./vitest.config.js";

// `npm run test:reference`: tests that run against the live enterprise
// reference stack (Keycloak, LiteLLM, PostgreSQL, the broker) started with
// Docker Compose. They need Docker, so `npm test` excludes them and the
// Reference E2E workflow (.github/workflows/reference-e2e.yml) runs them.
// One file at a time: each starts its own stack, and the stacks are slow to
// start.

const INCLUDE = [
  "tests/enterprise-reference/**/*.test.ts",
  "examples/enterprise-reference/tests/**/*.test.ts",
];

// The Reference E2E workflow runs one group per runner, each with a Docker of
// its own. Every stack publishes on ports Docker chooses, so two runs on one
// host do not meet either (concurrent-stacks.test.ts). The groups are
// balanced by the durations measured on ubuntu-latest, stack start and stop
// included (about 205 s each). A file no group names runs in the last group,
// so a new file is never left out.
const SHARDS: readonly (readonly string[])[] = [
  // 205 s
  ["tests/enterprise-reference/gateway-evidence.test.ts"],
  // 165 s and 30 s
  [
    "examples/enterprise-reference/tests/distribution-flow.test.ts",
    "examples/enterprise-reference/tests/sandbox.test.ts",
  ],
  // 110 s and 95 s
  [
    "examples/enterprise-reference/tests/user-switching.test.ts",
    "tests/enterprise-reference/usage-continuity.test.ts",
  ],
  // The rest: security-oidc, team-member-budget, gateway-rate-limits and
  // gateway-concurrency-entitlement, about 45 s each; live-provider skips
  // itself without its provider variables.
  [],
];

/**
 * The files of one group, from PISHIP_REFERENCE_SHARD=<index>/<count>
 * (index from 1, count the number of groups). Without it, every file.
 */
function shard(value: string | undefined) {
  if (!value) return { include: INCLUDE, exclude: [] };
  const match = /^(\d+)\/(\d+)$/.exec(value);
  const index = Number(match?.[1]);
  const count = Number(match?.[2]);
  if (count !== SHARDS.length || index < 1 || index > count)
    throw new Error(
      `PISHIP_REFERENCE_SHARD=${value}: expected <index>/${SHARDS.length}, one per group in vitest.reference.config.ts`,
    );
  const named = SHARDS.flat();
  for (const file of named) {
    if (!existsSync(fileURLToPath(new URL(file, import.meta.url))))
      throw new Error(
        `vitest.reference.config.ts names a missing file: ${file}`,
      );
    if (named.indexOf(file) !== named.lastIndexOf(file))
      throw new Error(`vitest.reference.config.ts names ${file} twice`);
  }
  return index === count
    ? { include: INCLUDE, exclude: named }
    : { include: [...(SHARDS[index - 1] ?? [])], exclude: [] };
}

const files = shard(process.env.PISHIP_REFERENCE_SHARD);

export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: files.include,
    exclude: [...configDefaults.exclude, ...files.exclude],
    fileParallelism: false,
    // Removes stacks and temporary directories a killed earlier run left.
    globalSetup: ["tests/enterprise-reference/global-setup.ts"],
    testTimeout: 120_000,
    hookTimeout: 300_000,
  },
});
