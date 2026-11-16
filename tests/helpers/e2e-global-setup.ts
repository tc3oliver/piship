import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { TestProject } from "vitest/node";
import {
  e2eFileKey,
  e2eShard,
  type LifecycleFixture,
  prebuildFixtures,
} from "./e2e-shards.js";
import reserveFixtures from "./global-setup.js";
import { prebuildLifecycleFixtures } from "./lifecycle.js";

// The full E2E run builds the lifecycle release fixtures up front: built
// lazily, they ran alongside the heaviest scenario files and stretched those
// files past their timeouts on runners with few cores.
export default async function setup(project: TestProject) {
  // Every E2E file runs the built CLI; without it each fixture build fails
  // with a bare MODULE_NOT_FOUND stack.
  const cli = fileURLToPath(
    new URL("../../packages/cli/dist/bin.js", import.meta.url),
  );
  if (!existsSync(cli))
    throw new Error(
      `${cli} is missing: run npm run build first. The E2E tier runs the built CLI, so rebuild after every source change.`,
    );
  const cleanup = reserveFixtures(project);
  try {
    await prebuildLifecycleFixtures(
      project.getProvidedContext().lifecycleFixtures,
      await selectedFixtures(project),
    );
  } catch (error) {
    // Vitest 4 reports a failed global setup as "No test files found" and
    // drops the error, so the cause is printed (and annotated in CI) first.
    const message = error instanceof Error ? error.message : String(error);
    console.error(`E2E global setup failed: ${message}`);
    if (process.env.GITHUB_ACTIONS)
      console.error(
        `::error title=E2E global setup failed::${message
          .replace(/%/g, "%25")
          .replace(/\r/g, "%0D")
          .replace(/\n/g, "%0A")}`,
      );
    // The build that failed is what has to be reported. A fixture directory a
    // process still holds (Windows cannot remove one) must not replace it.
    try {
      cleanup();
    } catch {
      // Left in the temp directory.
    }
    throw error;
  }
  return cleanup;
}

/**
 * The fixtures of the files this run selected: those a filename filter
 * matched (`npm run test:e2e -- tests/e2e/cli.test.ts`), split as the
 * sequencer splits them with `--shard` (vitest.e2e.config.ts). Undefined,
 * every fixture, for a full run.
 */
async function selectedFixtures(
  project: TestProject,
): Promise<ReadonlySet<LifecycleFixture> | undefined> {
  const shard = project.vitest.config.shard;
  // The CLI's filename filters; Vitest keeps them on the instance but does
  // not type them as public.
  const filters = (project.vitest as unknown as { filenamePattern?: string[] })
    .filenamePattern;
  const all = (await project.globTestFiles()).testFiles;
  const selected = filters?.length
    ? (await project.globTestFiles(filters)).testFiles
    : undefined;
  const fixtures = prebuildFixtures(all, selected, shard);
  const files = shard
    ? e2eShard(selected ?? all, shard.index, shard.count)
    : selected;
  console.info(
    `E2E ${shard ? `shard ${shard.index}/${shard.count}` : files ? "files" : "full run"}: ${files ? files.map(e2eFileKey).join(", ") : `${all.length} files`}; fixtures: ${fixtures ? [...fixtures].join(", ") || "none" : "all"}`,
  );
  return fixtures;
}
