import type { TestProject } from "vitest/node";
import {
  e2eFileKey,
  e2eFixtures,
  e2eShard,
  type LifecycleFixture,
} from "./e2e-shards.js";
import reserveFixtures from "./global-setup.js";
import { prebuildLifecycleFixtures } from "./lifecycle.js";

// The full E2E run builds the lifecycle release fixtures up front: built
// lazily, they ran alongside the heaviest scenario files and stretched those
// files past their timeouts on runners with few cores.
export default async function setup(project: TestProject) {
  const cleanup = reserveFixtures(project);
  try {
    await prebuildLifecycleFixtures(
      project.getProvidedContext().lifecycleFixtures,
      await shardFixtures(project),
    );
  } catch (error) {
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
 * With `--shard`, only the fixtures that this shard's files use: the same
 * split the sequencer makes (vitest.e2e.config.ts), over every E2E file.
 * Without it, every fixture.
 */
async function shardFixtures(
  project: TestProject,
): Promise<ReadonlySet<LifecycleFixture> | undefined> {
  const shard = project.vitest.config.shard;
  if (!shard) return undefined;
  const { testFiles } = await project.globTestFiles();
  const files = e2eShard(testFiles, shard.index, shard.count);
  const fixtures = e2eFixtures(files);
  console.info(
    `E2E shard ${shard.index}/${shard.count}: ${files.map(e2eFileKey).join(", ")}; fixtures: ${[...fixtures].join(", ") || "none"}`,
  );
  return fixtures;
}
