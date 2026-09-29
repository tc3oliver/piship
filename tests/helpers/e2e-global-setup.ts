import type { TestProject } from "vitest/node";
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
    );
  } catch (error) {
    cleanup();
    throw error;
  }
  return cleanup;
}
