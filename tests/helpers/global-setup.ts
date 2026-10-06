import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestProject } from "vitest/node";
import { testStoreHome } from "./test-store.js";

declare module "vitest" {
  export interface ProvidedContext {
    lifecycleFixtures: string;
  }
}

// Only reserves a per-run directory: each example distribution's lifecycle
// releases are built lazily, in a subdirectory of their own, by the first
// scenario that needs them (tests/helpers/lifecycle.ts), so runs without
// lifecycle scenarios pay nothing. The name is short for the same reason as
// the subdirectories' (`Distribution.fixture`): Windows path length.
export default function setup(project: TestProject) {
  const directory = mkdtempSync(join(tmpdir(), "piship-e2e-"));
  project.provide("lifecycleFixtures", directory);
  return () => {
    rmSync(testStoreHome, { recursive: true, force: true });
    rmSync(directory, { recursive: true, force: true });
  };
}
