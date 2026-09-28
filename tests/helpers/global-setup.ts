import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestProject } from "vitest/node";

declare module "vitest" {
  export interface ProvidedContext {
    lifecycleFixtures: string;
  }
}

// Only reserves a per-run directory: each example distribution's lifecycle
// releases are built lazily, in a subdirectory of their own, by the first
// scenario that needs them (tests/helpers/lifecycle.ts), so runs without
// lifecycle scenarios pay nothing.
export default function setup(project: TestProject) {
  const directory = mkdtempSync(join(tmpdir(), "piship-lifecycle-fixtures-"));
  project.provide("lifecycleFixtures", directory);
  return () => rmSync(directory, { recursive: true, force: true });
}
