// vitest.config.ts turns the compiled Windows Job Object helper off, so a
// governed child starts through PowerShell and an Add-Type compile, about
// 0.9 s each. A file that starts dozens of children calls this at load: on
// Windows it compiles the helper once, into a state home of its own, as a
// user's first command does. Both supervisors run the same Job Object code.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";

export function useCompiledJobHelper(): void {
  if (process.platform !== "win32") return;
  const state = mkdtempSync(join(tmpdir(), "piship-job-helper-"));
  process.env.PISHIP_STATE_HOME = state;
  process.env.PISHIP_WINDOWS_JOB_HELPER = "on";
  afterAll(() => rmSync(state, { recursive: true, force: true }));
}
