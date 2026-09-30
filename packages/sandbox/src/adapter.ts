// The OS sandbox adapter contract. An adapter turns a resolved profile and a
// command into a wrapped command; it never decides policy.
import { execFile } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";
import { redact } from "@piship/contracts";
import type { SandboxProfile } from "./profile.js";

export const SANDBOX_ADAPTER_IDS = [
  "linux-bubblewrap",
  "macos-seatbelt",
  "unsupported",
] as const;
export type SandboxAdapterId = (typeof SANDBOX_ADAPTER_IDS)[number];

/** A program to run inside the sandbox with exactly the environment given. */
export interface SandboxCommand {
  readonly file: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
}

/** What to spawn on the host so that `SandboxCommand` runs contained. */
export interface WrappedCommand {
  readonly file: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
}

export type AdapterAvailability =
  | { readonly available: true }
  | { readonly available: false; readonly reason: string };

export interface SandboxAdapter {
  readonly id: SandboxAdapterId;
  /**
   * Whether the mechanism keeps a protected file that does not exist yet from
   * being created (Seatbelt denies the path itself, so the file can never
   * appear). Bubblewrap cannot: it protects a path by mounting over it, and a
   * mount point for a missing file would be an empty file left on the host.
   * Omitted means it cannot; git control is then not verified while a
   * protected file is missing where the sandbox may write.
   */
  readonly guardsMissingFiles?: boolean;
  /** Checks that the mechanism works on this host (cached after the first call). */
  available(): Promise<AdapterAvailability>;
  /** Wrap a command. Only valid after `available()` resolved available. */
  wrap(profile: SandboxProfile, command: SandboxCommand): WrappedCommand;
}

/** Locate an executable on PATH without running a shell. */
export function findExecutable(
  name: string,
  path: string | undefined = process.env.PATH,
): string | undefined {
  for (const dir of (path ?? "").split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // not here
    }
  }
  return undefined;
}

export interface RunResult {
  readonly ok: boolean;
  readonly detail: string;
}

/** Run a short check command; the detail is redacted and bounded. */
export function runCheck(
  file: string,
  args: readonly string[],
  timeoutMs = 10_000,
): Promise<RunResult> {
  return new Promise((resolvePromise) => {
    execFile(
      file,
      [...args],
      { timeout: timeoutMs, env: { PATH: "/usr/bin:/bin" }, windowsHide: true },
      (error, _stdout, stderr) => {
        const text = String(stderr ?? "").trim() || (error?.message ?? "");
        resolvePromise({
          ok: !error,
          detail: redact(text.split("\n")[0] ?? "").slice(0, 300),
        });
      },
    );
  });
}
