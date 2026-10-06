// Helpers shared by the release modules.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { PiShipError } from "@piship/contracts";
import type { CommandResult } from "./metadata.js";

export function hash(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

export function gate(
  code: ConstructorParameters<typeof PiShipError>[0],
  gateName: string,
  message: string,
  userAction?: string,
  stage: "Release" | "Build" = "Release",
): PiShipError {
  return new PiShipError(code, `${stage} gate ${gateName}: ${message}`, {
    component: stage === "Release" ? "release" : "build",
    sanitizedDetail: { gate: gateName },
    ...(userAction ? { userAction } : {}),
  });
}

export function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

/**
 * Runs a command to completion without blocking the process, so independent
 * commands can run side by side. Never rejects: a command that cannot start,
 * times out, or fails is a result with the exit code, or `null` when it has
 * none, as for `spawnSync`.
 */
export function runCommand(
  file: string,
  args: readonly string[],
  options: {
    readonly cwd: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly timeout?: number;
    readonly maxBuffer?: number;
  },
): Promise<CommandResult> {
  return new Promise((done) => {
    const child = execFile(
      file,
      [...args],
      { encoding: "utf8", ...options },
      (error, stdout, stderr) =>
        done({
          status: error
            ? typeof error.code === "number"
              ? error.code
              : null
            : 0,
          stdout,
          stderr: stderr || error?.message || "",
        }),
    );
    // Like spawnSync, give the command an empty, closed standard input.
    child.stdin?.on("error", () => {});
    child.stdin?.end();
  });
}

export type Outcome<T> = { readonly value: T } | { readonly error: unknown };

/** A promise's outcome as a value. It never rejects, so it may run unwatched. */
export function outcome<T>(work: Promise<T>): Promise<Outcome<T>> {
  return work.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
}

/** The value of an outcome, or its error thrown. */
export function unwrap<T>(result: Outcome<T>): T {
  if ("error" in result) throw result.error;
  return result.value;
}
