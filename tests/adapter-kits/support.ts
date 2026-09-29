// Shared plumbing for the kit self-tests: load an SDK example the way a
// distribution payload holds it, and collect every report for the evidence
// file (`PISHIP_KIT_REPORT=<path>` writes it as JSON).
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { ConformanceReport } from "@piship/adapter-conformance";

const SDK_DIR = fileURLToPath(
  new URL("../../packages/adapter-sdk/", import.meta.url),
);

/**
 * A payload-shaped directory for the examples: the adapter files, and the
 * SDK in `node_modules/`, the only place their bare import resolves from.
 */
export function examplesPayload(): {
  load<T>(name: string, replace?: readonly [RegExp, string][]): Promise<T>;
  close(): void;
} {
  const root = mkdtempSync(join(tmpdir(), "piship-kit-examples-"));
  mkdirSync(join(root, "node_modules", "@piship"), { recursive: true });
  symlinkSync(
    SDK_DIR,
    join(root, "node_modules", "@piship", "adapter-sdk"),
    process.platform === "win32" ? "junction" : "dir",
  );
  let copies = 0;
  return {
    async load<T>(name: string, replace: readonly [RegExp, string][] = []) {
      // A new file name per load: the module cache would return the first.
      const target = join(root, `${++copies}-${name}`);
      const source = join(SDK_DIR, "examples", name);
      if (replace.length === 0) copyFileSync(source, target);
      else {
        let text = readFileSync(source, "utf8");
        for (const [pattern, value] of replace) {
          if (!pattern.test(text))
            throw new Error(`${name} no longer contains ${pattern}`);
          text = text.replace(pattern, value);
        }
        writeFileSync(target, text);
      }
      const module = (await import(pathToFileURL(target).href)) as {
        default: T;
      };
      return module.default;
    },
    close: () => rmSync(root, { recursive: true, force: true }),
  };
}

const reports: Record<string, ConformanceReport> = {};

/** Keep `report` for the evidence file under `implementation`. */
export function record(
  implementation: string,
  report: ConformanceReport,
): ConformanceReport {
  reports[implementation] = report;
  return report;
}

/** Write every recorded report when `PISHIP_KIT_REPORT` names a file. */
export function writeReports(): void {
  const path = process.env.PISHIP_KIT_REPORT;
  if (!path) return;
  let previous: Record<string, ConformanceReport> = {};
  try {
    previous = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    // a new file
  }
  writeFileSync(
    path,
    `${JSON.stringify({ ...previous, ...reports }, null, 2)}\n`,
  );
}

export const statuses = (report: ConformanceReport) =>
  Object.fromEntries(
    report.results.map((result) => [result.behavior, result.status]),
  );

export const reasons = (report: ConformanceReport) =>
  Object.fromEntries(
    report.results
      .filter((result) => result.reason)
      .map((result) => [result.behavior, result.reason]),
  );
