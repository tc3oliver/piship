import { SEARCH_TOOLS } from "@piship/schema";
import type { Collector } from "../collector.js";
import type { AnyLock, Verdict } from "../types.js";

/**
 * v1alpha6 `searchTools`: executables shipped in the payload. A new tool, a
 * new source, or different bytes at the same version are high risk; a
 * version change of a tool from the same upstream is medium, like a runtime
 * dependency's.
 */
export function searchTools(out: Collector, b: AnyLock, a: AnyLock): void {
  for (const tool of SEARCH_TOOLS) {
    const x = b.searchTools?.[tool];
    const y = a.searchTools?.[tool];
    const item = `search tool ${tool}`;
    if (!x && y) {
      out.push(
        "packages",
        "added",
        item,
        ["high", "Bundles a new executable that Pi runs for find and grep."],
        undefined,
        y.version,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "packages",
        "removed",
        item,
        ["low", "Bundled executable removed; Pi uses one on PATH, if any."],
        x.version,
      );
      continue;
    }
    if (!x || !y) continue;
    out.scalar("packages", `${item} source`, x.source, y.source, [
      "high",
      "Bundled executable now comes from a different upstream.",
    ]);
    out.scalar("packages", `${item} version`, x.version, y.version, [
      "medium",
      "Bundled executable version changed.",
    ]);
    out.set(
      "packages",
      `${item} target`,
      Object.keys(x.targets),
      Object.keys(y.targets),
      ["medium", "Bundled executable added for a release target."],
      ["low", "Bundled executable removed for a release target."],
    );
    if (x.version !== y.version) continue;
    const content: Verdict = [
      "high",
      "Bundled executable content changed without a version change.",
    ];
    for (const [target, before] of Object.entries(x.targets)) {
      const after = y.targets[target];
      if (!after) continue;
      out.scalar(
        "packages",
        `${item} ${target} archive`,
        before.archive,
        after.archive,
        content,
      );
      out.scalar(
        "packages",
        `${item} ${target} binary`,
        before.binary,
        after.binary,
        content,
      );
    }
  }
}
