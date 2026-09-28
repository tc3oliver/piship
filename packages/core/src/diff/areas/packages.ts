import { byKey, type Collector, keys, origin } from "../collector.js";
import type { AnyLock } from "../types.js";

export function packages(out: Collector, b: AnyLock, a: AnyLock): void {
  const before = byKey(b.runtime?.packages, (item) => item.path);
  const after = byKey(a.runtime?.packages, (item) => item.path);
  for (const path of keys(before, after)) {
    const x = before.get(path);
    const y = after.get(path);
    if (!x && y) {
      out.push(
        "packages",
        "added",
        path,
        y.installScript
          ? ["high", "New dependency runs an install script."]
          : ["medium", "New runtime dependency."],
        undefined,
        y.version,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "packages",
        "removed",
        path,
        ["low", "Runtime dependency removed."],
        x.version,
      );
      continue;
    }
    if (!x || !y) continue;
    if (x.version !== y.version)
      out.push(
        "packages",
        "changed",
        path,
        ["medium", "Dependency version changed."],
        x.version,
        y.version,
      );
    else if (x.integrity !== y.integrity)
      out.push(
        "packages",
        "changed",
        `${path} integrity`,
        ["high", "Package content changed without a version change."],
        x.integrity,
        y.integrity,
      );
    const bo = origin(x.resolved);
    const ao = origin(y.resolved);
    if (bo !== undefined && ao !== undefined && bo !== ao)
      out.push(
        "packages",
        "changed",
        `${path} origin`,
        ["high", "Package now resolves from a different origin."],
        bo,
        ao,
      );
    if (y.installScript && !x.installScript)
      out.push(
        "packages",
        "changed",
        `${path} install script`,
        ["high", "Dependency now runs an install script."],
        "none",
        "install script",
      );
  }
}
