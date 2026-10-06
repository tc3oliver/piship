import type { GovernanceManifest } from "@piship/schema";
import { byKey, type Collector, compare, keys } from "../collector.js";

export function capabilities(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const before = byKey(b.capabilities, (item) => item.name);
  const after = byKey(a.capabilities, (item) => item.name);
  for (const name of keys(before, after)) {
    const x = before.get(name);
    const y = after.get(name);
    const item = `capability ${name}`;
    const xe = x?.enabled ?? false;
    const ye = y?.enabled ?? false;
    if (xe !== ye)
      out.push(
        "capabilities",
        "changed",
        item,
        !ye && name === "permissions"
          ? ["high", "Disables permission enforcement."]
          : ["medium", ye ? "Enables a capability." : "Disables a capability."],
        xe ? "enabled" : "disabled",
        ye ? "enabled" : "disabled",
      );
    const bs = x?.settings ?? {};
    const as = y?.settings ?? {};
    for (const key of [
      ...new Set([...Object.keys(bs), ...Object.keys(as)]),
    ].sort(compare))
      if (bs[key] !== as[key])
        out.push(
          "capabilities",
          key in bs ? (key in as ? "changed" : "removed") : "added",
          `${item} setting ${key}`,
          key === "autoApproveFile" || key === "autoApproveKey"
            ? ["high", "Changes provider auto approval configuration."]
            : ["low", "Capability setting changed."],
        );
  }
}
