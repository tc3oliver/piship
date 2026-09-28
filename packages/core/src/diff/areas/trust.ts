import type { GovernanceLock } from "../../trust.js";
import { byKey, CLASS_RANK, type Collector, keys, rank } from "../collector.js";
import type { Verdict } from "../types.js";
import { resourceArea } from "./resources.js";

function contractBase(contract: string): [string, string] {
  const match = /^(.*)\/v(\d+)$/.exec(contract);
  return match ? [match[1] ?? contract, match[2] ?? ""] : [contract, ""];
}

export function trustEvidence(
  out: Collector,
  b: GovernanceLock,
  a: GovernanceLock,
): void {
  const before = byKey(b.certified, (item) => item.path);
  const after = byKey(a.certified, (item) => item.path);
  for (const path of keys(before, after)) {
    const x = before.get(path);
    const y = after.get(path);
    const item = `certified ${path}`;
    const area = resourceArea((y ?? x)?.kind ?? "");
    if (!x && y) {
      out.push(
        area,
        "added",
        item,
        ["medium", "Adds a certified resource."],
        undefined,
        `${y.evidence.id}@${y.evidence.version}`,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        area,
        "removed",
        item,
        ["low", "Removes a certified resource."],
        `${x.evidence.id}@${x.evidence.version}`,
      );
      continue;
    }
    if (!x || !y) continue;
    const reviewed: Verdict = [
      "high",
      "Reviewed certified content changed; confirm the new review evidence.",
    ];
    out.scalar(area, `${item} id`, x.evidence.id, y.evidence.id, reviewed);
    out.scalar(
      area,
      `${item} version`,
      x.evidence.version,
      y.evidence.version,
      reviewed,
    );
    out.scalar(area, `${item} integrity`, x.integrity, y.integrity, reviewed);
    out.scalar(area, `${item} source`, x.evidence.source, y.evidence.source, [
      "medium",
      "Certified source changed.",
    ]);
    out.scalar(
      area,
      `${item} license`,
      x.evidence.license,
      y.evidence.license,
      ["medium", "Certified license changed."],
    );
    out.set(
      area,
      `${item} pi`,
      x.evidence.pi,
      y.evidence.pi,
      ["medium", "Certified for an additional Pi version."],
      ["low", "No longer certified for this Pi version."],
    );
  }

  const bp = byKey(b.providers, (item) => item.capability);
  const ap = byKey(a.providers, (item) => item.capability);
  for (const capability of keys(bp, ap)) {
    const x = bp.get(capability);
    const y = ap.get(capability);
    const item = `provider ${capability}`;
    if (!x && y) {
      out.push(
        "providers",
        "added",
        item,
        y.class === "builtin"
          ? ["medium", "Adds a builtin capability provider."]
          : ["high", "Adds a capability provider (executable code)."],
        undefined,
        `${y.id}@${y.version}`,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "providers",
        "removed",
        item,
        ["low", "Removes a capability provider."],
        `${x.id}@${x.version}`,
      );
      continue;
    }
    if (!x || !y) continue;
    out.scalar("providers", `${item} id`, x.id, y.id, [
      "high",
      "Different provider implements the capability.",
    ]);
    out.scalar("providers", `${item} class`, x.class, y.class, (bc, ac) =>
      rank(
        CLASS_RANK,
        bc,
        ac,
        "Widens trust: provider moves to a less-reviewed trust class.",
        "Narrows trust: provider moves to a more-reviewed trust class.",
      ),
    );
    out.scalar("providers", `${item} version`, x.version, y.version, [
      "medium",
      "Provider version changed.",
    ]);
    out.scalar("providers", `${item} integrity`, x.integrity, y.integrity, [
      "high",
      "Provider code changed.",
    ]);
    const majors = new Map(x.implements.map(contractBase));
    const changedMajor = y.implements
      .map(contractBase)
      .some(([base, major]) => majors.has(base) && majors.get(base) !== major);
    out.set(
      "providers",
      `${item} implements`,
      x.implements,
      y.implements,
      changedMajor
        ? ["high", "Capability contract major version changed."]
        : ["medium", "Provider implements an additional contract."],
      changedMajor
        ? ["high", "Capability contract major version changed."]
        : ["medium", "Provider no longer implements this contract."],
    );
  }
}
