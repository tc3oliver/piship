import type { LockedResource } from "../../index.js";
import {
  byKey,
  CLASS_RANK,
  type Collector,
  EXECUTABLE_KINDS,
  keys,
  rank,
} from "../collector.js";
import type { AnyLock, DiffArea, Verdict } from "../types.js";

export function resourceArea(kind: string): DiffArea {
  if (kind === "providers") return "providers";
  return EXECUTABLE_KINDS.includes(kind) ? "extensions" : "resources";
}

function contentVerdict(kind: string, verb: "adds" | "changes"): Verdict {
  if (EXECUTABLE_KINDS.includes(kind))
    return [
      "high",
      `${verb === "adds" ? "Adds" : "Changes"} executable code (${kind}).`,
    ];
  if (kind === "instructions" || kind === "skills")
    return [
      "medium",
      `${verb === "adds" ? "Adds" : "Changes"} ${kind} that shape agent behavior.`,
    ];
  return ["low", `${verb === "adds" ? "Adds" : "Changes"} ${kind} content.`];
}

export function resources(out: Collector, b: AnyLock, a: AnyLock): void {
  const key = (item: LockedResource) => `${item.kind} ${item.path}`;
  const before = byKey(b.resources, key);
  const after = byKey(a.resources, key);
  for (const item of keys(before, after)) {
    const x = before.get(item);
    const y = after.get(item);
    const kind = (y ?? x)?.kind ?? "";
    const area = resourceArea(kind);
    if (!x && y) {
      out.push(
        area,
        "added",
        item,
        contentVerdict(kind, "adds"),
        undefined,
        y.sha256,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        area,
        "removed",
        item,
        ["low", `Removes ${kind} content.`],
        x.sha256,
      );
      continue;
    }
    if (!x || !y) continue;
    if (x.sha256 !== y.sha256)
      out.push(
        area,
        "changed",
        item,
        contentVerdict(kind, "changes"),
        x.sha256,
        y.sha256,
      );
    if (x.class !== undefined && y.class !== undefined)
      out.scalar(area, `${item} class`, x.class, y.class, (bc, ac) =>
        rank(
          CLASS_RANK,
          bc,
          ac,
          "Widens trust: content moves to a less-reviewed trust class.",
          "Narrows trust: content moves to a more-reviewed trust class.",
        ),
      );
  }
}
