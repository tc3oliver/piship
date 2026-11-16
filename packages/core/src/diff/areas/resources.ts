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

/** MCP server IDs by the locked path of their stdio module (an `adapters` resource). */
function mcpModules(lock: AnyLock): Map<string, string> {
  const modules = new Map<string, string>();
  for (const server of lock.governance?.manifest.mcp?.servers ?? [])
    if (server.module)
      modules.set(server.module.replace(/^\.\//, ""), server.id);
  return modules;
}

export function resources(out: Collector, b: AnyLock, a: AnyLock): void {
  const key = (item: LockedResource) => `${item.kind} ${item.path}`;
  const before = byKey(b.resources, key);
  const after = byKey(a.resources, key);
  const beforeModules = mcpModules(b);
  const afterModules = mcpModules(a);
  for (const item of keys(before, after)) {
    const x = before.get(item);
    const y = after.get(item);
    const kind = (y ?? x)?.kind ?? "";
    const path = (y ?? x)?.path ?? "";
    const server =
      kind === "adapters"
        ? (afterModules.get(path) ?? beforeModules.get(path))
        : undefined;
    const area = server ? "mcp" : resourceArea(kind);
    const verdict = (verb: "adds" | "changes"): Verdict =>
      server
        ? [
            "high",
            `${verb === "adds" ? "Adds" : "Changes"} the module of MCP server ${server} (executable code).`,
          ]
        : contentVerdict(kind, verb);
    if (!x && y) {
      // A new server, or one that switched modules, is reported under mcp.
      if (server && beforeModules.get(path) !== server) continue;
      out.push(area, "added", item, verdict("adds"), undefined, y.sha256);
      continue;
    }
    if (x && !y) {
      // Dropping a server's module means the server was removed or moved: reported under mcp.
      if (!server)
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
      out.push(area, "changed", item, verdict("changes"), x.sha256, y.sha256);
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
