import type { GovernanceManifest } from "@piship/schema";
import {
  byKey,
  type Collector,
  compare,
  keys,
  MCP_MODE_RANK,
  rank,
  safeUrl,
  TRUST_RANK,
} from "../collector.js";
import type { Verdict } from "../types.js";

export function mcp(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  out.scalar("mcp", "mcp mode", b.mcp?.mode, a.mcp?.mode, (x, y) =>
    rank(
      MCP_MODE_RANK,
      x,
      y,
      "Admits more MCP servers.",
      "Admits fewer MCP servers.",
    ),
  );
  for (const field of ["project", "user"] as const)
    out.scalar("mcp", `mcp ${field}`, b.mcp?.[field], a.mcp?.[field], (x, y) =>
      rank(
        TRUST_RANK,
        x,
        y,
        `Trusts ${field} MCP definitions.`,
        `No longer trusts ${field} MCP definitions.`,
      ),
    );
  const before = byKey(b.mcp?.servers, (item) => item.id);
  const after = byKey(a.mcp?.servers, (item) => item.id);
  for (const id of keys(before, after)) {
    const x = before.get(id);
    const y = after.get(id);
    const item = `mcp server ${id}`;
    if (!x && y) {
      out.push(
        "mcp",
        "added",
        item,
        ["high", "New MCP server runs executable or remote code."],
        undefined,
        y.transport,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "mcp",
        "removed",
        item,
        ["low", "Removes an MCP server."],
        x.transport,
      );
      continue;
    }
    if (!x || !y) continue;
    const code: Verdict = [
      "high",
      "Server now runs different code or reaches a different endpoint.",
    ];
    out.scalar("mcp", `${item} transport`, x.transport, y.transport, code);
    out.scalar("mcp", `${item} command`, x.command, y.command, code);
    out.scalar("mcp", `${item} module`, x.module, y.module, code);
    out.scalar("mcp", `${item} url`, safeUrl(x.url), safeUrl(y.url), code);
    out.scalar("mcp", `${item} args`, x.args?.join(" "), y.args?.join(" "), [
      "medium",
      "Server arguments changed.",
    ]);
    out.scalar(
      "mcp",
      `${item} credential`,
      x.credential,
      y.credential,
      (_, c) =>
        c === "runtime"
          ? ["high", "Server now receives the runtime credential."]
          : ["medium", "Server no longer receives the runtime credential."],
    );
    out.scalar(
      "mcp",
      `${item} expectedServerName`,
      x.expectedServerName,
      y.expectedServerName,
      ["medium", "Server identity check changed."],
    );
    out.set(
      "mcp",
      `${item} tools.allow`,
      x.tools?.allow,
      y.tools?.allow,
      ["high", "Widens the tool allow list."],
      ["medium", "Narrows the tool allow list."],
    );
    out.set(
      "mcp",
      `${item} tools.deny`,
      x.tools?.deny,
      y.tools?.deny,
      ["medium", "Denies an additional tool."],
      ["high", "Stops denying a tool."],
    );
    out.set(
      "mcp",
      `${item} env.allow`,
      x.env?.allow,
      y.env?.allow,
      ["high", "Passes an additional environment variable to the server."],
      ["medium", "Passes fewer environment variables to the server."],
    );
    out.set(
      "mcp",
      `${item} env.set`,
      Object.keys(x.env?.set ?? {}),
      Object.keys(y.env?.set ?? {}),
      ["medium", "Sets an additional environment variable."],
      ["low", "No longer sets this environment variable."],
    );
    for (const key of Object.keys(y.env?.set ?? {}).sort(compare))
      if (key in (x.env?.set ?? {}) && x.env.set[key] !== y.env.set[key])
        out.push("mcp", "changed", `${item} env.set ${key}`, [
          "medium",
          "Environment value changed.",
        ]);
    out.scalar("mcp", `${item} required`, x.required, y.required, [
      "low",
      "Server start requirement changed.",
    ]);
    const timing = (server: typeof x) =>
      `timeout ${server.timeoutMs}ms, startup ${server.startupTimeoutMs}ms, attempts ${server.retry?.attempts}`;
    out.scalar("mcp", `${item} timing`, timing(x), timing(y), [
      "low",
      "Server timeouts or retries changed.",
    ]);
  }
}
