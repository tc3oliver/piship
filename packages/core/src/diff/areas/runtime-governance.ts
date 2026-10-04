// piship-lock/v1alpha6 governance evidence: Codemode and tool search, the
// resolved exposure of each locked tool, the runtime seam table, session
// export status, the data lifecycle, virtual model routes, Pi packages, and
// cache warming. An older lock has none of these; its side reads as absent,
// never as a downgrade.
import { EXPOSURE_VISIBILITY } from "@piship/policy";
import {
  byKey,
  CLASS_RANK,
  type Collector,
  compare,
  keys,
} from "../collector.js";
import type { AnyLock, Verdict } from "../types.js";

const STATUS_RANK: Readonly<Record<string, number>> = {
  unsupported: 0,
  "audit-only": 1,
  enforced: 2,
};
const SEAM_RANK: Readonly<Record<string, number>> = {
  none: 0,
  observe: 1,
  hook: 2,
};
const visibility = (exposure: string): number =>
  EXPOSURE_VISIBILITY[exposure as keyof typeof EXPOSURE_VISIBILITY] ?? 0;

function exposureVerdict(before: string, after: string): Verdict {
  return visibility(after) > visibility(before)
    ? ["high", "Exposure widened: the model can see or reach more."]
    : ["medium", "Exposure narrowed."];
}

export function runtimeTools(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.runtimeTools;
  const y = a.runtimeTools;
  out.scalar(
    "tools",
    "Codemode",
    x?.codemode ?? (y ? "off" : undefined),
    y?.codemode ?? (x ? "off" : undefined),
    (before, after) =>
      before === "off"
        ? ["high", "Enables Codemode: model scripts can call tools."]
        : after === "off"
          ? ["medium", "Disables Codemode."]
          : ["medium", "Codemode mode changed."],
  );
  out.scalar(
    "tools",
    "tool search",
    x?.toolSearch ?? (y ? "off" : undefined),
    y?.toolSearch ?? (x ? "off" : undefined),
    (_, after) =>
      after === "on"
        ? ["medium", "Deferred tools become discoverable through tool search."]
        : ["low", "Disables tool search."],
  );
  const rules = (lock: AnyLock) =>
    new Map(
      (lock.runtimeTools?.exposure ?? []).map((rule) => [
        rule.pattern,
        rule.exposure,
      ]),
    );
  const before = rules(b);
  const after = rules(a);
  for (const pattern of keys(before, after))
    out.scalar(
      "tools",
      `exposure rule ${pattern}`,
      before.get(pattern),
      after.get(pattern),
      (be, ae) =>
        be === ""
          ? ae === "hidden" || ae === "deferred"
            ? ["medium", "Adds a narrowing exposure rule."]
            : ["medium", "Adds an exposure rule."]
          : ae === ""
            ? [
                "high",
                "Removes an exposure rule; the tool's own exposure applies.",
              ]
            : exposureVerdict(be, ae),
    );
  const tools = (lock: AnyLock) =>
    byKey(lock.tools, (item) => `${item.origin} ${item.tool}`);
  const bt = tools(b);
  const at = tools(a);
  for (const key of keys(bt, at)) {
    const be = bt.get(key)?.exposure;
    const ae = at.get(key)?.exposure;
    out.scalar("tools", `tool ${key}`, be, ae, (bx, ax) =>
      bx === ""
        ? ax === "hidden"
          ? ["low", "New tool, hidden."]
          : ["medium", "New tool visible to the model."]
        : ax === ""
          ? ["low", "Tool no longer locked."]
          : exposureVerdict(bx, ax),
    );
  }
}

export function enforcement(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.enforcement;
  const y = a.enforcement;
  if (x && y) {
    out.scalar("enforcement", "seam table Pi", x.pi, y.pi, [
      "medium",
      "Seam table proven against another Pi version.",
    ]);
    let seamChanged = false;
    const actions = [
      ...new Set([...Object.keys(x.seams), ...Object.keys(y.seams)]),
    ].sort(compare);
    for (const action of actions) {
      const bs = (x.seams as Record<string, string>)[action];
      const as = (y.seams as Record<string, string>)[action];
      if (bs !== as) seamChanged = true;
      out.scalar("enforcement", `seam ${action}`, bs, as, (be, ae) =>
        (SEAM_RANK[ae] ?? 0) < (SEAM_RANK[be] ?? 0)
          ? ["high", "Enforcement downgrade: the runtime seam weakened."]
          : ["medium", "Runtime seam strengthened."],
      );
    }
    if (!seamChanged)
      out.scalar("enforcement", "seam digest", x.digest, y.digest, [
        "medium",
        "Per-resource seam evidence changed.",
      ]);
  } else if (x || y)
    out.push(
      "enforcement",
      y ? "added" : "removed",
      "seam evidence",
      y
        ? ["low", "The lock now records runtime seam evidence."]
        : ["high", "The lock no longer records runtime seam evidence."],
    );
  const bx: Record<string, string> = b.sessionExportStatus ?? {};
  const ax: Record<string, string> = a.sessionExportStatus ?? {};
  for (const resource of [
    ...new Set([...Object.keys(bx), ...Object.keys(ax)]),
  ].sort(compare))
    out.scalar(
      "enforcement",
      `session export ${resource}`,
      bx[resource],
      ax[resource],
      (be, ae) =>
        be === "" || ae === ""
          ? ["low", "Session export status recorded."]
          : (STATUS_RANK[ae] ?? 0) < (STATUS_RANK[be] ?? 0)
            ? ["high", "Enforcement downgrade for session export."]
            : ["medium", "Session export is now enforced."],
    );
}

export function dataLifecycle(out: Collector, b: AnyLock, a: AnyLock): void {
  out.scalar("data", "data contract", b.data?.contract, a.data?.contract, [
    "medium",
    "Data lifecycle contract changed.",
  ]);
  const x = b.data?.declared;
  const y = a.data?.declared;
  const classes = [
    ...new Set([
      ...Object.keys(x?.retention ?? {}),
      ...Object.keys(y?.retention ?? {}),
    ]),
  ].sort(compare);
  for (const dataClass of classes) {
    const name = dataClass as keyof NonNullable<typeof x>["retention"];
    const bs = x?.retention[name]?.retentionSeconds;
    const as = y?.retention[name]?.retentionSeconds;
    // Audit retention is a minimum; every other class's a maximum.
    const audit = dataClass === "audit";
    out.scalar("data", `retention ${dataClass}`, bs, as, (be, ae) => {
      const keepsLess =
        ae === "" ? false : be === "" ? true : Number(ae) < Number(be);
      if (audit)
        return keepsLess || ae === ""
          ? ["high", "Audit records may be deleted sooner."]
          : ["medium", "Audit records are kept longer."];
      return keepsLess
        ? ["medium", `${dataClass} are deleted sooner.`]
        : ["medium", `${dataClass} are kept longer.`];
    });
  }
  out.set(
    "data",
    "purge on logout",
    x?.purge.onLogout,
    y?.purge.onLogout,
    ["low", "Logout purges this class."],
    ["medium", "Logout no longer purges this class."],
  );
  out.scalar(
    "data",
    "purge on uninstall",
    x?.purge.onUninstall,
    y?.purge.onUninstall,
    (_, ae) =>
      ae === "all"
        ? ["low", "Uninstall purges all data."]
        : ["medium", "Uninstall no longer purges all data."],
  );
  const be: Record<string, string> = x?.export ?? {};
  const ae: Record<string, string> = y?.export ?? {};
  for (const resource of [
    ...new Set([...Object.keys(be), ...Object.keys(ae)]),
  ].sort(compare))
    out.scalar(
      "data",
      `export ${resource}`,
      be[resource],
      ae[resource],
      (_, after) =>
        after === "allow"
          ? ["high", "Session export allowed."]
          : after === ""
            ? ["high", "Session export rule removed; the policy decides."]
            : ["medium", "Session export restricted."],
    );
}

export function virtualModels(out: Collector, b: AnyLock, a: AnyLock): void {
  const before = byKey(b.virtualModels, (item) => item.id);
  const after = byKey(a.virtualModels, (item) => item.id);
  for (const id of keys(before, after)) {
    const x = before.get(id);
    const y = after.get(id);
    if (!x && y) {
      out.push(
        "models",
        "added",
        `virtual model ${id}`,
        ["high", "New virtual model with physical routes."],
        undefined,
        y.routes.join(", "),
      );
      continue;
    }
    if (x && !y) {
      out.push("models", "removed", `virtual model ${id}`, [
        "low",
        "Virtual model removed.",
      ]);
      continue;
    }
    if (!x || !y) continue;
    out.scalar("models", `virtual model ${id} router`, x.router, y.router, [
      "medium",
      "Virtual model router changed.",
    ]);
    out.set(
      "models",
      `virtual model ${id} route`,
      x.routes,
      y.routes,
      ["high", "New physical route."],
      ["low", "Physical route removed."],
    );
  }
}

/** v1alpha6 Pi packages: any new package or change of what one resolves to. */
export function piPackages(out: Collector, b: AnyLock, a: AnyLock): void {
  const before = byKey(b.packages, (item) => item.id);
  const after = byKey(a.packages, (item) => item.id);
  const identity = (item: NonNullable<AnyLock["packages"]>[number]) =>
    item.source === "git"
      ? `git ${item.commit ?? ""}`
      : item.source === "npm"
        ? `npm ${item.version ?? ""}`
        : item.source;
  for (const id of keys(before, after)) {
    const x = before.get(id);
    const y = after.get(id);
    const item = `Pi package ${id}`;
    if (!x && y) {
      out.push(
        "packages",
        "added",
        item,
        ["high", "New Pi package: its extensions run in the agent."],
        undefined,
        identity(y),
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "packages",
        "removed",
        item,
        ["low", "Pi package removed."],
        identity(x),
      );
      continue;
    }
    if (!x || !y) continue;
    const source: Verdict = ["high", "Pi package source changed."];
    out.scalar("packages", `${item} source`, x.source, y.source, source);
    out.scalar("packages", `${item} url`, x.url, y.url, source);
    out.scalar("packages", `${item} version`, x.version, y.version, [
      "high",
      "Pi package version changed.",
    ]);
    out.scalar("packages", `${item} commit`, x.commit, y.commit, [
      "high",
      "Pi package commit changed.",
    ]);
    const content: Verdict = ["high", "Pi package content changed."];
    out.scalar(
      "packages",
      `${item} integrity`,
      x.integrity,
      y.integrity,
      content,
    );
    out.scalar("packages", `${item} tree`, x.tree, y.tree, content);
    out.scalar("packages", `${item} class`, x.class, y.class, (bc, ac) =>
      (CLASS_RANK[ac] ?? 0) > (CLASS_RANK[bc] ?? 0)
        ? ["high", "Pi package trust class widened to a less reviewed one."]
        : ["medium", "Pi package trust class narrowed."],
    );
  }
}

/** v1alpha6 `runtime.cacheWarming`: absent is `off`. */
export function cacheWarming(out: Collector, b: AnyLock, a: AnyLock): void {
  if (!b.cacheWarming && !a.cacheWarming) return;
  out.scalar(
    "models",
    "cache warming",
    b.cacheWarming?.mode ?? "off",
    a.cacheWarming?.mode ?? "off",
    (_, after) =>
      after === "off"
        ? ["low", "Cache warming off: no extra model requests."]
        : ["medium", "Cache warming sends extra model requests."],
  );
  out.scalar(
    "models",
    "cache warming userOverride",
    b.cacheWarming?.userOverride ?? false,
    a.cacheWarming?.userOverride ?? false,
    (_, after) =>
      after === "true"
        ? ["medium", "Users may override the cache warming mode."]
        : ["low", "The distribution's cache warming mode is enforced."],
  );
}
