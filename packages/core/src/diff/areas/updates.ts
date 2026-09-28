import {
  byKey,
  type Collector,
  fingerprint,
  keys,
  safeUrl,
} from "../collector.js";
import type { AnyLock, Verdict } from "../types.js";

export function updates(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.updates;
  const y = a.updates;
  if (!x && !y) return;
  out.scalar("updates", "update channel", x?.channel, y?.channel, [
    "medium",
    "Default update channel changed.",
  ]);
  out.set(
    "updates",
    "update channels",
    x?.channels,
    y?.channels,
    (value) =>
      value === "dev"
        ? ["medium", "Users may select the dev channel."]
        : ["low", "Users may select an additional channel."],
    ["low", "Removes a selectable channel."],
  );
  out.scalar(
    "updates",
    "update source",
    safeUrl(x?.source),
    safeUrl(y?.source),
    ["high", "Updates come from a different source."],
  );
  out.scalar("updates", "update rollback", x?.rollback, y?.rollback, (_, v) =>
    v === "false"
      ? ["medium", "The previous known-good release is no longer kept."]
      : ["low", "Keeps the previous known-good release."],
  );
  const before = byKey(x?.trust?.keys, (item) => item.id);
  const after = byKey(y?.trust?.keys, (item) => item.id);
  const publish: Verdict = ["high", "Changes who can publish updates."];
  for (const id of keys(before, after)) {
    const bk = before.get(id)?.publicKey;
    const ak = after.get(id)?.publicKey;
    out.scalar(
      "updates",
      `update trust key ${id}`,
      bk === undefined ? undefined : fingerprint(bk),
      ak === undefined ? undefined : fingerprint(ak),
      publish,
    );
  }
}
