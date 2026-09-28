import {
  byKey,
  type Collector,
  FAIL_ON_RANK,
  keys,
  origin,
  rank,
} from "../collector.js";
import type { AnyLock } from "../types.js";

export function release(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.release;
  const y = a.release;
  if (!x && !y) return;
  out.set(
    "release",
    "release target",
    x?.targets,
    y?.targets,
    [
      "medium",
      "Advertises an additional target; it needs installed E2E evidence.",
    ],
    ["low", "No longer advertises this target."],
  );
  out.set(
    "release",
    "release source",
    x?.sources?.map((value) => origin(value) ?? value),
    y?.sources?.map((value) => origin(value) ?? value),
    ["high", "Approves a new package source origin."],
    ["low", "Removes an approved package source."],
  );
  out.scalar(
    "release",
    "vulnerabilities failOn",
    x?.vulnerabilities?.failOn,
    y?.vulnerabilities?.failOn,
    (bf, af) =>
      rank(
        FAIL_ON_RANK,
        bf,
        af,
        "Loosens the vulnerability gate.",
        "Tightens the vulnerability gate.",
      ),
  );
  const before = byKey(x?.vulnerabilities?.allow, (item) => item.id);
  const after = byKey(y?.vulnerabilities?.allow, (item) => item.id);
  for (const id of keys(before, after)) {
    const be = before.get(id)?.expires;
    const ae = after.get(id)?.expires;
    out.scalar("release", `vulnerability exception ${id}`, be, ae, (bv, av) =>
      av === ""
        ? ["medium", "Removes a reviewed vulnerability exception."]
        : bv === ""
          ? ["high", "Allows a known vulnerability."]
          : av > bv
            ? ["high", "Extends a vulnerability exception."]
            : ["medium", "Shortens a vulnerability exception."],
    );
  }
}
