import { normalizePolicyAction } from "@piship/contracts";
import type { GovernanceManifest } from "@piship/schema";
import {
  type Collector,
  compare,
  DIMENSION_RANK,
  EFFECT_RANK,
  keys,
  rank,
  TRUST_RANK,
} from "../collector.js";
import type { Verdict } from "../types.js";

type RuleEntry = {
  readonly tier: string;
  readonly rule: GovernanceManifest["policy"]["enforced"][number];
};

function describeRule({ tier, rule }: RuleEntry): string {
  return `${tier}: ${rule.effect} ${rule.action} ${rule.resource}`;
}

export function policy(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const bp = b.policy;
  const ap = a.policy;
  out.scalar("policy", "policy id", bp?.id, ap?.id, [
    "medium",
    "Different policy set.",
  ]);
  out.scalar("policy", "policy version", bp?.version, ap?.version, [
    "low",
    "Policy version changed.",
  ]);
  out.scalar("policy", "policy default", bp?.default, ap?.default, (x, y) =>
    rank(
      EFFECT_RANK,
      x,
      y,
      "Relaxes policy default.",
      "Tightens policy default.",
    ),
  );
  // Absent is off, so declaring the default changes nothing.
  out.scalar(
    "policy",
    "policy userAuto",
    bp?.userAuto ?? "off",
    ap?.userAuto ?? "off",
    (_, y) =>
      y === "allowed"
        ? [
            "high",
            "Lets each user switch on auto mode, which approves asks from the distribution defaults without a prompt; deny and enforced rules still apply.",
          ]
        : [
            "medium",
            "Users can no longer switch on auto mode; a switch that is on stops applying.",
          ],
  );
  out.scalar("policy", "policy adapter", bp?.adapter, ap?.adapter, (_, y) =>
    y === ""
      ? [
          "high",
          "Removes the team rules adapter, which only narrows; relaxes policy.",
        ]
      : ["high", "Team rules adapter changed (executable code)."],
  );
  const rules = (config: typeof bp | undefined) =>
    new Map<string, RuleEntry>(
      (["enforced", "defaults"] as const).flatMap((tier) =>
        (config?.[tier] ?? []).map(
          (rule) => [rule.id, { tier, rule }] as const,
        ),
      ),
    );
  const before = rules(bp);
  const after = rules(ap);
  const defaultRank = EFFECT_RANK[ap?.default ?? "deny"] ?? 0;
  for (const id of keys(before, after)) {
    const x = before.get(id);
    const y = after.get(id);
    const item = `policy rule ${id}`;
    if (!x && y) {
      const looser =
        y.rule.effect === "allow" ||
        (EFFECT_RANK[y.rule.effect] ?? 0) > defaultRank;
      out.push(
        "policy",
        "added",
        item,
        looser
          ? ["high", "Adds a rule looser than the default; relaxes policy."]
          : ["medium", "Adds a restricting rule; tightens policy."],
        undefined,
        describeRule(y),
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "policy",
        "removed",
        item,
        x.rule.effect === "allow"
          ? ["medium", "Removes an allow rule; tightens policy."]
          : ["high", `Removes a ${x.rule.effect} rule; relaxes policy.`],
        describeRule(x),
      );
      continue;
    }
    if (!x || !y) continue;
    out.scalar("policy", item, x.rule.effect, y.rule.effect, (be, ae) =>
      rank(EFFECT_RANK, be, ae, "Relaxes policy.", "Tightens policy."),
    );
    out.scalar("policy", `${item} tier`, x.tier, y.tier, (_, at) =>
      at === "defaults"
        ? [
            "high",
            "Rule is no longer enforced and can be overridden; relaxes policy.",
          ]
        : ["medium", "Rule becomes enforced; tightens policy."],
    );
    const scope: Verdict = [
      "high",
      "Changes what the rule covers; review coverage with policy explain.",
    ];
    // `model.use` is read as `model.select`: the rename is not a change.
    out.scalar(
      "policy",
      `${item} action`,
      normalizePolicyAction(x.rule.action),
      normalizePolicyAction(y.rule.action),
      scope,
    );
    out.scalar(
      "policy",
      `${item} resource`,
      x.rule.resource,
      y.rule.resource,
      scope,
    );
    out.scalar("policy", `${item} reason`, x.rule.reason, y.rule.reason, [
      "low",
      "Rule explanation changed.",
    ]);
  }
  out.set(
    "policy",
    "policy acknowledgeUnenforced",
    bp?.acknowledgeUnenforced,
    ap?.acknowledgeUnenforced,
    [
      "medium",
      "Acknowledges a rule no runtime seam enforces; managed validation no longer fails on it.",
    ],
    ["low", "No longer acknowledges an unenforced rule."],
  );
  for (const [field, order] of [
    ["resourceTrust", TRUST_RANK],
    ["providerTrust", TRUST_RANK],
  ] as const) {
    const bt: Record<string, string> = bp?.[field] ?? {};
    const at: Record<string, string> = ap?.[field] ?? {};
    for (const key of [
      ...new Set([...Object.keys(bt), ...Object.keys(at)]),
    ].sort(compare))
      out.scalar("policy", `policy ${field}.${key}`, bt[key], at[key], (x, y) =>
        rank(order, x, y, "Relaxes trust; relaxes policy.", "Tightens trust."),
      );
  }
  for (const tier of ["company", "external", "unknown"] as const) {
    const bd: Record<string, string> =
      bp?.projectTrust?.[tier]?.dimensions ?? {};
    const ad: Record<string, string> =
      ap?.projectTrust?.[tier]?.dimensions ?? {};
    for (const key of [
      ...new Set([...Object.keys(bd), ...Object.keys(ad)]),
    ].sort(compare))
      out.scalar(
        "policy",
        `policy projectTrust.${tier}.${key}`,
        bd[key],
        ad[key],
        (x, y) =>
          rank(
            DIMENSION_RANK,
            x,
            y,
            "Admits more project content; relaxes policy.",
            "Admits less project content; tightens policy.",
          ),
      );
    if (tier === "unknown") continue;
    const matchers = (config: typeof bp | undefined) =>
      (config?.projectTrust?.[tier]?.match ?? []).map((matcher) =>
        [
          matcher.remote === undefined ? "" : `remote=${matcher.remote}`,
          matcher.path === undefined ? "" : `path=${matcher.path}`,
        ]
          .filter(Boolean)
          .join(" "),
      );
    out.set(
      "policy",
      `policy projectTrust.${tier}.match`,
      matchers(bp),
      matchers(ap),
      tier === "company"
        ? [
            "high",
            "More projects are treated as company projects; relaxes policy.",
          ]
        : ["medium", "More projects are treated as external projects."],
      ["medium", "Fewer projects match this project class."],
    );
  }
}
